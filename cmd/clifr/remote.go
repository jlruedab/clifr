package main

// clifr --host: query another host's recording (clifrd --serve, phase 7.2).
// The window's data files are listed by the server, the missing ones fetched
// into a cache (by SHA-256), and the query runs locally on exactly the
// listed set (hard links into a directory of its own), as on a local
// --data-dir. TLS: clifrd's self-signed certificate, pinned on first use in
// ~/.config/clifr/known_hosts (plain HTTP only to a loopback address).

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"clifr/internal/query"
	"clifr/internal/remote"
)

// defaultServePort is clifrd --serve's port in the docs' examples.
const defaultServePort = "8443"

// remoteDirs are the query directories made in this run (removed at exit);
// clifr tui fetches in the background, so under remoteMu.
var (
	remoteMu   sync.Mutex
	remoteDirs []string
)

func cleanupRemote() {
	remoteMu.Lock()
	defer remoteMu.Unlock()
	for _, d := range remoteDirs {
		os.RemoveAll(d)
	}
}

type remoteHost struct {
	g        *globals
	base     string // scheme://host:port
	hostport string
	client   *http.Client
}

// hostURL turns --host into a base URL: HOST, HOST:PORT or a URL; plain HTTP
// for a loopback address (clifrd serves it so), HTTPS otherwise.
func hostURL(h string) (base, hostport string, err error) {
	if strings.Contains(h, "://") {
		u, err := url.Parse(h)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") {
			return "", "", fmt.Errorf("--host %q: want HOST, HOST:PORT or https://HOST:PORT", h)
		}
		hostport = u.Host
		if u.Port() == "" {
			hostport = net.JoinHostPort(u.Hostname(), defaultServePort)
		}
		return u.Scheme + "://" + hostport, hostport, nil
	}
	hostport = h
	if _, _, err := net.SplitHostPort(h); err != nil {
		hostport = net.JoinHostPort(strings.Trim(h, "[]"), defaultServePort)
	}
	host, _, _ := net.SplitHostPort(hostport)
	scheme := "https"
	if ip := net.ParseIP(host); host == "localhost" || ip != nil && ip.IsLoopback() {
		scheme = "http"
	}
	return scheme + "://" + hostport, hostport, nil
}

func connect(g *globals) (*remoteHost, error) {
	if g.token == "" {
		return nil, usageError{errors.New("--host needs a token: --token TOKEN or CLIFR_TOKEN (on the server: clifrd token new)")}
	}
	base, hostport, err := hostURL(g.host)
	if err != nil {
		return nil, usageError{err}
	}
	h := &remoteHost{g: g, base: base, hostport: hostport}
	tr := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute, // listing a long window hashes its files
		MaxIdleConnsPerHost:   4,
	}
	if strings.HasPrefix(base, "https://") {
		// A certificate a CA vouches for (--tls-ca, else the system's CAs:
		// clifrd --serve-tls-config) is accepted for the host name; clifrd's
		// own self-signed one is pinned instead (the user, 2026-11-08).
		var roots *x509.CertPool // nil: the system's
		if g.tlsCA != "" {
			if roots, err = readCA(g.tlsCA); err != nil {
				return nil, usageError{err}
			}
		}
		pin := ""
		if roots == nil {
			if pin, err = trustHost(g, hostport); err != nil {
				return nil, err
			}
		}
		tr.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // checked here: by the CA, else against the pin
			VerifyConnection: func(cs tls.ConnectionState) error {
				err := verifyCA(cs.PeerCertificates, hostport, roots)
				switch {
				case err == nil:
					return nil
				case roots != nil:
					return fmt.Errorf("the certificate of %s: %w (--tls-ca %s)", hostport, err, g.tlsCA)
				case pin != "" && len(cs.PeerCertificates) > 0 && remote.Fingerprint(cs.PeerCertificates[0]) == pin:
					return nil
				case pin == "":
					return fmt.Errorf("the certificate of %s is not the pinned one: no CA vouches for it any more (%v)", hostport, err)
				}
				return fmt.Errorf("the certificate of %s is not the pinned one", hostport)
			},
		}
	}
	h.client = &http.Client{Transport: tr}
	return h, nil
}

// readCA reads --tls-ca: PEM certificates.
func readCA(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--tls-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("--tls-ca %s: no PEM certificate in it", path)
	}
	return pool, nil
}

// verifyCA checks certs (the server's chain) for hostport's host name or IP
// address against roots (nil: the system's CAs).
func verifyCA(certs []*x509.Certificate, hostport string, roots *x509.CertPool) error {
	if len(certs) == 0 {
		return errors.New("no certificate")
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err = certs[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter})
	return err
}

// knownHosts is clifr's pin file: "HOST:PORT SHA256:..." per line.
func knownHosts() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "clifr", "known_hosts"), nil
}

func readPins(path string) map[string]string {
	pins := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return pins
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) >= 2 && !strings.HasPrefix(f[0], "#") {
			pins[f[0]] = f[1]
		}
	}
	return pins
}

// trustHost returns the fingerprint to require of hostport: the pinned one,
// or, on first use, the server's after the user confirmed it (a terminal) or
// --tls-fingerprint matched it.
func trustHost(g *globals, hostport string) (string, error) {
	path, err := knownHosts()
	if err != nil {
		return "", err
	}
	pinned := readPins(path)[hostport]
	if g.tlsFP != "" && pinned != "" && g.tlsFP != pinned {
		return "", fmt.Errorf("--tls-fingerprint %s differs from the one pinned for %s in %s (%s)", g.tlsFP, hostport, path, pinned)
	}
	if pinned != "" {
		return pinned, nil // the handshake must match it, or a CA vouch for it (VerifyConnection)
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", hostport,
		&tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true})
	if err != nil {
		return "", fmt.Errorf("%s: %w", hostport, err)
	}
	certs := conn.ConnectionState().PeerCertificates
	conn.Close()
	if len(certs) == 0 {
		return "", fmt.Errorf("%s: no certificate", hostport)
	}
	if g.tlsFP == "" && verifyCA(certs, hostport, nil) == nil {
		return "", nil // a system CA vouches for it: nothing to pin
	}
	fp := remote.Fingerprint(certs[0])
	switch {
	case g.tlsFP != "":
		if g.tlsFP != fp {
			return "", fmt.Errorf("the certificate of %s is %s, not --tls-fingerprint %s: not connecting", hostport, fp, g.tlsFP)
		}
	case term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd())):
		fmt.Fprintf(stderr, "The certificate of %s is not known yet.\nIts fingerprint is %s.\n"+
			"On the server, clifrd logs its own at start (journalctl -u clifrd | grep certificate).\n"+
			"Trust it and remember it in %s? (yes/no) ", hostport, fp, path)
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "yes" && a != "y" {
			return "", errors.New("not trusted: not connecting")
		}
	default:
		return "", fmt.Errorf("the certificate of %s is not known yet (fingerprint %s).\n"+
			"Check it against the server's (journalctl -u clifrd | grep certificate), then give it with\n"+
			"--tls-fingerprint %s, or connect once from a terminal", hostport, fp, fp)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(f, "%s %s\n", hostport, fp)
	if err := f.Close(); err != nil {
		return "", err
	}
	query.Header("remote: pinned the certificate of %s (%s) in %s", hostport, fp, path)
	return fp, nil
}

func (h *remoteHost) do(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.g.token)
	resp, err := h.client.Do(req)
	if err != nil {
		var cv *tls.CertificateVerificationError
		if errors.As(err, &cv) || strings.Contains(err.Error(), "not the pinned one") {
			path, _ := knownHosts()
			return nil, fmt.Errorf("%s: its TLS certificate changed since it was pinned (in %s).\n"+
				"If clifrd's TLS directory was recreated on purpose, delete the %s line there and connect again;\n"+
				"otherwise someone may be in the way: do not connect", h.hostport, path, h.hostport)
		}
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		return nil, fmt.Errorf("%s refused the token (on the server: clifrd token list)", h.hostport)
	}
	return resp, nil
}

func (h *remoteHost) getJSON(ctx context.Context, path string, v any) error {
	resp, err := h.do(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s%s: %s: %s", h.hostport, path, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(v)
}

var hexRe = regexp.MustCompile(`^[0-9a-f]+$`)

// errGone: a listed file was compacted or deleted before it was fetched.
var errGone = errors.New("gone")

// fetchWindow fetches what [from, to] needs (both 0: the whole recording)
// and returns a directory with exactly those files.
func fetchWindow(g *globals, from, to int64) (string, error) {
	dir, note, err := fetchWindowQuiet(g, from, to)
	if err != nil {
		return "", err
	}
	query.Header("%s", note)
	return dir, nil
}

// fetchWindowQuiet is fetchWindow without its header line (returned):
// clifr tui fetches in the background, where nothing may print.
func fetchWindowQuiet(g *globals, from, to int64) (dir, note string, err error) {
	h, err := connect(g)
	if err != nil {
		return "", "", err
	}
	ctx := context.Background()
	var in remote.Info
	if err := h.getJSON(ctx, remote.PathInfo, &in); err != nil {
		return "", "", err
	}
	id := in.MachineID
	if !hexRe.MatchString(id) {
		sum := sha256.Sum256([]byte(h.hostport)) // no machine-id: by address
		id = hex.EncodeToString(sum[:16])
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", "", err
	}
	cache := filepath.Join(base, "clifr", id)
	if err := os.MkdirAll(filepath.Join(cache, "objects"), 0o700); err != nil {
		return "", "", err
	}
	q := remote.PathFiles
	if from != 0 || to != 0 {
		q += "?from=" + strconv.FormatInt(from, 10) + "&to=" + strconv.FormatInt(to, 10)
	}
	var list remote.Files
	var fetched, cached int
	var bytes int64
	for attempt := 0; ; attempt++ {
		if err := h.getJSON(ctx, q, &list); err != nil {
			return "", "", err
		}
		fetched, cached, bytes, err = h.fetchFiles(ctx, cache, list.Files)
		if errors.Is(err, errGone) && attempt == 0 {
			continue // compacted meanwhile: list again
		}
		if err != nil {
			return "", "", err
		}
		break
	}
	if dir, err = linkSet(cache, list.Files); err != nil {
		return "", "", err
	}
	remoteMu.Lock()
	remoteDirs = append(remoteDirs, dir)
	remoteMu.Unlock()
	note = fmt.Sprintf("remote: %s (%s, machine-id %.8s): %d files, %d fetched (%s), %d from the cache", h.hostport, in.Hostname,
		in.MachineID, len(list.Files), fetched, humanBytes(bytes), cached)
	pruneCache(cache)
	return dir, note, nil
}

// remoteEnd is the end of the remote recording (/v1/info's to_ms): clifr
// tui polls it to see whether clifrd wrote more.
func (h *remoteHost) remoteEnd() (int64, error) {
	var in remote.Info
	if err := h.getJSON(context.Background(), remote.PathInfo, &in); err != nil {
		return 0, err
	}
	return in.ToMS, nil
}

func objectPath(cache, sum string) string { return filepath.Join(cache, "objects", sum[:2], sum) }

// fetchFiles fetches the files not in the cache yet, four at a time, each
// checked against its listed size and SHA-256 before it is kept.
func (h *remoteHost) fetchFiles(ctx context.Context, cache string, files []remote.File) (fetched, cached int, total int64, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan remote.File)
	var mu sync.Mutex
	var first error
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range work {
				if err := h.fetch(ctx, cache, f); err != nil {
					mu.Lock()
					if first == nil {
						first = err
						cancel()
					}
					mu.Unlock()
					continue
				}
				mu.Lock()
				fetched++
				total += f.Bytes
				mu.Unlock()
			}
		}()
	}
	now := time.Now()
	for _, f := range files {
		if len(f.SHA256) != 64 || !hexRe.MatchString(f.SHA256) {
			first = fmt.Errorf("server listed %q with a bad sum", f.Path)
			break
		}
		if fi, err := os.Stat(objectPath(cache, f.SHA256)); err == nil && fi.Size() == f.Bytes {
			os.Chtimes(objectPath(cache, f.SHA256), now, now) // used: kept by pruneCache
			cached++
			continue
		}
		select {
		case work <- f:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(work)
	wg.Wait()
	return fetched, cached, total, first
}

func (h *remoteHost) fetch(ctx context.Context, cache string, f remote.File) error {
	resp, err := h.do(ctx, remote.PathFile+"?path="+url.QueryEscape(f.Path))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return errGone
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s: %s", f.Path, resp.Status, strings.TrimSpace(string(b)))
	}
	dst := objectPath(cache, f.SHA256)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	var rnd [6]byte
	rand.Read(rnd[:])
	tmp := filepath.Join(cache, "objects", ".tmp-"+hex.EncodeToString(rnd[:]))
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, sum), io.LimitReader(resp.Body, f.Bytes+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && (n != f.Bytes || hex.EncodeToString(sum.Sum(nil)) != f.SHA256) {
		// Replaced since it was listed (an open file at a flush): list again.
		err = errGone
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// linkSet makes a query directory with exactly the listed files, hard-linked
// from the cache (copied where links are not possible). Paths come from the
// server: only TABLEDIR/DAY|open/NAME.parquet is accepted.
func linkSet(cache string, files []remote.File) (string, error) {
	var rnd [6]byte
	rand.Read(rnd[:])
	dir := filepath.Join(cache, "q-"+hex.EncodeToString(rnd[:]))
	for _, f := range files {
		if !remote.ValidPath(f.Path) {
			os.RemoveAll(dir)
			return "", fmt.Errorf("server listed an unexpected path %q", f.Path)
		}
		dst := filepath.Join(dir, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
		if err := os.Link(objectPath(cache, f.SHA256), dst); err != nil {
			if err := copyObject(objectPath(cache, f.SHA256), dst); err != nil {
				os.RemoveAll(dir)
				return "", err
			}
		}
	}
	return dir, nil
}

func copyObject(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// pruneCache removes cached files not used for two weeks, and query
// directories left by a clifr that was killed.
func pruneCache(cache string) {
	old := time.Now().Add(-14 * 24 * time.Hour)
	filepath.WalkDir(filepath.Join(cache, "objects"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil && fi.ModTime().Before(old) {
				os.Remove(p)
			}
		}
		return nil
	})
	entries, _ := os.ReadDir(cache)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "q-") {
			if fi, err := e.Info(); err == nil && fi.ModTime().Before(time.Now().Add(-24*time.Hour)) {
				os.RemoveAll(filepath.Join(cache, e.Name()))
			}
		}
	}
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}
