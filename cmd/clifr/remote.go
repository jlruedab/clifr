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

// remoteDirs are the query directories made in this run (removed at exit).
var remoteDirs []string

func cleanupRemote() {
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
	if err := checkRemoteLicense(g); err != nil {
		return nil, err
	}
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
		pin, err := trustHost(g, hostport)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // self-signed: checked against the pin instead
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 || remote.Fingerprint(cs.PeerCertificates[0]) != pin {
					return fmt.Errorf("the certificate of %s is not the pinned one", hostport)
				}
				return nil
			},
		}
	}
	h.client = &http.Client{Transport: tr}
	return h, nil
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
		return pinned, nil // the handshake must match it (VerifyConnection)
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
	fp := remote.Fingerprint(certs[0])
	switch {
	case g.tlsFP != "":
		if g.tlsFP != fp {
			return "", fmt.Errorf("the certificate of %s is %s, not --tls-fingerprint %s: not connecting", hostport, fp, g.tlsFP)
		}
	case term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd())):
		fmt.Fprintf(os.Stderr, "The certificate of %s is not known yet.\nIts fingerprint is %s.\n"+
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
	h, err := connect(g)
	if err != nil {
		return "", err
	}
	ctx := context.Background()
	var in remote.Info
	if err := h.getJSON(ctx, remote.PathInfo, &in); err != nil {
		return "", err
	}
	id := in.MachineID
	if !hexRe.MatchString(id) {
		sum := sha256.Sum256([]byte(h.hostport)) // no machine-id: by address
		id = hex.EncodeToString(sum[:16])
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	cache := filepath.Join(base, "clifr", id)
	if err := os.MkdirAll(filepath.Join(cache, "objects"), 0o700); err != nil {
		return "", err
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
			return "", err
		}
		fetched, cached, bytes, err = h.fetchFiles(ctx, cache, list.Files)
		if errors.Is(err, errGone) && attempt == 0 {
			continue // compacted meanwhile: list again
		}
		if err != nil {
			return "", err
		}
		break
	}
	dir, err := linkSet(cache, list.Files)
	if err != nil {
		return "", err
	}
	remoteDirs = append(remoteDirs, dir)
	query.Header("remote: %s (%s, machine-id %.8s): %d files, %d fetched (%s), %d from the cache", h.hostport, in.Hostname,
		in.MachineID, len(list.Files), fetched, humanBytes(bytes), cached)
	pruneCache(cache)
	return dir, nil
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
