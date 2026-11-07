package remote

import (
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
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"clifr/internal/bundle"
	"clifr/internal/pqstore"
)

// Server serves a data directory to clifr --host.
type Server struct {
	DataDir string
	Tokens  *Tokens
	Version string // clifrd's
	Logf    func(format string, args ...any)

	sem      chan struct{} // concurrent listings and transfers
	sums     sync.Map      // path -> sumEntry
	badAuth  atomic.Int64
	initOnce sync.Once
}

type sumEntry struct {
	size int64
	mod  time.Time
	sum  string
}

// maxParallel bounds the listings and transfers served at once: the
// recorder comes first.
const maxParallel = 4

func (s *Server) init() {
	s.initOnce.Do(func() {
		s.sem = make(chan struct{}, maxParallel)
		if s.Logf == nil {
			s.Logf = func(string, ...any) {}
		}
	})
}

// CheckServeAddr validates a --serve address. Any host may be served (all
// interfaces: ":8443"); loopback addresses get plain HTTP, others TLS.
func CheckServeAddr(addr string) (loopback bool, err error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("--serve %q: want HOST:PORT or :PORT, e.g. :8443 or 127.0.0.1:8443", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 { // 0: any free port (logged)
		return false, fmt.Errorf("--serve %q: bad port", addr)
	}
	if host == "localhost" {
		return true, nil
	}
	if host == "" {
		return false, nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false, fmt.Errorf("--serve %q: the host must be an IP address (or empty for all interfaces)", addr)
	}
	return ip.IsLoopback(), nil
}

// Listen opens addr: plain TCP on a loopback address, TLS 1.3 with cert
// otherwise.
func Listen(addr string, cert tls.Certificate) (net.Listener, bool, error) {
	loopback, err := CheckServeAddr(addr)
	if err != nil {
		return nil, false, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, false, err
	}
	if loopback {
		return ln, false, nil
	}
	return tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}), true, nil
}

// HTTPServer is s's http.Server (timeouts for slow clients and large files).
func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Minute, // a large hourly file over a slow link
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
}

// Handler routes the API. Every request needs a valid token; a failed one
// is answered after a delay (guessing is slow) and logged.
func (s *Server) Handler() http.Handler {
	s.init()
	mux := http.NewServeMux()
	mux.HandleFunc(PathInfo, s.info)
	mux.HandleFunc(PathFiles, s.limited(s.files))
	mux.HandleFunc(PathFile, s.limited(s.file))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || s.Tokens == nil || !s.Tokens.Check(strings.TrimSpace(tok)) {
			if n := s.badAuth.Add(1); n <= 10 || n%100 == 0 {
				s.Logf("serve: rejected a request from %s without a valid token (%d so far)", r.RemoteAddr, n)
			}
			time.Sleep(500 * time.Millisecond)
			w.Header().Set("WWW-Authenticate", `Bearer realm="clifrd"`)
			http.Error(w, "a valid token is needed (clifr --token, or CLIFR_TOKEN)", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) limited(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
			h(w, r)
		case <-r.Context().Done():
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	meta, err := pqstore.ReadMeta(s.DataDir)
	if err != nil {
		http.Error(w, "meta: "+err.Error(), http.StatusInternalServerError)
		return
	}
	in := Info{Server: s.Version, NowMS: time.Now().UnixMilli(), Hostname: meta["hostname"], MachineID: meta["machine_id"],
		BootID: meta["boot_id"], TimeZone: meta["timezone"], SchemaVersion: meta["schema_version"], Recorder: meta["clifrd_version"]}
	in.FromMS, in.ToMS = s.span()
	writeJSON(w, in)
}

// span is the recording's range by its sample files' names (to the minute;
// clifr reads the exact range from the data).
func (s *Server) span() (from, to int64) {
	dated, _ := pqstore.DataFiles(s.DataDir, "samples")
	for _, f := range dated {
		_, hi, ok := pqstore.FileSpan(f, 0) // hi: the file's end plus a minute of slack
		if !ok {
			continue
		}
		length := time.Minute // DAY/HH-MM[-n].parquet: one flush
		if !strings.Contains(filepath.Base(f), "-") {
			length = time.Hour // DAY/HH.parquet: a compacted hour
		}
		start := hi - (time.Minute + length).Milliseconds()
		if from == 0 || start < from {
			from = start
		}
		if hi > to {
			to = hi
		}
	}
	return from, to
}

func (s *Server) files(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, err1 := parseMS(q.Get("from"))
	to, err2 := parseMS(q.Get("to"))
	if err := errors.Join(err1, err2); err != nil || from > to {
		http.Error(w, "from and to: Unix milliseconds, from <= to (or both absent)", http.StatusBadRequest)
		return
	}
	meta, err := pqstore.ReadMeta(s.DataDir)
	if err != nil {
		http.Error(w, "meta: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var out Files
	for attempt := 0; attempt < 2; attempt++ {
		out, err = s.list(from, to, meta)
		if !errors.Is(err, fs.ErrNotExist) {
			break // else compacted meanwhile: once more
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
}

func (s *Server) list(from, to int64, meta map[string]string) (Files, error) {
	sel, err := bundle.Select(bundle.Options{DataDir: s.DataDir, From: from, To: to}, meta)
	if err != nil {
		return Files{}, err
	}
	rels := append([]string(nil), sel.Copy...)
	for _, abs := range sel.After {
		for _, p := range abs {
			rel, err := filepath.Rel(s.DataDir, p)
			if err != nil {
				return Files{}, err
			}
			rels = append(rels, rel)
		}
	}
	out := Files{FromMS: from, ToMS: to, Files: make([]File, 0, len(rels))}
	seen := map[string]bool{}
	for _, rel := range rels {
		rel = filepath.ToSlash(rel)
		if seen[rel] {
			continue
		}
		seen[rel] = true
		size, sum, err := s.sum(rel)
		if err != nil {
			return Files{}, err
		}
		out.Files = append(out.Files, File{Path: rel, Bytes: size, SHA256: sum})
	}
	return out, nil
}

func parseMS(v string) (int64, error) {
	if v == "" {
		return 0, nil
	}
	return strconv.ParseInt(v, 10, 64)
}

// relRe is the only shape of path served: TABLEDIR/DAY/NAME.parquet or
// TABLEDIR/open/NAME.parquet.
var relRe = regexp.MustCompile(`^([0-9a-z_]+)/(\d{4}-\d{2}-\d{2}|open)/[A-Za-z0-9_.-]+\.parquet$`)

var tableDirs = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range pqstore.Tables {
		m[pqstore.Dir(t)] = true
		m[t] = true // recordings made before 2026-11-01
	}
	return m
}()

// ValidPath reports whether rel has the shape of a served data file:
// TABLEDIR/DAY/NAME.parquet or TABLEDIR/open/NAME.parquet of a known table,
// clean, with no "..". The server serves nothing else, and clifr --host
// accepts nothing else in a listing.
func ValidPath(rel string) bool {
	m := relRe.FindStringSubmatch(rel)
	return m != nil && tableDirs[m[1]] && path.Clean(rel) == rel && !strings.Contains(rel, "..")
}

// openData opens a data file named by a client: only a regular file of a
// known table, inside the data directory (no "..", no symlink).
func (s *Server) openData(rel string) (*os.File, fs.FileInfo, error) {
	if !ValidPath(rel) {
		return nil, nil, fs.ErrPermission
	}
	p := filepath.Join(s.DataDir, filepath.FromSlash(rel))
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fs.ErrPermission
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscallNoFollow, 0)
	if err != nil {
		return nil, nil, err
	}
	if fi, err = f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fs.ErrPermission
	}
	return f, fi, nil
}

// sum returns a data file's size and SHA-256, cached by size and mtime
// (closed files never change; open ones are replaced by renaming).
func (s *Server) sum(rel string) (int64, string, error) {
	f, fi, err := s.openData(rel)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	if e, ok := s.sums.Load(rel); ok {
		if e := e.(sumEntry); e.size == fi.Size() && e.mod.Equal(fi.ModTime()) {
			return e.size, e.sum, nil
		}
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return 0, "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	s.sums.Store(rel, sumEntry{fi.Size(), fi.ModTime(), sum})
	return fi.Size(), sum, nil
}

func (s *Server) file(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	size, sum, err := s.sum(rel)
	if err == nil {
		var f *os.File
		if f, _, err = s.openData(rel); err == nil {
			defer f.Close()
			w.Header().Set("Content-Type", "application/vnd.apache.parquet")
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			w.Header().Set(SHA256Header, sum)
			// The file is replaced by renaming, never rewritten in place:
			// this open file stays as listed. clifr checks the sum anyway.
			io.CopyN(w, f, size)
			return
		}
	}
	switch {
	case errors.Is(err, fs.ErrPermission):
		http.Error(w, "not a data file of the recording", http.StatusForbidden)
	case errors.Is(err, fs.ErrNotExist):
		http.Error(w, "gone (compacted or deleted by retention): list the window again", http.StatusNotFound)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
