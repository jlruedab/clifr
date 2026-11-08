package remote

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clifr/internal/pqstore"
	"clifr/internal/store"
)

func TestTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve-tokens")
	if _, err := LoadTokens(path); err == nil {
		t.Error("a missing token file was accepted")
	}
	tok, err := AddToken(path, "ops  laptop\nx")
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode %#o", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), tok) || !strings.HasPrefix(string(b), "sha256:"+Hash(tok)+" ops laptop x\n") {
		t.Errorf("token file: %q", b)
	}
	tok2, _ := AddToken(path, "")
	ts, err := LoadTokens(path)
	if err != nil {
		t.Fatal(err)
	}
	if !ts.Check(tok) || !ts.Check(tok2) || ts.Check(tok+"x") || ts.Check("") || ts.Check(tok[len(tokenPrefix):]) {
		t.Error("Check")
	}
	// Revoked: refused at once, without reloading by hand.
	time.Sleep(10 * time.Millisecond) // a new mtime
	if n, err := RevokeToken(path, Hash(tok)[:8]); err != nil || n != 1 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	if ts.Check(tok) || !ts.Check(tok2) {
		t.Error("after revoking the first token")
	}
	if _, err := RevokeToken(path, "abc"); err == nil {
		t.Error("a short prefix was accepted")
	}
	// Readable by others: refused, and nothing is accepted any more.
	os.Chmod(path, 0o644)
	if _, err := LoadTokens(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("mode 644: %v", err)
	}
	if ts.Check(tok2) {
		t.Error("a token was accepted from a group-readable file")
	}
	if _, err := ParseTokens([]byte("sha256:abcd\n")); err == nil {
		t.Error("a short hash was accepted")
	}
}

func TestCert(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "serve-tls")
	_, fp, created, err := LoadOrCreateCert(dir, "web01")
	if err != nil || !created || !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("create: %q %v %v", fp, created, err)
	}
	for name, want := range map[string]os.FileMode{"": 0o700, keyFile: 0o600, certFile: 0o644} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v (%v), want %#o", name, fi.Mode().Perm(), err, want)
		}
	}
	c, fp2, created, err := LoadOrCreateCert(dir, "web01")
	if err != nil || created || fp2 != fp || c.Leaf.Subject.CommonName != "clifrd web01" {
		t.Errorf("reload: %q %v %v", fp2, created, err)
	}
	os.Chmod(filepath.Join(dir, keyFile), 0o640)
	if _, _, _, err := LoadOrCreateCert(dir, "web01"); err == nil {
		t.Error("a group-readable key was used")
	}
}

func TestCheckServeAddr(t *testing.T) {
	for _, c := range []struct {
		addr     string
		loopback bool
		ok       bool
	}{
		{"127.0.0.1:8443", true, true}, {"[::1]:8443", true, true}, {"localhost:8443", true, true},
		{":8443", false, true}, {"0.0.0.0:8443", false, true}, {"192.0.2.7:8443", false, true},
		{"8443", false, false}, {"host.example:8443", false, false}, {":0x1", false, false}, {":70000", false, false},
	} {
		lb, err := CheckServeAddr(c.addr)
		if (err == nil) != c.ok || err == nil && lb != c.loopback {
			t.Errorf("%s: loopback %v, err %v", c.addr, lb, err)
		}
	}
}

// recording writes a small real recording: two flushes of samples and meta.
func recording(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pq, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	pq.SetMeta("hostname", "web01")
	pq.SetMeta("machine_id", "abc123")
	now := time.Now().UnixMilli()
	for i := 0; i < 3; i++ {
		if err := pq.Write(&store.Batch{Sample: store.Sample{TS: now - int64(3-i)*30_000, NProc: 10 + i}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := pq.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestServer(t *testing.T) {
	dir := recording(t)
	tokPath := filepath.Join(t.TempDir(), "serve-tokens")
	tok, _ := AddToken(tokPath, "test")
	tokens, err := LoadTokens(tokPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer((&Server{DataDir: dir, Tokens: tokens, Version: "test"}).Handler())
	defer srv.Close()
	get := func(token, p string) (*http.Response, []byte) {
		req, _ := http.NewRequest("GET", srv.URL+p, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	for _, p := range []string{PathInfo, PathFiles, PathFile + "?path=x"} {
		if resp, _ := get("", p); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without a token: %d", p, resp.StatusCode)
		}
		if resp, _ := get("clifr_wrong", p); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s with a wrong token: %d", p, resp.StatusCode)
		}
	}

	resp, b := get(tok, PathInfo)
	var in Info
	if resp.StatusCode != 200 || json.Unmarshal(b, &in) != nil || in.Hostname != "web01" || in.MachineID != "abc123" ||
		in.FromMS == 0 || in.ToMS < in.FromMS || in.Server != "test" {
		t.Errorf("info: %d %s", resp.StatusCode, b)
	}

	resp, b = get(tok, PathFiles)
	var fl Files
	if resp.StatusCode != 200 || json.Unmarshal(b, &fl) != nil || len(fl.Files) == 0 {
		t.Fatalf("files: %d %s", resp.StatusCode, b)
	}
	sawSamples := false
	for _, f := range fl.Files {
		resp, body := get(tok, PathFile+"?path="+url.QueryEscape(f.Path))
		h := sha256.Sum256(body)
		if resp.StatusCode != 200 || int64(len(body)) != f.Bytes || hex.EncodeToString(h[:]) != f.SHA256 ||
			resp.Header.Get(SHA256Header) != f.SHA256 {
			t.Errorf("%s: %d, %d bytes, sum %s (listed %d, %s)", f.Path, resp.StatusCode, len(body), resp.Header.Get(SHA256Header), f.Bytes, f.SHA256)
		}
		if strings.HasPrefix(f.Path, pqstore.Dir("samples")+"/") {
			sawSamples = true
		}
	}
	if !sawSamples {
		t.Errorf("no samples file listed: %+v", fl.Files)
	}
	if resp, _ := get(tok, PathFiles+"?from=5&to=1"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("from > to: %d", resp.StatusCode)
	}

	// Only data files of known tables, inside the data directory.
	outside := filepath.Join(t.TempDir(), "secret.parquet")
	os.WriteFile(outside, []byte("secret"), 0o644)
	day := filepath.Join(dir, pqstore.Dir("samples"), "2026-01-01")
	os.MkdirAll(day, 0o750)
	os.Symlink(outside, filepath.Join(day, "00-00.parquet"))
	os.WriteFile(filepath.Join(dir, "serve-tokens.parquet"), []byte("x"), 0o600)
	for _, p := range []string{"../secret.parquet", outside, pqstore.Dir("samples") + "/../../x.parquet",
		"nosuchtable/2026-01-01/00-00.parquet", pqstore.Dir("samples") + "/2026-01-01/00-00.parquet",
		"serve-tokens.parquet", pqstore.Dir("samples") + "/2026-01-01/x.txt", ""} {
		if resp, body := get(tok, PathFile+"?path="+url.QueryEscape(p)); resp.StatusCode != http.StatusForbidden &&
			resp.StatusCode != http.StatusNotFound || strings.Contains(string(body), "secret") {
			t.Errorf("%q: %d %q", p, resp.StatusCode, body)
		}
	}
	req, _ := http.NewRequest("POST", srv.URL+PathInfo, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %v %v", resp, err)
	}
}

func TestListenTLS(t *testing.T) {
	cert, fp, _, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "tls"), "web01")
	if err != nil {
		t.Fatal(err)
	}
	ln, isTLS, err := Listen("127.0.0.1:0", cert, nil)
	if err != nil || isTLS {
		t.Fatalf("loopback: TLS %v, %v", isTLS, err)
	}
	ln.Close()
	ln, isTLS, err = Listen(":0", cert, nil)
	if err != nil || !isTLS {
		t.Fatalf("all interfaces: TLS %v, %v", isTLS, err)
	}
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	_, port, _ := strings.Cut(ln.Addr().String(), "]:")
	if port == "" {
		port = ln.Addr().String()[strings.LastIndexByte(ln.Addr().String(), ':')+1:]
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:"+port, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if st.Version != tls.VersionTLS13 || Fingerprint(st.PeerCertificates[0]) != fp {
		t.Errorf("TLS %x, fingerprint %s want %s", st.Version, Fingerprint(st.PeerCertificates[0]), fp)
	}
}
