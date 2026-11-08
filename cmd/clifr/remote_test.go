package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clifr/internal/license"
	"clifr/internal/pqstore"
	"clifr/internal/remote"
	"clifr/internal/store"
)

func TestHostURL(t *testing.T) {
	for _, c := range []struct{ in, base string }{
		{"web01", "https://web01:8443"}, {"web01:9000", "https://web01:9000"}, {"192.0.2.7", "https://192.0.2.7:8443"},
		{"127.0.0.1:8443", "http://127.0.0.1:8443"}, {"localhost", "http://localhost:8443"}, {"[::1]:8443", "http://[::1]:8443"},
		{"https://127.0.0.1:9443", "https://127.0.0.1:9443"}, {"https://web01", "https://web01:8443"},
	} {
		if base, _, err := hostURL(c.in); err != nil || base != c.base {
			t.Errorf("%s: %s %v, want %s", c.in, base, err, c.base)
		}
	}
	for _, bad := range []string{"ftp://web01", "https://web01/x", "https://"} {
		if _, _, err := hostURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// testRecording writes a small recording a process is in, a minute ago.
func testRecording(t *testing.T) (dir string, at time.Time) {
	t.Helper()
	dir = t.TempDir()
	pq, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	boot := now.Add(-48 * time.Hour).UnixMilli()
	for k, v := range map[string]string{"hostname": "web01", "machine_id": "0123456789abcdef0123456789abcdef", "boot_ms": strconv.FormatInt(boot, 10),
		"interval_s": "30", "clk_tck": "100", "page_kb": "4", "mem_total_kb": "1000000", "fds": "held"} {
		pq.SetMeta(k, v)
	}
	t1, t2 := now.Add(-90*time.Second).UnixMilli(), now.Add(-60*time.Second).UnixMilli()
	proc := store.ProcRow{ID: 101, PID: 4242, StartTime: boot + 1000, PPID: 1, UID: 0, Comm: "srvd", Cmdline: "/usr/sbin/srvd --port 8080",
		FirstSeen: t1, Source: "sample"}
	for i, ts := range []int64{t1, t2} {
		b := &store.Batch{Sample: store.Sample{TS: ts, NProc: 1},
			ProcSamples: []store.ProcSample{{ProcID: 101, TS: ts, State: "S", CPUTicks: int64(500 + i*10), RSSKB: 2048, VSZKB: 8192, Threads: 2}}}
		if i == 0 {
			b.ProcInserts = []store.ProcRow{proc}
		}
		if err := pq.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := pq.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, time.UnixMilli(t2 + 5000)
}

// serveTLS serves dir as clifrd --serve does, over TLS on 127.0.0.1 (a
// listener of its own: remote.Listen gives loopback plain HTTP), and counts
// the file downloads.
func serveTLS(t *testing.T, dir, tokPath, tlsDir string, files *atomic.Int64) (addr, fp string) {
	t.Helper()
	tokens, err := remote.LoadTokens(tokPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, fp, _, err := remote.LoadOrCreateCert(tlsDir, "web01")
	if err != nil {
		t.Fatal(err)
	}
	h := (&remote.Server{DataDir: dir, Tokens: tokens, Version: "test"}).Handler()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == remote.PathFile {
			files.Add(1)
		}
		h.ServeHTTP(w, r)
	})}
	go srv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}))
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), fp
}

// capture runs clifr with args and returns its standard output.
func capture(t *testing.T, args ...string) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	err = run(args)
	w.Close()
	os.Stdout = old
	return <-done, err
}

func TestRemoteQuery(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	t.Setenv("CLIFR_TOKEN", "")
	// --host needs a licence (7.3): one signed with a test key.
	t.Setenv("CLIFR_LICENSE", writeLicense(t, testLicenseKey(t), license.License{ID: "CL-T", Customer: "Test",
		Issued: "2026-11-08", Features: []string{license.FeatureRemote}}))
	dir, at := testRecording(t)
	tokPath := filepath.Join(t.TempDir(), "serve-tokens")
	token, err := remote.AddToken(tokPath, "test")
	if err != nil {
		t.Fatal(err)
	}
	var fetched atomic.Int64
	addr, fp := serveTLS(t, dir, tokPath, filepath.Join(t.TempDir(), "tls"), &fetched)
	host := "https://" + addr
	when := at.Format("2006-01-02 15:04:05")
	ps := func(extra ...string) (string, error) {
		return capture(t, append(append([]string{"--host", host, "--token", token, "--plain", "--at", when}, extra...), "ps aux")...)
	}

	// First use without a terminal: refused, with the fingerprint to check.
	if _, err := ps(); err == nil || !strings.Contains(err.Error(), "not known yet") || !strings.Contains(err.Error(), fp) {
		t.Fatalf("unknown certificate: %v", err)
	}
	if _, err := ps("--tls-fingerprint", "SHA256:wrong"); err == nil || !strings.Contains(err.Error(), "not connecting") {
		t.Errorf("wrong fingerprint: %v", err)
	}
	if _, err := capture(t, "--host", host, "--token", "clifr_wrong", "--tls-fingerprint", fp, "--plain", "--at", when, "ps aux"); err == nil ||
		!strings.Contains(err.Error(), "refused the token") {
		t.Errorf("wrong token: %v", err)
	}

	// Pinned now (the wrong-token try pinned it): the same output as the
	// local recording, from the cache the second time.
	got, err := ps("--tls-fingerprint", fp)
	if err != nil {
		t.Fatal(err)
	}
	want, err := capture(t, "--data-dir", dir, "--plain", "--at", when, "ps aux")
	if err != nil {
		t.Fatal(err)
	}
	if got != want || !strings.Contains(got, "/usr/sbin/srvd --port 8080") {
		t.Errorf("remote ps aux differs from local:\nremote:\n%s\nlocal:\n%s", got, want)
	}
	first := fetched.Load()
	if first == 0 {
		t.Fatal("nothing downloaded")
	}
	if got2, err := ps(); err != nil || got2 != want {
		t.Errorf("second query (pinned, no --tls-fingerprint): %v", err)
	}
	if n := fetched.Load(); n != first {
		t.Errorf("second query downloaded %d files again (cache)", n-first)
	}
	b, _ := os.ReadFile(filepath.Join(home, "config", "clifr", "known_hosts"))
	if string(b) != addr+" "+fp+"\n" {
		t.Errorf("known_hosts: %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(home, "cache", "clifr", "*", "q-*")); len(left) != 0 {
		t.Errorf("query directories left: %v", left)
	}

	// Another certificate at the pinned address: refused.
	os.WriteFile(filepath.Join(home, "config", "clifr", "known_hosts"), []byte(addr+" SHA256:someotherkey\n"), 0o600)
	if _, err := ps(); err == nil || !strings.Contains(err.Error(), "certificate changed") {
		t.Errorf("changed certificate: %v", err)
	}
}
