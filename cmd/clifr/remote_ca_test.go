package main

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clifr/internal/license"
	"clifr/internal/remote"
	"clifr/internal/webconfig"
	"clifr/internal/webconfig/webtest"
)

// clifrd --serve-tls-config: the admin's certificate, verified with --tls-ca
// for the host name; nothing is pinned. Without --tls-ca (the test CA is not
// a system CA) clifr falls back to pinning; another CA is refused.
func TestRemoteQueryCA(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	t.Setenv("CLIFR_TOKEN", "")
	t.Setenv("CLIFR_TLS_CA", "")
	t.Setenv("CLIFR_LICENSE", writeLicense(t, testLicenseKey(t), license.License{ID: "CL-T", Customer: "Test",
		Issued: "2026-11-08", Features: []string{license.FeatureRemote}}))
	dir, at := testRecording(t)
	tokPath := filepath.Join(t.TempDir(), "serve-tokens")
	token, err := remote.AddToken(tokPath, "test")
	if err != nil {
		t.Fatal(err)
	}
	tokens, _ := remote.LoadTokens(tokPath)
	p := webtest.New(t)
	// The same file may hold --metrics' client certificate settings and
	// users: --serve ignores them (clifr sends no client certificate).
	web, err := webconfig.New("serve", p.Config(t, webtest.TLSServer+"  client_ca_file: ca.pem\n"+
		"  client_auth_type: RequireAndVerifyClientCert\nbasic_auth_users:\n  prom: "+webtest.Hash(t, "pw")+"\n"), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	ln, isTLS, err := remote.Listen("127.0.0.1:0", tls.Certificate{}, web)
	if err != nil || !isTLS {
		t.Fatalf("Listen: %v, TLS %v (TLS on loopback too with --serve-tls-config)", err, isTLS)
	}
	srv := (&remote.Server{DataDir: dir, Tokens: tokens, Version: "test"}).HTTPServer()
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	when := at.Format("2006-01-02 15:04:05")
	ps := func(host string, extra ...string) (string, error) {
		args := append([]string{"--host", "https://" + net.JoinHostPort(host, port), "--token", token, "--plain", "--at", when}, extra...)
		return capture(t, append(args, "ps aux")...)
	}
	want, err := capture(t, "--data-dir", dir, "--plain", "--at", when, "ps aux")
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(p.Dir, "ca.pem")
	for _, host := range []string{"127.0.0.1", "localhost"} { // the certificate's IP and DNS names
		if got, err := ps(host, "--tls-ca", ca); err != nil || got != want {
			t.Errorf("%s with --tls-ca: %v", host, err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "config", "clifr", "known_hosts")); err == nil {
		t.Error("a CA-verified certificate was pinned")
	}
	// Without --tls-ca: no system CA vouches for it, so clifr wants a pin.
	if _, err := ps("127.0.0.1"); err == nil || !strings.Contains(err.Error(), "not known yet") {
		t.Errorf("without --tls-ca: %v", err)
	}
	// Another CA: refused.
	other := webtest.New(t)
	if _, err := ps("127.0.0.1", "--tls-ca", filepath.Join(other.Dir, "ca.pem")); err == nil || !strings.Contains(err.Error(), "--tls-ca") {
		t.Errorf("another CA: %v", err)
	}
	// A name the certificate does not have: refused even with the CA.
	ln6, err := net.Listen("tcp", "[::1]:0")
	if err == nil {
		ln6.Close()
		if _, err := ps("::1", "--tls-ca", ca); err == nil {
			t.Error("::1 (not a name of the certificate) was accepted")
		}
	}
	// TLS 1.3 at least, whatever the file says.
	if c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: p.Pool, MaxVersion: tls.VersionTLS12, ServerName: "127.0.0.1"}); err == nil {
		c.Close()
		t.Error("TLS 1.2 was accepted by --serve")
	}
}
