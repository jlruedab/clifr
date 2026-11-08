package webconfig

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"clifr/internal/webconfig/webtest"
)

func TestChecks(t *testing.T) {
	p := webtest.New(t)
	for name, c := range map[string]struct{ yaml, want string }{
		"unknown key":      {"tls_server_config:\n  cert_file: server.pem\n  key_file: server.key\n  sni: x\n", "field sni not found"},
		"not bcrypt":       {"basic_auth_users:\n  prometheus: plaintext\n", "not a bcrypt hash"},
		"header":           {"http_server_config:\n  headers:\n    X-Powered-By: me\n", "is not one of"},
		"no certificate":   {"tls_server_config:\n  client_auth_type: NoClientCert\n", "needs cert_file and key_file"},
		"mTLS without CA":  {webtest.TLSServer + "  client_auth_type: RequireAndVerifyClientCert\n", "needs client_ca_file"},
		"bad auth type":    {webtest.TLSServer + "  client_auth_type: Sometimes\n", "client_auth_type"},
		"bad version":      {webtest.TLSServer + "  min_version: TLS9\n", "TLS version"},
		"missing key file": {"tls_server_config:\n  cert_file: server.pem\n  key_file: nosuch.key\n", "nosuch.key"},
	} {
		if _, _, err := Load(p.Config(t, c.yaml)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// Relative paths are the config file's directory's, and Node Exporter's
	// own keys are accepted.
	_, cfg, err := Load(p.Config(t, webtest.TLSServer+"  min_version: TLS13\n"+
		"  prefer_server_cipher_suites: true\n  curve_preferences: [X25519, CurveP256]\nhttp_server_config:\n  http2: true\n"))
	if err != nil || cfg.MinVersion != tls.VersionTLS13 || len(cfg.CurvePreferences) != 2 {
		t.Errorf("a valid file: %v %+v", err, cfg)
	}
}

// serve runs a handler answering "ok" behind w (TLS and Wrap) on 127.0.0.1.
func serve(t *testing.T, w *Web) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: w.Wrap(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { io.WriteString(rw, "ok") }))}
	go srv.Serve(tls.NewListener(ln, &tls.Config{GetConfigForClient: w.TLSForClient}))
	t.Cleanup(func() { srv.Close() })
	return "https://" + ln.Addr().String() + "/"
}

func get(c *http.Client, url, user, pw string) (int, http.Header, error) {
	req, _ := http.NewRequest("GET", url, nil)
	if user != "" {
		req.SetBasicAuth(user, pw)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header, nil
}

func TestBasicAuthAndReload(t *testing.T) {
	p := webtest.New(t)
	w, err := New("metrics", p.Config(t, webtest.TLSServer+"http_server_config:\n  headers:\n"+
		"    X-Content-Type-Options: nosniff\nbasic_auth_users:\n  prometheus: "+webtest.Hash(t, "s3cret")+"\n"), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	url, c := serve(t, w), p.Client("")
	for _, x := range []struct {
		user, pw string
		code     int
	}{{"", "", 401}, {"prometheus", "wrong", 401}, {"nobody", "s3cret", 401}, {"prometheus", "s3cret", 200}, {"prometheus", "s3cret", 200}} {
		code, h, err := get(c, url, x.user, x.pw)
		if err != nil || code != x.code || h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s/%s: %d %v (header %q)", x.user, x.pw, code, err, h.Get("X-Content-Type-Options"))
		}
	}
	// Plain HTTP to the TLS port: refused.
	if code, _, err := get(&http.Client{Timeout: 5 * time.Second}, strings.Replace(url, "https", "http", 1), "prometheus", "s3cret"); err == nil && code == 200 {
		t.Error("plain HTTP was served")
	}
	// A new password applies without a restart; an invalid edit keeps it.
	time.Sleep(10 * time.Millisecond)
	p.Config(t, webtest.TLSServer+"basic_auth_users:\n  prometheus: "+webtest.Hash(t, "n3w")+"\n")
	if code, _, _ := get(c, url, "prometheus", "n3w"); code != 200 {
		t.Errorf("new password: %d", code)
	}
	if code, _, _ := get(c, url, "prometheus", "s3cret"); code != 401 {
		t.Errorf("old password after the change: %d", code)
	}
	time.Sleep(10 * time.Millisecond)
	p.Config(t, "basic_auth_users: [broken\n")
	if code, _, _ := get(c, url, "prometheus", "n3w"); code != 200 {
		t.Errorf("after an invalid edit: %d (the previous settings must stay)", code)
	}
}

func TestClientCerts(t *testing.T) {
	p := webtest.New(t)
	w, err := New("metrics", p.Config(t, webtest.TLSServer+"  client_ca_file: ca.pem\n"+
		"  client_auth_type: RequireAndVerifyClientCert\n  client_allowed_sans: [prometheus.example]\n"), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	url := serve(t, w)
	if _, _, err := get(p.Client(""), url, "", ""); err == nil {
		t.Error("no client certificate: served")
	}
	if code, _, err := get(p.Client("client"), url, "", ""); err != nil || code != 200 {
		t.Errorf("with the client certificate: %d %v", code, err)
	}
	if _, _, err := get(p.Client("other"), url, "", ""); err == nil {
		t.Error("a certificate outside client_allowed_sans: served")
	}
	if l := w.Leaf(); l == nil || l.Subject.CommonName != "clifrd" {
		t.Errorf("Leaf: %v", l)
	}
}
