package metrics

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// pki writes a CA, a server certificate for 127.0.0.1 and two client
// certificates (one with the SAN "prometheus.example") into dir.
type pki struct {
	dir  string
	pool *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{dir: t.TempDir(), pool: x509.NewCertPool()}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	p.pool.AddCert(ca)
	p.write("ca.pem", "CERTIFICATE", caDER)
	issue := func(name string, serial int64, tmpl *x509.Certificate) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl.SerialNumber, tmpl.NotBefore, tmpl.NotAfter = big.NewInt(serial), time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		kd, _ := x509.MarshalECPrivateKey(k)
		p.write(name+".pem", "CERTIFICATE", der)
		p.write(name+".key", "EC PRIVATE KEY", kd)
	}
	issue("server", 2, &x509.Certificate{Subject: pkix.Name{CommonName: "clifrd"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	issue("client", 3, &x509.Certificate{Subject: pkix.Name{CommonName: "prometheus"}, DNSNames: []string{"prometheus.example"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	issue("other", 4, &x509.Certificate{Subject: pkix.Name{CommonName: "other"}, DNSNames: []string{"other.example"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return p
}

func (p *pki) write(name, typ string, der []byte) {
	os.WriteFile(filepath.Join(p.dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600)
}

func (p *pki) config(t *testing.T, yaml string) string {
	t.Helper()
	f := filepath.Join(p.dir, "web-config.yml")
	if err := os.WriteFile(f, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func hash(t *testing.T, pw string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func TestWebConfigChecks(t *testing.T) {
	p := newPKI(t)
	for name, c := range map[string]struct{ yaml, want string }{
		"unknown key":      {"tls_server_config:\n  cert_file: server.pem\n  key_file: server.key\n  sni: x\n", "field sni not found"},
		"not bcrypt":       {"basic_auth_users:\n  prometheus: plaintext\n", "not a bcrypt hash"},
		"header":           {"http_server_config:\n  headers:\n    X-Powered-By: me\n", "is not one of"},
		"no certificate":   {"tls_server_config:\n  client_auth_type: NoClientCert\n", "needs cert_file and key_file"},
		"mTLS without CA":  {"tls_server_config:\n  cert_file: server.pem\n  key_file: server.key\n  client_auth_type: RequireAndVerifyClientCert\n", "needs client_ca_file"},
		"bad auth type":    {"tls_server_config:\n  cert_file: server.pem\n  key_file: server.key\n  client_auth_type: Sometimes\n", "client_auth_type"},
		"bad version":      {"tls_server_config:\n  cert_file: server.pem\n  key_file: server.key\n  min_version: TLS9\n", "TLS version"},
		"missing key file": {"tls_server_config:\n  cert_file: server.pem\n  key_file: nosuch.key\n", "nosuch.key"},
	} {
		if _, _, err := LoadWebConfig(p.config(t, c.yaml)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// Relative paths are the config file's directory's, and Node Exporter's
	// own keys are accepted.
	_, cfg, err := LoadWebConfig(p.config(t, "tls_server_config:\n  cert_file: server.pem\n  key_file: server.key\n  min_version: TLS13\n"+
		"  prefer_server_cipher_suites: true\n  curve_preferences: [X25519, CurveP256]\nhttp_server_config:\n  http2: true\n"))
	if err != nil || cfg.MinVersion != tls.VersionTLS13 || len(cfg.CurvePreferences) != 2 {
		t.Errorf("a valid file: %v %+v", err, cfg)
	}
}

// serve runs /metrics with the web configuration file f on 127.0.0.1 and
// returns its URL.
func serve(t *testing.T, f string) string {
	t.Helper()
	web, err := NewWeb(f, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", web)
	if err != nil {
		t.Fatal(err)
	}
	srv := Serve(ln, func() *Snapshot { return testSnapshot() }, web)
	t.Cleanup(func() { srv.Close() })
	return "https://" + ln.Addr().String() + "/metrics"
}

func client(p *pki, cert string) *http.Client {
	cfg := &tls.Config{RootCAs: p.pool}
	if cert != "" {
		c, _ := tls.LoadX509KeyPair(filepath.Join(p.dir, cert+".pem"), filepath.Join(p.dir, cert+".key"))
		cfg.Certificates = []tls.Certificate{c}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
}

func get(t *testing.T, c *http.Client, url, user, pw string) (int, string, http.Header, error) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if user != "" {
		req.SetBasicAuth(user, pw)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header, nil
}

func TestMetricsTLSBasicAuth(t *testing.T) {
	p := newPKI(t)
	f := p.config(t, "tls_server_config:\n  cert_file: server.pem\n  key_file: server.key\nhttp_server_config:\n  headers:\n"+
		"    X-Content-Type-Options: nosniff\nbasic_auth_users:\n  prometheus: "+hash(t, "s3cret")+"\n")
	url := serve(t, f)
	c := client(p, "")
	for _, x := range []struct {
		user, pw string
		code     int
	}{{"", "", 401}, {"prometheus", "wrong", 401}, {"nobody", "s3cret", 401}, {"prometheus", "s3cret", 200}, {"prometheus", "s3cret", 200}} {
		code, body, h, err := get(t, c, url, x.user, x.pw)
		if err != nil || code != x.code || h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s/%s: %d %v (header %q)", x.user, x.pw, code, err, h.Get("X-Content-Type-Options"))
		}
		if x.code == 200 && !strings.Contains(body, "clifr_build_info") {
			t.Errorf("body: %.100s", body)
		}
	}
	// Plain HTTP to the TLS port: no metrics.
	if code, _, _, err := get(t, &http.Client{Timeout: 5 * time.Second}, strings.Replace(url, "https", "http", 1), "prometheus", "s3cret"); err == nil && code == 200 {
		t.Error("plain HTTP was served")
	}

	// A new password: applies without a restart; an invalid edit keeps it.
	time.Sleep(10 * time.Millisecond)
	p.config(t, "tls_server_config:\n  cert_file: server.pem\n  key_file: server.key\nbasic_auth_users:\n  prometheus: "+hash(t, "n3w")+"\n")
	if code, _, _, _ := get(t, c, url, "prometheus", "n3w"); code != 200 {
		t.Errorf("new password: %d", code)
	}
	if code, _, _, _ := get(t, c, url, "prometheus", "s3cret"); code != 401 {
		t.Errorf("old password after the change: %d", code)
	}
	time.Sleep(10 * time.Millisecond)
	p.config(t, "basic_auth_users: [broken\n")
	if code, _, _, _ := get(t, c, url, "prometheus", "n3w"); code != 200 {
		t.Errorf("after an invalid edit: %d (the previous settings must stay)", code)
	}
}

func TestMetricsClientCerts(t *testing.T) {
	p := newPKI(t)
	f := p.config(t, "tls_server_config:\n  cert_file: server.pem\n  key_file: server.key\n  client_ca_file: ca.pem\n"+
		"  client_auth_type: RequireAndVerifyClientCert\n  client_allowed_sans: [prometheus.example]\n")
	url := serve(t, f)
	if _, _, _, err := get(t, client(p, ""), url, "", ""); err == nil {
		t.Error("no client certificate: served")
	}
	if code, _, _, err := get(t, client(p, "client"), url, "", ""); err != nil || code != 200 {
		t.Errorf("with the client certificate: %d %v", code, err)
	}
	if _, _, _, err := get(t, client(p, "other"), url, "", ""); err == nil {
		t.Error("a certificate outside client_allowed_sans: served")
	}
}

func TestCheckAddrTLS(t *testing.T) {
	for _, c := range []struct {
		addr    string
		withTLS bool
		ok      bool
	}{{":9100", true, true}, {"192.0.2.7:9100", true, true}, {":9100", false, false}, {"192.0.2.7:9100", false, false},
		{"127.0.0.1:9100", false, true}, {"host.example:9100", true, false}} {
		if _, err := CheckAddr(c.addr, c.withTLS); (err == nil) != c.ok {
			t.Errorf("%s TLS %v: %v", c.addr, c.withTLS, err)
		}
	}
}
