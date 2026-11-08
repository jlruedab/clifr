// Package webtest makes certificates for tests of web configuration files:
// a CA, a server certificate for 127.0.0.1 and localhost, and two client
// certificates (SANs prometheus.example and other.example).
package webtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// PKI is a test CA and its certificates, as files in Dir: ca.pem,
// server.pem/.key, client.pem/.key, other.pem/.key.
type PKI struct {
	Dir  string
	Pool *x509.CertPool
}

// New makes them in a new temporary directory.
func New(t testing.TB) *PKI {
	t.Helper()
	p := &PKI{Dir: t.TempDir(), Pool: x509.NewCertPool()}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	p.Pool.AddCert(ca)
	p.write(t, "ca.pem", "CERTIFICATE", caDER)
	issue := func(name string, serial int64, tmpl *x509.Certificate) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl.SerialNumber, tmpl.NotBefore, tmpl.NotAfter = big.NewInt(serial), time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		kd, _ := x509.MarshalECPrivateKey(k)
		p.write(t, name+".pem", "CERTIFICATE", der)
		p.write(t, name+".key", "EC PRIVATE KEY", kd)
	}
	issue("server", 2, &x509.Certificate{Subject: pkix.Name{CommonName: "clifrd"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames: []string{"localhost"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	issue("client", 3, &x509.Certificate{Subject: pkix.Name{CommonName: "prometheus"}, DNSNames: []string{"prometheus.example"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	issue("other", 4, &x509.Certificate{Subject: pkix.Name{CommonName: "other"}, DNSNames: []string{"other.example"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return p
}

func (p *PKI) write(t testing.TB, name, typ string, der []byte) {
	if err := os.WriteFile(filepath.Join(p.Dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Config writes yaml as Dir/web-config.yml and returns its path.
func (p *PKI) Config(t testing.TB, yaml string) string {
	t.Helper()
	f := filepath.Join(p.Dir, "web-config.yml")
	if err := os.WriteFile(f, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// Client is an HTTPS client trusting the CA, with the client certificate
// cert ("client", "other") or none ("").
func (p *PKI) Client(cert string) *http.Client {
	cfg := &tls.Config{RootCAs: p.Pool}
	if cert != "" {
		c, _ := tls.LoadX509KeyPair(filepath.Join(p.Dir, cert+".pem"), filepath.Join(p.Dir, cert+".key"))
		cfg.Certificates = []tls.Certificate{c}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
}

// Hash is a bcrypt hash of pw (the lowest cost: tests).
func Hash(t testing.TB, pw string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

// TLSServer is the part of a server config the tests use.
const TLSServer = "tls_server_config:\n  cert_file: server.pem\n  key_file: server.key\n"
