package metrics

// clifrd --metrics-tls-config FILE: TLS and basic authentication for
// /metrics, in Node Exporter's web configuration format (exporter-toolkit's
// --web.config.file; the user, 2026-11-08), so an existing web-config.yml
// works unchanged. Keys this version does not handle are refused, not
// ignored. The file (and the certificate files it names) is checked again on
// every connection and request, as Node Exporter does: a renewed certificate
// or a changed password applies without a restart.

import (
	"bytes"
	"crypto/sha256"

	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// WebConfig is the web configuration file.
type WebConfig struct {
	TLS   *TLSServerConfig  `yaml:"tls_server_config"`
	HTTP  HTTPServerConfig  `yaml:"http_server_config"`
	Users map[string]string `yaml:"basic_auth_users"` // user -> bcrypt hash
}

// TLSServerConfig is its tls_server_config.
type TLSServerConfig struct {
	Cert              string   `yaml:"cert"`
	Key               string   `yaml:"key"`
	ClientCA          string   `yaml:"client_ca"`
	CertFile          string   `yaml:"cert_file"`
	KeyFile           string   `yaml:"key_file"`
	ClientAuthType    string   `yaml:"client_auth_type"`
	ClientCAFile      string   `yaml:"client_ca_file"`
	ClientAllowedSANs []string `yaml:"client_allowed_sans"`
	MinVersion        string   `yaml:"min_version"`
	MaxVersion        string   `yaml:"max_version"`
	CipherSuites      []string `yaml:"cipher_suites"`
	PreferServer      *bool    `yaml:"prefer_server_cipher_suites"` // accepted; Go chooses (since 1.17)
	CurvePreferences  []string `yaml:"curve_preferences"`
}

// HTTPServerConfig is its http_server_config.
type HTTPServerConfig struct {
	HTTP2   *bool             `yaml:"http2"` // accepted; clifrd serves HTTP/1.1, which Prometheus scrapes
	Headers map[string]string `yaml:"headers"`
}

// allowedHeaders are the headers Node Exporter lets the file set.
var allowedHeaders = []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
	"X-XSS-Protection", "Strict-Transport-Security"}

var clientAuthTypes = map[string]tls.ClientAuthType{
	"": tls.NoClientCert, "NoClientCert": tls.NoClientCert, "RequestClientCert": tls.RequestClientCert,
	"RequireAnyClientCert": tls.RequireAnyClientCert, "VerifyClientCertIfGiven": tls.VerifyClientCertIfGiven,
	"RequireAndVerifyClientCert": tls.RequireAndVerifyClientCert,
}

var tlsVersions = map[string]uint16{"TLS10": tls.VersionTLS10, "TLS11": tls.VersionTLS11, "TLS12": tls.VersionTLS12, "TLS13": tls.VersionTLS13}

var curves = map[string]tls.CurveID{"CurveP256": tls.CurveP256, "CurveP384": tls.CurveP384, "CurveP521": tls.CurveP521, "X25519": tls.X25519}

// LoadWebConfig reads and checks a web configuration file: every key known,
// the certificate and key loadable, the bcrypt hashes well formed.
func LoadWebConfig(path string) (*WebConfig, *tls.Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var c WebConfig
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && err.Error() != "EOF" {
		return nil, nil, fmt.Errorf("%s: %w (Node Exporter's web configuration format; keys clifrd does not handle are refused)", path, err)
	}
	dir := filepath.Dir(path)
	rel := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(dir, p)
	}
	for user, h := range c.Users {
		if _, err := bcrypt.Cost([]byte(h)); err != nil {
			return nil, nil, fmt.Errorf("%s: basic_auth_users: %s: not a bcrypt hash (htpasswd -nBC 10 \"\" | tr -d ':\\n')", path, user)
		}
	}
	for h := range c.HTTP.Headers {
		if !slices.Contains(allowedHeaders, h) {
			return nil, nil, fmt.Errorf("%s: http_server_config.headers: %s is not one of %s", path, h, strings.Join(allowedHeaders, ", "))
		}
	}
	if c.TLS == nil {
		return &c, nil, nil
	}
	t := c.TLS
	t.CertFile, t.KeyFile, t.ClientCAFile = rel(t.CertFile), rel(t.KeyFile), rel(t.ClientCAFile)
	cfg, err := t.tlsConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: tls_server_config: %w", path, err)
	}
	return &c, cfg, nil
}

func (t *TLSServerConfig) tlsConfig() (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	switch {
	case t.Cert != "" && t.CertFile != "", t.Key != "" && t.KeyFile != "":
		return nil, errors.New("give the certificate and key inline (cert, key) or as files (cert_file, key_file), not both")
	case t.Cert != "" && t.Key != "":
		cert, err = tls.X509KeyPair([]byte(t.Cert), []byte(t.Key))
	case t.CertFile != "" && t.KeyFile != "":
		cert, err = tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	default:
		return nil, errors.New("needs cert_file and key_file (or cert and key)")
	}
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	auth, ok := clientAuthTypes[t.ClientAuthType]
	if !ok {
		return nil, fmt.Errorf("client_auth_type %q (want RequireAndVerifyClientCert, or another crypto/tls ClientAuthType)", t.ClientAuthType)
	}
	cfg.ClientAuth = auth
	if t.ClientCAFile != "" || t.ClientCA != "" {
		pem := []byte(t.ClientCA)
		if t.ClientCAFile != "" {
			if pem, err = os.ReadFile(t.ClientCAFile); err != nil {
				return nil, err
			}
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("client CA: no certificate in it")
		}
		cfg.ClientCAs = pool
	} else if auth == tls.VerifyClientCertIfGiven || auth == tls.RequireAndVerifyClientCert {
		return nil, fmt.Errorf("client_auth_type %s needs client_ca_file", t.ClientAuthType)
	}
	if len(t.ClientAllowedSANs) > 0 {
		allowed := t.ClientAllowedSANs
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no client certificate (client_allowed_sans)")
			}
			c := cs.PeerCertificates[0]
			var sans []string
			sans = append(sans, c.DNSNames...)
			sans = append(sans, c.EmailAddresses...)
			for _, ip := range c.IPAddresses {
				sans = append(sans, ip.String())
			}
			for _, u := range c.URIs {
				sans = append(sans, u.String())
			}
			for _, s := range sans {
				if slices.Contains(allowed, s) {
					return nil
				}
			}
			return errors.New("client certificate's names are not in client_allowed_sans")
		}
	}
	for _, v := range []struct {
		name string
		dst  *uint16
	}{{t.MinVersion, &cfg.MinVersion}, {t.MaxVersion, &cfg.MaxVersion}} {
		if v.name == "" {
			continue
		}
		x, ok := tlsVersions[v.name]
		if !ok {
			return nil, fmt.Errorf("TLS version %q (TLS10..TLS13)", v.name)
		}
		*v.dst = x
	}
	for _, name := range t.CipherSuites {
		id, ok := cipherID(name)
		if !ok {
			return nil, fmt.Errorf("cipher suite %q (see crypto/tls CipherSuites)", name)
		}
		cfg.CipherSuites = append(cfg.CipherSuites, id)
	}
	for _, name := range t.CurvePreferences {
		id, ok := curves[name]
		if !ok {
			return nil, fmt.Errorf("curve %q (CurveP256, CurveP384, CurveP521, X25519)", name)
		}
		cfg.CurvePreferences = append(cfg.CurvePreferences, id)
	}
	return cfg, nil
}

func cipherID(name string) (uint16, bool) {
	for _, c := range tls.CipherSuites() {
		if c.Name == name {
			return c.ID, true
		}
	}
	return 0, false
}

// Web is a web configuration file, reloaded when it or the files it
// names change. A file that became invalid keeps the last good settings
// (and the error is logged once per change).
type Web struct {
	path string
	logf func(string, ...any)

	mu      sync.Mutex
	stamp   string // modification times and sizes of the file and its certificate files
	cfg     *WebConfig
	tls     *tls.Config
	authOK  map[[sha256.Size]byte]bool // user, password and hash already checked
	lastErr string
}

// NewWeb loads path; an invalid file at start is an error.
func NewWeb(path string, logf func(string, ...any)) (*Web, error) {
	w := &Web{path: path, logf: logf}
	c, t, err := LoadWebConfig(path)
	if err != nil {
		return nil, err
	}
	w.cfg, w.tls, w.stamp, w.authOK = c, t, w.files(c), map[[sha256.Size]byte]bool{}
	return w, nil
}

func (w *Web) files(c *WebConfig) string {
	paths := []string{w.path}
	if c != nil && c.TLS != nil {
		paths = append(paths, c.TLS.CertFile, c.TLS.KeyFile, c.TLS.ClientCAFile)
	}
	var b strings.Builder
	for _, p := range paths {
		if p == "" {
			continue
		}
		if fi, err := os.Stat(p); err == nil {
			fmt.Fprintf(&b, "%s %d %d;", p, fi.ModTime().UnixNano(), fi.Size())
		}
	}
	return b.String()
}

// current returns the settings, reloading them if a file changed.
func (w *Web) current() (*WebConfig, *tls.Config) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if st := w.files(w.cfg); st != w.stamp {
		c, t, err := LoadWebConfig(w.path)
		if err != nil {
			if err.Error() != w.lastErr {
				w.lastErr = err.Error()
				w.logf("metrics: %v; keeping the previous settings", err)
			}
		} else {
			w.cfg, w.tls, w.stamp, w.lastErr = c, t, w.files(c), ""
			w.authOK = map[[sha256.Size]byte]bool{}
		}
	}
	return w.cfg, w.tls
}

// hasTLS reports whether the file configures TLS (required for addresses
// other than loopback).
func (w *Web) hasTLS() bool {
	_, t := w.current()
	return t != nil
}

// tlsForClient is the listener's GetConfigForClient: each new connection
// takes the current settings.
func (w *Web) tlsForClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	_, t := w.current()
	if t == nil {
		return nil, errors.New("tls_server_config was removed: restart clifrd to serve without TLS")
	}
	return t, nil
}

// dummyHash is compared against for unknown users, so that the time an
// answer takes does not tell which user names exist.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("clifr-dummy"), bcrypt.DefaultCost)

// wrap adds the configured headers and, with basic_auth_users, basic
// authentication to h.
func (w *Web) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		c, _ := w.current()
		for k, v := range c.HTTP.Headers {
			rw.Header().Set(k, v)
		}
		if len(c.Users) > 0 && !w.authorized(c, r) {
			rw.Header().Set("WWW-Authenticate", `Basic realm="clifrd metrics", charset="UTF-8"`)
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(rw, r)
	})
}

func (w *Web) authorized(c *WebConfig, r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	hash, known := c.Users[user]
	key := sha256.Sum256([]byte(user + "\x00" + pass + "\x00" + hash))
	w.mu.Lock()
	cached := w.authOK[key]
	w.mu.Unlock()
	if cached && known {
		return true
	}
	h := []byte(hash)
	if !known {
		h = dummyHash
	}
	good := bcrypt.CompareHashAndPassword(h, []byte(pass)) == nil
	if good && known {
		w.mu.Lock()
		w.authOK[key] = true
		w.mu.Unlock()
		return true
	}
	return false
}

// HasTLS reports whether the settings serve TLS.
func (w *Web) HasTLS() bool { return w.hasTLS() }

// Describe is how clifrd's log names the protection: client certificates,
// basic authentication.
func (w *Web) Describe() string {
	c, t := w.current()
	var parts []string
	if t != nil && t.ClientAuth == tls.RequireAndVerifyClientCert {
		parts = append(parts, "client certificates required")
	}
	if len(c.Users) > 0 {
		parts = append(parts, fmt.Sprintf("basic authentication (%d users)", len(c.Users)))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}
