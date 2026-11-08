package metrics

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// CheckAddr validates a --metrics address and returns the one to listen on.
// Without TLS (no --metrics-tls-config, or one without tls_server_config)
// only loopback addresses: 127.0.0.1:9100, [::1]:9100 or localhost:9100, so
// no password or metric crosses a network in clear. With TLS any address,
// ":9100" for all interfaces (the user, 2026-11-08).
func CheckAddr(addr string, withTLS bool) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("--metrics %q: want HOST:PORT, e.g. 127.0.0.1:9100 (or :9100 with TLS)", addr)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	switch {
	case host != "" && ip == nil:
		return "", fmt.Errorf("--metrics %q: the host must be an IP address (or empty for all interfaces, with TLS)", addr)
	case !withTLS && (ip == nil || !ip.IsLoopback()):
		return "", fmt.Errorf("--metrics %q: without TLS only loopback addresses (127.0.0.1 or ::1); for others give "+
			"--metrics-tls-config FILE with tls_server_config (Node Exporter's web configuration format)", addr)
	}
	return net.JoinHostPort(host, port), nil
}

// Listen opens addr (CheckAddr first), with TLS when web has it. A failure
// here is the environment's (port taken, no TCP under the unit): clifrd logs
// it and records anyway.
func Listen(addr string, web *Web) (net.Listener, error) {
	withTLS := web != nil && web.hasTLS()
	a, err := CheckAddr(addr, withTLS)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", a)
	if errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, fmt.Errorf("--metrics %s: %w (the systemd unit allows no TCP sockets: install its metrics drop-in)", addr, err)
	}
	if err != nil || !withTLS {
		return ln, err
	}
	return tls.NewListener(ln, &tls.Config{GetConfigForClient: web.tlsForClient}), nil
}

// Handler serves /metrics from get's newest Snapshot.
func Handler(get func() *Snapshot) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s := get()
		if s == nil {
			http.Error(w, "clifrd has not sampled yet", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if r.Method == http.MethodHead {
			return
		}
		Write(w, s)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "clifrd: Prometheus metrics at /metrics")
	})
	return mux
}

// Serve serves Handler(get) on ln until Close is called on the returned server.
func Serve(ln net.Listener, get func() *Snapshot, web *Web) *http.Server {
	h := Handler(get)
	if web != nil {
		h = web.wrap(h) // headers and basic authentication
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	go srv.Serve(ln)
	return srv
}
