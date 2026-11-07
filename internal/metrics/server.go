package metrics

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// CheckAddr validates a --metrics address and returns the one to listen on.
// Only loopback addresses for now (the user, 2026-11-07: TLS and
// authentication come later): 127.0.0.1:9100, [::1]:9100 or localhost:9100.
func CheckAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("--metrics %q: want HOST:PORT, e.g. 127.0.0.1:9100", addr)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("--metrics %q: only loopback addresses for now (127.0.0.1 or ::1): there is no TLS or authentication yet", addr)
	}
	return net.JoinHostPort(host, port), nil
}

// Listen opens addr (CheckAddr first). A failure here is the environment's
// (port taken, no TCP under the unit): clifrd logs it and records anyway.
func Listen(addr string) (net.Listener, error) {
	a, err := CheckAddr(addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", a)
	if errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, fmt.Errorf("--metrics %s: %w (the systemd unit allows no TCP sockets: install its metrics drop-in)", addr, err)
	}
	return ln, err
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
func Serve(ln net.Listener, get func() *Snapshot) *http.Server {
	srv := &http.Server{
		Handler:           Handler(get),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	go srv.Serve(ln)
	return srv
}
