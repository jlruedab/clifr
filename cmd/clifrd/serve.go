package main

import (
	"crypto/tls"
	"net/http"
	"os"

	"clifr/internal/recorder"
	"clifr/internal/remote"
	"clifr/internal/webconfig"
)

// startServe starts clifrd --serve. A bad address was refused before (a
// configuration error stops clifrd); anything else that keeps it from
// serving (no tokens, the certificate, the port) is logged, and clifrd
// records without serving: the recording comes first. It never serves
// without a token file.
func startServe(addr, tokenFile, tlsDir, dataDir, version string, web *webconfig.Web, log *recorder.Logger) *http.Server {
	tokens, err := remote.LoadTokens(tokenFile)
	if err != nil {
		log.Errorf("serve: %v; not serving (clifrd token new adds one)", err)
		return nil
	}
	var cert tls.Certificate
	var fp string
	if web == nil { // clifrd's own self-signed certificate, pinned by clifr
		host, _ := os.Hostname()
		var created bool
		cert, fp, created, err = remote.LoadOrCreateCert(tlsDir, host)
		if err != nil {
			log.Errorf("serve: TLS certificate in %s: %v; not serving", tlsDir, err)
			return nil
		}
		if created {
			log.Printf("serve: created a self-signed TLS certificate in %s", tlsDir)
		}
	} else if l := web.Leaf(); l != nil {
		fp = remote.Fingerprint(l)
	}
	ln, isTLS, err := remote.Listen(addr, cert, web)
	if err != nil {
		log.Errorf("serve: %v; not serving (under the systemd unit, install its serve drop-in)", err)
		return nil
	}
	s := &remote.Server{DataDir: dataDir, Tokens: tokens, Version: version, Logf: log.Warnf}
	srv := s.HTTPServer()
	go srv.Serve(ln)
	switch {
	case web != nil:
		log.Printf("serve: recording served at https://%s (the certificate of --serve-tls-config, %s: clifr --host "+
			"verifies it with --tls-ca or the system's CAs)", ln.Addr(), fp)
		if web.HasUsers() {
			log.Printf("serve: the file's basic_auth_users and client certificate settings apply to --metrics only; --serve uses tokens")
		}
	case isTLS:
		log.Printf("serve: recording served at https://%s (certificate %s; clifr --host pins it on first use)", ln.Addr(), fp)
	default:
		log.Printf("serve: recording served at http://%s (loopback: no TLS)", ln.Addr())
	}
	return srv
}
