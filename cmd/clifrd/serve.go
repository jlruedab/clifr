package main

import (
	"net/http"
	"os"

	"clifr/internal/recorder"
	"clifr/internal/remote"
)

// startServe starts clifrd --serve. A bad address was refused before (a
// configuration error stops clifrd); anything else that keeps it from
// serving (no tokens, the certificate, the port) is logged, and clifrd
// records without serving: the recording comes first. It never serves
// without a token file.
func startServe(addr, tokenFile, tlsDir, dataDir, version string, log *recorder.Logger) *http.Server {
	tokens, err := remote.LoadTokens(tokenFile)
	if err != nil {
		log.Errorf("serve: %v; not serving (clifrd token new adds one)", err)
		return nil
	}
	host, _ := os.Hostname()
	cert, fp, created, err := remote.LoadOrCreateCert(tlsDir, host)
	if err != nil {
		log.Errorf("serve: TLS certificate in %s: %v; not serving", tlsDir, err)
		return nil
	}
	if created {
		log.Printf("serve: created a self-signed TLS certificate in %s", tlsDir)
	}
	ln, isTLS, err := remote.Listen(addr, cert)
	if err != nil {
		log.Errorf("serve: %v; not serving (under the systemd unit, install its serve drop-in)", err)
		return nil
	}
	s := &remote.Server{DataDir: dataDir, Tokens: tokens, Version: version, Logf: log.Warnf}
	srv := s.HTTPServer()
	go srv.Serve(ln)
	if isTLS {
		log.Printf("serve: recording served at https://%s (certificate %s; clifr --host pins it on first use)", ln.Addr(), fp)
	} else {
		log.Printf("serve: recording served at http://%s (loopback: no TLS)", ln.Addr())
	}
	return srv
}
