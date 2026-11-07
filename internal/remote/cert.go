package remote

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Certificate files in the TLS directory (clifrd --serve-tls-dir).
const (
	certFile = "cert.pem"
	keyFile  = "key.pem"
)

// LoadOrCreateCert returns clifrd's TLS certificate from dir, making a
// self-signed one (ECDSA P-256, valid 20 years) the first time. clifr pins
// its public key on first use, so it must not change: it is kept, never
// renewed by itself. The key is 0600 in a 0700 directory.
func LoadOrCreateCert(dir, hostname string) (cert tls.Certificate, fingerprint string, created bool, err error) {
	cp, kp := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	if _, err := os.Stat(cp); errors.Is(err, fs.ErrNotExist) {
		if err := createCert(dir, cp, kp, hostname); err != nil {
			return tls.Certificate{}, "", false, err
		}
		created = true
	}
	if fi, err := os.Stat(kp); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return tls.Certificate{}, "", false, fmt.Errorf("%s: mode %#o: the key must be readable by its owner only (chmod 600)", kp, fi.Mode().Perm())
	}
	cert, err = tls.LoadX509KeyPair(cp, kp)
	if err != nil {
		return tls.Certificate{}, "", false, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, "", false, err
	}
	cert.Leaf = leaf
	return cert, Fingerprint(leaf), created, nil
}

func createCert(dir, cp, kp, hostname string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "clifrd " + hostname, Organization: []string{"clifr (self-signed, pinned by clifr)"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if hostname != "" {
		tmpl.DNSNames = []string{hostname}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	// The key first, then the certificate: a certificate on disk means its
	// key is there too.
	if err := writeAtomic(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return err
	}
	return writeAtomic(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
