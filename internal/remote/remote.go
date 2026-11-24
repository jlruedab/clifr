// Package remote is clifrd --serve and what clifr --host needs of it: the
// recording's Parquet files over HTTPS, so clifr can query another host's
// recording locally. Every request needs a token (stored hashed, tokens.go);
// TLS uses clifrd's own self-signed certificate, which clifr pins on first
// use (cert.go); plain HTTP only on loopback addresses. Only data files are
// served, never the token file or the TLS key. Pure Go: clifrd is static.
package remote

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

// API paths. Each needs "Authorization: Bearer TOKEN".
const (
	PathInfo  = "/v1/info"  // Info
	PathFiles = "/v1/files" // ?from=MS&to=MS (both absent: the whole recording): Files
	PathFile  = "/v1/file"  // ?path=REL: the file's bytes; header SHA256Header
)

// SHA256Header carries a served file's SHA-256 (hex), which clifr checks.
const SHA256Header = "X-Clifr-Sha256"

// DefaultTokenFile holds the SHA-256 of each token clifrd accepts.
const DefaultTokenFile = "/etc/clifr/serve-tokens"

// Info describes the served recording.
type Info struct {
	Server        string `json:"server"` // clifrd's version
	NowMS         int64  `json:"now_ms"` // the server's clock
	FromMS        int64  `json:"from_ms"`
	ToMS          int64  `json:"to_ms"` // the recording's range (from its sample files)
	Hostname      string `json:"hostname"`
	MachineID     string `json:"machine_id"`
	BootID        string `json:"boot_id"`
	TimeZone      string `json:"timezone"`
	SchemaVersion string `json:"schema_version"`
	Recorder      string `json:"clifrd_version"`
}

// File is one data file of a window.
type File struct {
	Path   string `json:"path"` // relative to the data directory, '/'-separated
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"` // hex
}

// Files is a window's data files: exactly the set a query of that window
// reads (bundle.Select: files copied whole, and the entity files written
// after the window, served whole too so that each stays cacheable).
type Files struct {
	FromMS int64  `json:"from_ms"`
	ToMS   int64  `json:"to_ms"`
	Files  []File `json:"files"`
}

// Fingerprint is how a certificate is pinned and shown: the SHA-256 of its
// public key, as OpenSSH prints host keys ("SHA256:" and unpadded base64).
func Fingerprint(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}
