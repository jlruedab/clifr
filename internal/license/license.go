// Package license is clifr's commercial licence (phase 7.3,
// docs/clifr-plan.md): a text file with the licence's fields as JSON and an
// Ed25519 signature of them, checked offline against public keys built into
// clifr. No network, no machine fingerprint, no obfuscation: under the AGPL
// anyone may remove the check from their own build; it marks commercial use
// (clifr --host), it does not police it. Pure Go, standard library only.
package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// FeatureRemote is what clifr --host needs.
const FeatureRemote = "remote"

const (
	beginLine = "-----BEGIN CLIFR LICENSE-----"
	sigLine   = "-----SIGNATURE-----"
	endLine   = "-----END CLIFR LICENSE-----"
	dateFmt   = "2006-01-02"
)

// License is a licence's fields. Fields this version does not know are kept
// in the signed bytes and ignored.
type License struct {
	V        int      `json:"v"`
	ID       string   `json:"id"`
	Customer string   `json:"customer"`
	Contact  string   `json:"contact,omitempty"` // whom to ask for a renewal
	Issued   string   `json:"issued"`            // YYYY-MM-DD
	Expires  string   `json:"expires,omitempty"` // YYYY-MM-DD, the last day it is valid; "" = no end
	Features []string `json:"features"`
}

// Errors of Parse, for the messages clifr prints.
var (
	ErrDamaged    = errors.New("not a clifr licence, or damaged (the BEGIN/SIGNATURE/END lines or their base64)")
	ErrUnknownKey = errors.New("not signed by a key this clifr knows (forged, altered, or for another product)")
)

// Parse reads a licence and checks its signature against keys. Text before
// the BEGIN line and after END (a note, a mail's quoting) is ignored.
func Parse(text []byte, keys []ed25519.PublicKey) (*License, error) {
	body, sig, err := split(text)
	if err != nil {
		return nil, err
	}
	ok := false
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, body, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, ErrUnknownKey
	}
	var l License
	if err := json.Unmarshal(body, &l); err != nil {
		return nil, fmt.Errorf("licence fields: %w", err)
	}
	if err := l.check(); err != nil {
		return nil, err
	}
	return &l, nil
}

// split returns the signed JSON and the signature.
func split(text []byte) (body, sig []byte, err error) {
	s := strings.ReplaceAll(string(text), "\r\n", "\n")
	i := strings.Index(s, beginLine)
	j := strings.Index(s, sigLine)
	k := strings.Index(s, endLine)
	if i < 0 || j < i || k < j {
		return nil, nil, ErrDamaged
	}
	dec := func(part string) ([]byte, error) {
		return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(part), ""))
	}
	if body, err = dec(s[i+len(beginLine) : j]); err != nil || len(body) == 0 {
		return nil, nil, ErrDamaged
	}
	if sig, err = dec(s[j+len(sigLine) : k]); err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, ErrDamaged
	}
	return body, sig, nil
}

func (l *License) check() error {
	if l.V != 1 {
		return fmt.Errorf("licence format version %d: this clifr reads version 1 (update clifr)", l.V)
	}
	if l.ID == "" || l.Customer == "" {
		return errors.New("licence without an id or a customer")
	}
	if _, err := time.Parse(dateFmt, l.Issued); err != nil {
		return fmt.Errorf("licence issue date %q: want YYYY-MM-DD", l.Issued)
	}
	if l.Expires != "" {
		if _, err := time.Parse(dateFmt, l.Expires); err != nil {
			return fmt.Errorf("licence expiry date %q: want YYYY-MM-DD", l.Expires)
		}
	}
	return nil
}

// Has reports whether the licence includes a feature.
func (l *License) Has(feature string) bool { return slices.Contains(l.Features, feature) }

// Expired reports whether now is after the licence's last day (UTC).
func (l *License) Expired(now time.Time) bool {
	if l.Expires == "" {
		return false
	}
	end, err := time.Parse(dateFmt, l.Expires)
	return err == nil && !now.UTC().Before(end.AddDate(0, 0, 1))
}

// Sign makes the licence text for l with the issuer's private key (the
// clifr-license tool; never in clifr itself).
func Sign(l License, priv ed25519.PrivateKey) ([]byte, error) {
	if l.V == 0 {
		l.V = 1
	}
	if err := l.check(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, body)
	var b bytes.Buffer
	fmt.Fprintf(&b, "clifr commercial licence %s for %s\n%s\n", l.ID, l.Customer, beginLine)
	wrap(&b, base64.StdEncoding.EncodeToString(body))
	fmt.Fprintln(&b, sigLine)
	wrap(&b, base64.StdEncoding.EncodeToString(sig))
	fmt.Fprintln(&b, endLine)
	return b.Bytes(), nil
}

func wrap(b *bytes.Buffer, s string) {
	for len(s) > 64 {
		b.WriteString(s[:64] + "\n")
		s = s[64:]
	}
	b.WriteString(s + "\n")
}

// ParsePublicKey reads a public key as clifr-license keygen prints it:
// "clifr-ed25519:" and the base64 key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "clifr-ed25519:"))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("not a clifr public key (clifr-ed25519:BASE64)")
	}
	return ed25519.PublicKey(b), nil
}

// FormatPublicKey is the text form of a public key.
func FormatPublicKey(k ed25519.PublicKey) string {
	return "clifr-ed25519:" + base64.StdEncoding.EncodeToString(k)
}

// productionKeys are the issuer's public keys built into clifr (a list, so
// that a key can be replaced: licences signed by an old one stay valid until
// it is taken out). Empty until the copyright holder generates the
// production key pair (7.3c); until then no licence is accepted.
var productionKeys = []string{}

// Keys are the public keys licences are checked against. Tests replace it.
var Keys = func() []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, s := range productionKeys {
		if k, err := ParsePublicKey(s); err == nil {
			out = append(out, k)
		}
	}
	return out
}
