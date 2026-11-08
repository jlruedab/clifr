package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clifr/internal/license"
)

// keygen, sign, verify, and what clifr itself makes of the licence.
func TestIssue(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "issuer.key")
	var out bytes.Buffer
	if err := run([]string{"keygen", "-out", key}, &out); err != nil {
		t.Fatal(err)
	}
	pub := strings.TrimSpace(out.String())
	if !strings.HasPrefix(pub, "clifr-ed25519:") {
		t.Fatalf("public key %q", pub)
	}
	if fi, _ := os.Stat(key); fi.Mode().Perm() != 0o600 {
		t.Errorf("private key mode %#o", fi.Mode().Perm())
	}
	if err := run([]string{"keygen", "-out", key}, &out); err == nil {
		t.Error("an existing key was overwritten")
	}
	out.Reset()
	run([]string{"pubkey", "-key", key}, &out)
	if strings.TrimSpace(out.String()) != pub {
		t.Errorf("pubkey %q, keygen printed %q", out.String(), pub)
	}

	lic := filepath.Join(dir, "acme.lic")
	if err := run([]string{"sign", "-key", key, "-id", "CL-2026-0001", "-customer", "Acme Ltd", "-contact", "sales@example.com",
		"-issued", "2026-11-08", "-years", "1", "-o", lic}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"verify", "-pub", pub, lic}, &out); err != nil ||
		!strings.Contains(out.String(), "CL-2026-0001 for Acme Ltd, issued 2026-11-08, expires 2027-11-07, features remote") {
		t.Errorf("verify: %v %q", err, out.String())
	}
	// clifr's own check, with this public key built in.
	k, _ := license.ParsePublicKey(pub)
	b, _ := os.ReadFile(lic)
	l, err := license.Parse(b, []ed25519.PublicKey{k})
	if err != nil || !l.Has(license.FeatureRemote) || l.Expired(time.Date(2027, 11, 7, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("clifr's check: %+v %v", l, err)
	}

	// A private key others can read is refused.
	os.Chmod(key, 0o644)
	if err := run([]string{"sign", "-key", key, "-id", "x", "-customer", "y"}, &out); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("group-readable key: %v", err)
	}
}
