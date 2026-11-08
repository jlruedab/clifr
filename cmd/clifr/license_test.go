package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clifr/internal/license"
)

// testLicenseKey makes a key pair and makes clifr accept licences signed
// with it, for this test.
func testLicenseKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := license.Keys
	license.Keys = func() []ed25519.PublicKey { return []ed25519.PublicKey{pub} }
	t.Cleanup(func() { license.Keys = old })
	return priv
}

func writeLicense(t *testing.T, priv ed25519.PrivateKey, l license.License) string {
	t.Helper()
	b, err := license.Sign(l, priv)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "acme.lic")
	os.WriteFile(p, b, 0o644)
	return p
}

func TestLicenseCommand(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root install writes /etc/clifr/clifr.lic")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CLIFR_LICENSE", "")
	priv := testLicenseKey(t)

	if _, err := capture(t, "license"); err == nil || !strings.Contains(err.Error(), "no licence installed") {
		t.Errorf("none installed: %v", err)
	}
	good := writeLicense(t, priv, license.License{ID: "CL-0001", Customer: "Acme Ltd", Contact: "licensing@example.com",
		Issued: "2026-11-08", Expires: "2099-12-31", Features: []string{license.FeatureRemote}})
	if _, err := capture(t, "license", "install", good); err != nil {
		t.Fatal(err)
	}
	out, err := capture(t, "license")
	if err != nil || !strings.Contains(out, "Customer:  Acme Ltd") || !strings.Contains(out, "Status:    valid") ||
		!strings.Contains(out, "remote (clifr --host)") {
		t.Errorf("show: %v\n%s", err, out)
	}
	if out2, _ := capture(t, "license", "key"); out2 != out {
		t.Error("license key differs from license show")
	}

	// Expired: still shown, as expired, with the contact.
	old := writeLicense(t, priv, license.License{ID: "CL-0000", Customer: "Acme Ltd", Contact: "licensing@example.com",
		Issued: "2024-01-01", Expires: "2025-01-01", Features: []string{license.FeatureRemote}})
	out, err = capture(t, "--license", old, "license")
	if err != nil || !strings.Contains(out, "expired (clifr --host keeps working; renew it: licensing@example.com)") {
		t.Errorf("expired: %v\n%s", err, out)
	}

	// Signed by another key, or altered: refused, not installed.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged := writeLicense(t, other, license.License{ID: "CL-9999", Customer: "Mallory", Issued: "2026-11-08",
		Features: []string{license.FeatureRemote}})
	if _, err := capture(t, "license", "install", forged); err == nil || !strings.Contains(err.Error(), "not signed by a key") {
		t.Errorf("forged: %v", err)
	}
	if out, _ := capture(t, "license"); !strings.Contains(out, "CL-0001") {
		t.Errorf("the forged licence replaced the installed one:\n%s", out)
	}
	if _, err := capture(t, "license", "install"); err == nil {
		t.Error("install without a file accepted")
	}
}
