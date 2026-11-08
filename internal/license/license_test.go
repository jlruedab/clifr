package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignParse(t *testing.T) {
	pub, priv := testKey(t)
	other, _ := testKey(t)
	l := License{ID: "CL-0001", Customer: "Acme Ltd", Contact: "licensing@example.com", Issued: "2026-11-08",
		Expires: "2027-11-07", Features: []string{FeatureRemote}}
	text, err := Sign(l, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(text, []byte("clifr commercial licence CL-0001 for Acme Ltd\n-----BEGIN CLIFR LICENSE-----\n")) {
		t.Errorf("text:\n%s", text)
	}
	got, err := Parse(text, []ed25519.PublicKey{other, pub}) // the second key of a list
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "CL-0001" || got.Customer != "Acme Ltd" || !got.Has(FeatureRemote) || got.Has("fleet") || got.V != 1 {
		t.Errorf("parsed %+v", got)
	}
	// Pasted with mail quoting around it, and CRLF line ends.
	pasted := "Hello,\r\nhere is your licence:\r\n\r\n" + strings.ReplaceAll(string(text), "\n", "\r\n") + "\r\nRegards\r\n"
	if _, err := Parse([]byte(pasted), []ed25519.PublicKey{pub}); err != nil {
		t.Errorf("pasted: %v", err)
	}

	if _, err := Parse(text, []ed25519.PublicKey{other}); err != ErrUnknownKey {
		t.Errorf("unknown key: %v", err)
	}
	if _, err := Parse(text, nil); err != ErrUnknownKey {
		t.Errorf("no keys: %v", err)
	}
	// An altered field: the body is re-encoded with another expiry.
	forged := strings.Replace(string(text), string(mustB64(t, text)), b64([]byte(strings.Replace(string(body(t, text)), "2027-11-07", "2099-12-31", 1))), 1)
	if _, err := Parse([]byte(forged), []ed25519.PublicKey{pub}); err != ErrUnknownKey {
		t.Errorf("altered expiry: %v", err)
	}
	for _, bad := range []string{"", "random text", strings.Replace(string(text), "-----SIGNATURE-----", "", 1),
		strings.Replace(string(text), "-----END CLIFR LICENSE-----", "", 1)} {
		if _, err := Parse([]byte(bad), []ed25519.PublicKey{pub}); err != ErrDamaged {
			t.Errorf("damaged %.30q: %v", bad, err)
		}
	}
	if _, err := Sign(License{Customer: "x", Issued: "2026-11-08"}, priv); err == nil {
		t.Error("signed without an id")
	}
	if _, err := Sign(License{ID: "x", Customer: "x", Issued: "8/11/2026"}, priv); err == nil {
		t.Error("signed with a bad date")
	}
}

func TestExpired(t *testing.T) {
	l := License{Expires: "2027-11-07"}
	day := func(s string) time.Time { tm, _ := time.Parse("2006-01-02 15:04", s); return tm }
	for when, want := range map[string]bool{"2027-11-07 23:59": false, "2027-11-08 00:00": true, "2026-01-01 00:00": false} {
		if got := l.Expired(day(when)); got != want {
			t.Errorf("%s: expired %v", when, got)
		}
	}
	if (&License{}).Expired(day("2099-01-01 00:00")) {
		t.Error("no expiry date expired")
	}
}

func TestPublicKeyText(t *testing.T) {
	pub, _ := testKey(t)
	s := FormatPublicKey(pub)
	got, err := ParsePublicKey(s + "\n")
	if err != nil || !got.Equal(pub) || !strings.HasPrefix(s, "clifr-ed25519:") {
		t.Errorf("%s: %v", s, err)
	}
	if _, err := ParsePublicKey("clifr-ed25519:AAAA"); err == nil {
		t.Error("a short key accepted")
	}
	if len(Keys()) != 0 {
		t.Error("production keys before 7.3c")
	}
}

// body and mustB64 take a licence text apart for the forgery test.
func body(t *testing.T, text []byte) []byte {
	b, _, err := split(text)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustB64(t *testing.T, text []byte) string {
	s := string(text)
	i := strings.Index(s, beginLine) + len(beginLine)
	j := strings.Index(s, sigLine)
	return strings.TrimSpace(s[i:j])
}

func b64(b []byte) string {
	var buf bytes.Buffer
	wrap(&buf, base64.StdEncoding.EncodeToString(b))
	return strings.TrimSpace(buf.String())
}
