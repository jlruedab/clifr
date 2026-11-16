package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"clifr/internal/pqstore"
)

// TestSealSetupCmd: the verification key is the only line on standard
// output, it is not stored in the data directory, and a second setup needs
// --new.
func TestSealSetupCmd(t *testing.T) {
	dir := t.TempDir()
	out := captureStdout(t, func() {
		if err := sealSetupCmd([]string{"--data-dir", dir}); err != nil {
			t.Fatal(err)
		}
	})
	key := strings.TrimSpace(out)
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("stdout %q, want the key alone", out)
	}
	k0, err := pqstore.ParseVerifyKey(key)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := os.ReadFile(dir + "/integrity/" + pqstore.SealStateFile)
	if len(state) == 0 || strings.Contains(string(state), strings.TrimPrefix(key, pqstore.VerifyKeyPrefix)) {
		t.Errorf("seal.state missing or holds the verification key")
	}
	if err := sealSetupCmd([]string{"--data-dir", dir}); err == nil || !strings.Contains(err.Error(), "--new") {
		t.Errorf("second setup: %v", err)
	}
	out = captureStdout(t, func() {
		if err := sealSetupCmd([]string{"--data-dir", dir, "--new"}); err != nil {
			t.Fatal(err)
		}
	})
	k1, err := pqstore.ParseVerifyKey(out)
	if err != nil || pqstore.SealKeyID(k1) == pqstore.SealKeyID(k0) {
		t.Errorf("--new: %q %v", out, err)
	}
	if err := sealSetupCmd([]string{"--data-dir", dir + "/nope"}); err == nil {
		t.Error("a missing data directory was accepted")
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	f()
	w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}
