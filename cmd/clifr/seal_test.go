package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clifr/internal/bundle"
	"clifr/internal/pqstore"
	"clifr/internal/store"
)

// TestVerifySeals: clifr verify --integrity --seal-key on a sealed
// recording, then on one with a changed file; the seal options' usage
// errors; the sealing state in clifr info.
func TestVerifySeals(t *testing.T) {
	dir := t.TempDir()
	key, id, err := pqstore.SealSetup(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	s, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	s.SetMeta("hostname", "h")
	for i := range 3 {
		ts := time.Now().UnixMilli() + int64(i)
		s.Write(&store.Batch{Sample: store.Sample{TS: ts},
			ProcInserts: []store.ProcRow{{ID: int64(i + 1), PID: i + 1, StartTime: 1, Comm: "x", FirstSeen: ts}}})
		if err := s.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	out, err := capture(t, "verify", "--integrity", "-D", dir)
	if err != nil || !strings.Contains(out, "Sealing:      on, chain "+id) || !strings.Contains(out, "not verified") {
		t.Errorf("without a key: %v\n%s", err, out)
	}
	kf := filepath.Join(t.TempDir(), "key")
	os.WriteFile(kf, []byte(key+"\n"), 0o600)
	out, err = capture(t, "verify", "--integrity", "-D", dir, "--seal-key", "@"+kf)
	if err != nil || !strings.Contains(out, "Altered:      nothing found") || !strings.Contains(out, "verified") {
		t.Errorf("clean: %v\n%s", err, out)
	}
	out, err = capture(t, "info", "-D", dir)
	if err != nil || !strings.Contains(out, "Sealing:          on, chain "+id) {
		t.Errorf("info: %v\n%s", err, out)
	}

	parts, _ := filepath.Glob(filepath.Join(dir, pqstore.Dir("samples"), "*", "*.parquet"))
	b, _ := os.ReadFile(parts[0])
	b[len(b)/2] ^= 1
	os.WriteFile(parts[0], b, 0o640)
	out, err = capture(t, "verify", "--integrity", "-D", dir, "--seal-key", key)
	if err == nil || !strings.Contains(err.Error(), "altered after it was sealed") || !strings.Contains(out, "ALTERED:") {
		t.Errorf("changed file: %v\n%s", err, out)
	}

	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"verify", "-D", dir, "--seal-key", key}, "are for clifr verify --integrity"},
		{[]string{"verify", "--integrity", "-D", dir, "--seal-anchor", id + "/1:00"}, "needs --seal-key"},
		{[]string{"verify", "--integrity", "-D", dir, "--seal-key", "cs1-00"}, "not a clifr verification key"},
		{[]string{"verify", "--integrity", "-D", dir, "--seal-key", "@/nonexistent"}, "--seal-key"},
	} {
		if err := run(c.args); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.args, err, c.want)
		}
	}
}

// TestVerifySealsBundle: a bundle carries the integrity logs; verified with
// the key it shows nothing altered, and a file changed before the bundle
// was made (its bundle.json checksum then matches) is found by the seals.
func TestVerifySealsBundle(t *testing.T) {
	dir := t.TempDir()
	key, _, _ := pqstore.SealSetup(dir, false)
	s, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	s.SetMeta("hostname", "h")
	for i := range 3 {
		ts := time.Now().UnixMilli() + int64(i)
		s.Write(&store.Batch{Sample: store.Sample{TS: ts},
			ProcInserts: []store.ProcRow{{ID: int64(i + 1), PID: i + 1, StartTime: 1, Comm: "x", FirstSeen: ts}}})
		s.Flush()
	}
	s.Close()
	mk := func() string {
		p := filepath.Join(t.TempDir(), "b.tar")
		f, _ := os.Create(p)
		if _, err := bundle.Write(bundle.Options{DataDir: dir, Writer: "test", Now: time.Now()}, f); err != nil {
			t.Fatal(err)
		}
		f.Close()
		return p
	}
	b0 := mk()
	out, err := capture(t, "verify", "--integrity", "-D", b0, "--seal-key", key)
	if err != nil || !strings.Contains(out, "Altered:      nothing found") || strings.Contains(out, "Not protected") {
		t.Errorf("bundle: %v\n%s", err, out)
	}
	out, err = capture(t, "verify", "--integrity", "-D", b0)
	if err != nil || !strings.Contains(out, "Sealing:      on, chain") {
		t.Errorf("bundle without a key: %v\n%s", err, out)
	}
	parts, _ := filepath.Glob(filepath.Join(dir, pqstore.Dir("samples"), "*", "*.parquet"))
	b, _ := os.ReadFile(parts[0])
	b[len(b)/2] ^= 1
	os.WriteFile(parts[0], b, 0o640)
	out, err = capture(t, "verify", "--integrity", "-D", mk(), "--seal-key", key)
	if err == nil || !strings.Contains(out, "ALTERED:") {
		t.Errorf("changed before bundling: %v\n%s", err, out)
	}
}
