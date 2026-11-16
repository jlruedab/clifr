package pqstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sealedDir: a sealed recording (setup, three flushes, this hour
// compacted, a clean stop) and its key; anchors logged at info level.
func sealedDir(t *testing.T) (string, []byte, *Store, string) {
	t.Helper()
	dir := t.TempDir()
	vk, _, err := SealSetup(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	info := &logBuf{}
	s, err := Open(dir, Options{FlushInterval: time.Hour, Infof: info.logf})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		sealWrite(t, s)
	}
	if err := s.compact(time.Now().UTC().Truncate(time.Hour).Add(2*time.Hour), func() {}); err != nil {
		t.Fatal(err)
	}
	sealWrite(t, s)
	a := strings.Fields(strings.SplitN(info.String(), "seal anchor ", 2)[1])[0]
	return dir, mustKey(t, vk), s, a
}

func checkSeals(dir string, k []byte, anchors ...string) SealCheck {
	return CheckSeals(dir, [][]byte{k}, anchors, CheckIntegrity(dir), false)
}

func TestCheckSealsClean(t *testing.T) {
	dir, k, s, a := sealedDir(t)
	s.Close()
	c := checkSeals(dir, k, a)
	if c.Bad() != 0 || c.Verified == 0 || c.Removed == 0 || len(c.NoLine) != 0 || c.AfterLastSeal != 0 || c.After != 0 ||
		len(c.Anchors) != 1 || !strings.HasSuffix(c.Anchors[0], "reached") {
		t.Fatalf("%+v", c)
	}
	if st := ReadSealStatus(dir, false); st.State != "on" || st.KeyID != SealKeyID(k) || st.LastMS == 0 {
		t.Errorf("status %+v", st)
	}
}

// TestCheckSealsAltered: a changed file, a deleted file, a premature
// retention removal and anchors the recording no longer reaches are found;
// a file written after the last seal is unprotected, not altered.
func TestCheckSealsAltered(t *testing.T) {
	dir, k, s, a := sealedDir(t)
	// Two hour files: one removed by "retention" long before its time
	// (sealed by the next flush), one changed after it was sealed.
	hours, _ := filepath.Glob(filepath.Join(dir, "*", "*", "[0-9][0-9].parquet"))
	if len(hours) < 2 {
		t.Fatalf("hour files %v", hours)
	}
	if err := s.removeData(hours[0], retentionReason(72*time.Hour)); err != nil {
		t.Fatal(err)
	}
	sealWrite(t, s)
	s.Close()
	// A written file not sealed yet.
	extra := filepath.Join(dir, Dir("guard_events"), "2026-01-01", "00-00.parquet")
	os.MkdirAll(filepath.Dir(extra), 0o750)
	os.WriteFile(extra, []byte("x"), 0o640)
	s2 := newIntegrityLog(dir, func(string, ...any) {})
	s2.sealOpen(1)
	s2.record(extra)
	s2.close()

	b, _ := os.ReadFile(hours[1])
	b[len(b)/2] ^= 1
	os.WriteFile(hours[1], b, 0o640)
	opens, _ := filepath.Glob(filepath.Join(dir, Dir("processes"), "open", "*.parquet"))
	os.Remove(opens[0])

	id, rest, _ := strings.Cut(a, "/")
	_, tag, _ := strings.Cut(rest, ":")
	c := checkSeals(dir, k, a, id+"/9999:"+tag, id+"/1:00000000deadbeef", "junk")
	if len(c.Modified) != 1 || !strings.Contains(c.Modified[0], filepath.Base(filepath.Dir(filepath.Dir(hours[1])))) ||
		len(c.Deleted) != 1 || !strings.Contains(c.Deleted[0], "no removal") ||
		len(c.Premature) != 1 || !strings.Contains(c.Premature[0], "before its time") ||
		c.AfterLastSeal != 1 || c.AnchorsBad != 3 {
		t.Fatalf("%+v", c)
	}
	for i, want := range []string{"reached", "were removed", "rewritten", "not an anchor"} {
		if !strings.Contains(c.Anchors[i], want) {
			t.Errorf("anchor %d: %q, want %q", i, c.Anchors[i], want)
		}
	}
	// The same missing file in a bundle: left out by its window.
	if c := CheckSeals(dir, [][]byte{k}, nil, CheckIntegrity(dir), true); len(c.Deleted) != 0 || c.NotInBundle != 1 {
		t.Errorf("bundle: %+v", c)
	}
}

func TestSealStatus(t *testing.T) {
	dir := t.TempDir()
	if st := ReadSealStatus(dir, false); st.State != "off" {
		t.Errorf("empty: %+v", st)
	}
	SealSetup(dir, false)
	if st := ReadSealStatus(dir, false); st.State != "set up" {
		t.Errorf("after setup: %+v", st)
	}
	s, _ := sealStore(t, dir)
	sealWrite(t, s)
	s.Close()
	os.Remove(sealStatePath(dir))
	if st := ReadSealStatus(dir, false); st.State != "unsealed" || st.Why != "state-missing" {
		t.Errorf("state removed: %+v", st)
	}
	if st := ReadSealStatus(dir, true); st.State != "on" {
		t.Errorf("a bundle (no seal.state): %+v", st)
	}
	s, _ = sealStore(t, dir)
	sealWrite(t, s)
	s.Close()
	if st := ReadSealStatus(dir, true); st.State != "unsealed" || st.Why != "state-missing" {
		t.Errorf("after a run without state (the log says so, bundle or not): %+v", st)
	}
}

// TestCheckSealsBundleCopy: a bundle's copy of an open file made before
// clifrd rewrote it matches an earlier sealed version: verified in a
// bundle, a rollback in the data directory itself.
func TestCheckSealsBundleCopy(t *testing.T) {
	dir, k, s, _ := sealedDir(t)
	opens, _ := filepath.Glob(filepath.Join(dir, Dir("processes"), "open", "*.parquet"))
	old, _ := os.ReadFile(opens[0])
	sealWrite(t, s)
	s.Close()
	os.WriteFile(opens[0], old, 0o640)
	ir := CheckIntegrity(dir)
	if c := CheckSeals(dir, [][]byte{k}, nil, ir, true); c.Bad() != 0 {
		t.Errorf("bundle: %+v", c.Modified)
	}
	if c := CheckSeals(dir, [][]byte{k}, nil, ir, false); len(c.Modified) != 1 {
		t.Errorf("data directory: %+v", c.Modified)
	}
}
