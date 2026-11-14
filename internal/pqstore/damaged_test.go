package pqstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCompactDamagedPart: a damaged part (not Parquet) does not crash
// compaction (parquet-go panics on it), and the other hours still compact.
func TestCompactDamagedPart(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	day := filepath.Join(dir, Dir("guard_events"), "2026-10-09")
	writeFile(filepath.Join(day, "09-00.parquet"), guardRows(3, 0))
	os.WriteFile(filepath.Join(day, "09-05.parquet"), []byte("not parquet at all"), 0o640)
	writeFile(filepath.Join(day, "10-00.parquet"), guardRows(4, 0))
	writeFile(filepath.Join(day, "10-05.parquet"), guardRows(1, 0))
	err = s.compact(time.Date(2026, 10, 9, 11, 0, 0, 0, time.UTC), func() {})
	if err == nil {
		t.Error("no error for the damaged part")
	}
	if n := rowsIn(t, filepath.Join(day, "10.parquet")); n != 5 {
		t.Errorf("hour 10: %d rows, want 5 (compacted after hour 9 failed)", n)
	}
	if _, err := os.Stat(filepath.Join(day, "09-00.parquet")); err != nil {
		t.Errorf("hour 9's good part was lost: %v", err)
	}
}

// TestReadMetaDamaged: ReadMeta skips a damaged meta file.
func TestReadMetaDamaged(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, Options{})
	s.SetMeta("hostname", "web1")
	s.Close()
	os.WriteFile(filepath.Join(dir, Dir("meta"), "2026-10-09", "09-00.parquet"), []byte("x"), 0o640)
	os.MkdirAll(filepath.Join(dir, Dir("meta"), "2026-10-09"), 0o750)
	os.WriteFile(filepath.Join(dir, Dir("meta"), "2026-10-09", "09-00.parquet"), []byte("not parquet"), 0o640)
	m, err := ReadMeta(dir)
	if err != nil || m["hostname"] != "web1" {
		t.Errorf("meta %v, %v", m, err)
	}
}
