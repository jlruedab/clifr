package pqstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"clifr/internal/store"
)

// TestFlushAllOrNothing: when one table's file cannot be written, no other
// table's file of that flush is in place and the buffers are kept; the next
// flush writes each once. Before, the tables written the first time were
// written again: duplicate rows.
func TestFlushAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	day := time.Now().UTC().Format("2006-01-02")
	// guard_events' day directory is a file: its write fails.
	blocker := filepath.Join(dir, Dir("guard_events"), day)
	os.MkdirAll(filepath.Dir(blocker), 0o750)
	os.WriteFile(blocker, nil, 0o640)
	s.Write(&store.Batch{Sample: store.Sample{TS: 1000}, Guard: []store.GuardEvent{{TS: 1000, Kind: "skip"}}})
	if err := s.Flush(); err == nil {
		t.Fatal("the flush did not fail")
	}
	if n := countFiles(dir, "samples"); n != 0 {
		t.Fatalf("%d samples files in place after a failed flush", n)
	}
	os.Remove(blocker)
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if n, g := countFiles(dir, "samples"), countFiles(dir, "guard_events"); n != 1 || g != 1 {
		t.Errorf("after the retry: %d samples files, %d guard files; want 1 and 1", n, g)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*", "*", "*"+stageSuffix)); len(left) != 0 {
		t.Errorf("staged files left: %v", left)
	}
}

func countFiles(dir, table string) int {
	m, _ := filepath.Glob(filepath.Join(dir, Dir(table), "*", "*.parquet"))
	return len(m)
}

// TestFreeOldestHour deletes every table's files of the oldest hour, never
// one of the newest diskFullKeep, and nothing while compaction runs.
func TestFreeOldestHour(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 14, 10, 30, 0, 0, time.UTC)
	put := func(table, day, name string) string {
		p := filepath.Join(dir, Dir(table), day, name)
		os.MkdirAll(filepath.Dir(p), 0o750)
		os.WriteFile(p, []byte("12345"), 0o640)
		return p
	}
	a := put("samples", "2026-11-14", "07.parquet")
	b := put("guard_events", "2026-11-14", "07-05.parquet")
	c := put("samples", "2026-11-14", "08.parquet")
	keep := put("samples", "2026-11-14", "09-55.parquet") // the previous hour: kept
	s.busy.Store(true)
	if h, _ := s.freeOldestHour(now); h != "" {
		t.Errorf("freed %s while compaction ran", h)
	}
	s.busy.Store(false)
	h, n := s.freeOldestHour(now)
	if h != "2026-11-14 07:00" || n != 10 || exists(a) || exists(b) || !exists(c) {
		t.Errorf("first: %q %d", h, n)
	}
	if h, _ := s.freeOldestHour(now); h != "2026-11-14 08:00" || exists(c) {
		t.Errorf("second: %q", h)
	}
	if h, _ := s.freeOldestHour(now); h != "" || !exists(keep) {
		t.Errorf("freed %q from the newest hours", h)
	}
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }
