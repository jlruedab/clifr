package pqstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/parquet-go/parquet-go"
)

func rowsIn(t *testing.T, path string) int64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, _ := f.Stat()
	pf, err := parquet.OpenFile(f, fi.Size())
	if err != nil {
		t.Fatal(err)
	}
	return pf.NumRows()
}

func guardRows(n int, ts int64) []guardRow {
	r := make([]guardRow, n)
	for i := range r {
		r[i] = guardRow{TS: ts + int64(i), Kind: "skip"}
	}
	return r
}

func TestCompactAndRecover(t *testing.T) {
	dir := t.TempDir()
	day := filepath.Join(dir, "guard_events", "2026-10-09")
	for name, n := range map[string]int{"10-00": 3, "10-05": 4, "10-05-2": 1, "11-00": 2} {
		if err := writeFile(filepath.Join(day, name+".parquet"), guardRows(n, 0)); err != nil {
			t.Fatal(err)
		}
	}
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// 11:30: hour 10 is finished, hour 11 is not.
	if err := s.compact(time.Date(2026, 10, 9, 11, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if n := rowsIn(t, filepath.Join(day, "10.parquet")); n != 8 {
		t.Errorf("hour 10 has %d rows, want 8", n)
	}
	left, _ := filepath.Glob(filepath.Join(day, "*.parquet"))
	if len(left) != 2 { // 10.parquet, 11-00.parquet
		t.Errorf("files after compaction: %v", left)
	}

	// A crash after the rename but before the parts were removed: the next
	// Open removes the parts already merged.
	writeFile(filepath.Join(day, "10-30.parquet"), guardRows(5, 0))
	os.WriteFile(filepath.Join(day, "11-05.parquet.tmp"), []byte("partial"), 0o644)
	if _, err := Open(dir, Options{}); err != nil {
		t.Fatal(err)
	}
	left, _ = filepath.Glob(filepath.Join(day, "*"))
	if len(left) != 2 {
		t.Errorf("files after recovery: %v", left)
	}
}

func TestRetentionAndSizeCap(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 9, 12, 10, 0, 0, time.UTC)
	for _, h := range []string{"2026-10-06/08", "2026-10-09/09", "2026-10-09/10", "2026-10-09/12-05"} {
		writeFile(filepath.Join(dir, "samples", h+".parquet"), make([]sampleRow, 2000))
	}
	s, _ := Open(dir, Options{Retention: 72 * time.Hour})
	if err := s.expire(now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "samples", "2026-10-06")); !os.IsNotExist(err) {
		t.Error("hour older than the retention was kept (or its empty day directory)")
	}
	one := dirSize(filepath.Join(dir, "samples", "2026-10-09"))
	s.opt.MaxBytes = one / 2 // room for one of the three files left
	if err := s.expire(now); err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "samples", "*", "*.parquet"))
	// The cap removes the oldest hours, never the current one.
	if len(left) != 1 || filepath.Base(left[0]) != "12-05.parquet" {
		t.Errorf("after size cap: %v", left)
	}
}
