package pqstore

import (
	"fmt"
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

// A saved lsof output of a few MB must be stored compressed, not also as
// uncompressed min/max bounds.
func TestLargeTextCompresses(t *testing.T) {
	var b []byte
	for i := 0; len(b) < 3<<20; i++ {
		b = append(b, fmt.Sprintf("load    %7d root %4du IPv4 %9d 0t0 TCP 127.0.0.1:%d->127.0.0.2:%d (ESTABLISHED)\n",
			1000+i%50, i%4000, 4000000+i, 30000+i%5, 40000+i%20000)...)
	}
	p := filepath.Join(t.TempDir(), "v.parquet")
	if err := writeFile(p, []verifyRow{{ID: 1, Cmd: "lsof -n -P", Output: string(b)}}); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Size() > int64(len(b))/3 {
		t.Errorf("%d bytes of text stored in %d bytes", len(b), fi.Size())
	}
}

// A file written before a column was added must still be readable with the
// current row type (compaction copies old files): the new column reads as 0.
func TestReadOlderSchema(t *testing.T) {
	type oldKeyframeRow struct {
		TS    int64  `parquet:"ts"`
		Proto string `parquet:"proto,dict"`
		LPort int32  `parquet:"lport"`
		FD    int32  `parquet:"fd"`
	}
	dir := t.TempDir()
	old, out := filepath.Join(dir, "old.parquet"), filepath.Join(dir, "new.parquet")
	if err := writeFile(old, []oldKeyframeRow{{TS: 5, Proto: "tcp", LPort: 22, FD: 3}}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	w := parquet.NewGenericWriter[keyframeRow](f, writerOptions...)
	if err := copyRows(old, w, make([]keyframeRow, 16)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	rows, err := parquet.ReadFile[keyframeRow](out)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if r := rows[0]; r.TS != 5 || r.Proto != "tcp" || r.LPort != 22 || r.FD != 3 || r.V6Only != 0 {
		t.Errorf("got %+v", r)
	}
}
