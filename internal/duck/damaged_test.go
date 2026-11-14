package duck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parquet-go/parquet-go"

	"clifr/internal/pqstore"
	"clifr/internal/store"
)

// TestDamagedFileSkipped: a file cut short or empty is left out with a
// warning naming it; the rest of the table still loads (DuckDB refused the
// whole query before).
func TestDamagedFileSkipped(t *testing.T) {
	dir := t.TempDir()
	pq, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	pq.SetMeta("interval_s", "30")
	for _, x := range batches() {
		if err := pq.Write(x); err != nil {
			t.Fatal(err)
		}
	}
	if err := pq.Close(); err != nil {
		t.Fatal(err)
	}
	good, _ := filepath.Glob(filepath.Join(dir, pqstore.Dir("proc_samples"), "*", "*.parquet"))
	if len(good) == 0 {
		t.Fatal("no proc_samples file")
	}
	day := filepath.Dir(good[0])
	b, _ := os.ReadFile(good[0])
	os.WriteFile(filepath.Join(day, "23-55.parquet"), b[:len(b)/2], 0o640) // cut short
	os.WriteFile(filepath.Join(day, "23-56.parquet"), nil, 0o640)          // empty

	var warnings []string
	defer func(w func(string)) { warn = w }(warn)
	warn = func(s string) { warnings = append(warnings, s) }

	dk, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer dk.Close()
	q, err := dk.Prepare(`SELECT count(*) FROM proc_samples`)
	if err != nil {
		t.Fatalf("query refused: %v", err)
	}
	var n int
	if err := dk.QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if want := rowsOf(t, good); n != want {
		t.Errorf("%d rows, want %d (the good files')", n, want)
	}
	if len(warnings) != 2 || !strings.Contains(warnings[0], "23-55.parquet") || !strings.Contains(warnings[1], "23-56.parquet") ||
		!strings.Contains(warnings[0], "results lack its rows, from about") {
		t.Errorf("warnings: %q", warnings)
	}
	// Each damaged file is reported once.
	dk.Prepare(`SELECT count(*) FROM proc_samples, processes`)
	if len(warnings) != 2 {
		t.Errorf("warned again: %q", warnings)
	}
}

func rowsOf(t *testing.T, files []string) int {
	t.Helper()
	n := 0
	for _, f := range files {
		if err := pqstore.CheckFile(f); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		n += countRows(t, f)
	}
	return n
}

func countRows(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	pf, err := parquet.OpenFile(f, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	return int(pf.NumRows())
}

// TestDamagedPageSkipped: a byte changed inside a compressed data page (the
// zstd frame checksum no longer matches) makes DuckDB fail on the file; the
// loader leaves it out with a warning and loads the rest. probe finds such
// a file when DuckDB's error names none.
func TestDamagedPageSkipped(t *testing.T) {
	dir := t.TempDir()
	pq, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		b := &store.Batch{Sample: store.Sample{TS: int64(1000 + i)}}
		for j := range 5000 {
			b.Guard = append(b.Guard, store.GuardEvent{TS: int64(i*10000 + j), Kind: "skip", Detail: fmt.Sprintf("detail %d %d", i, j*7919%104729)})
		}
		pq.Write(b)
		if err := pq.Flush(); err != nil { // two parts (NAME and NAME-2)
			t.Fatal(err)
		}
	}
	pq.Close()
	files, _ := filepath.Glob(filepath.Join(dir, pqstore.Dir("guard_events"), "*", "*.parquet"))
	if len(files) < 1 {
		t.Fatal("no guard_events file")
	}
	bad := files[0]
	b, _ := os.ReadFile(bad)
	b[len(b)/4] ^= 0x10 // inside the data pages, far from the footer
	os.WriteFile(bad, b, 0o640)
	if pqstore.CheckFile(bad) != nil {
		t.Fatal("the damage should pass the cheap check")
	}

	var warnings []string
	defer func(w func(string)) { warn = w }(warn)
	warn = func(s string) { warnings = append(warnings, s) }
	dk, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer dk.Close()
	q, err := dk.Prepare(`SELECT count(*) FROM guard_events`)
	if err != nil {
		t.Fatalf("query refused: %v", err)
	}
	var n int
	dk.QueryRow(q).Scan(&n)
	if want := 5000 * (len(files) - 1); n != want {
		t.Errorf("%d rows, want %d", n, want)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], filepath.Base(bad)) {
		t.Errorf("warnings %q", warnings)
	}
}
