package duck

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"clifr/internal/pqstore"
)

// TestFileMergedWhileLoading: clifrd's compaction merges an hour's flush
// files into one and deletes them between clifr listing a table and DuckDB
// reading it (2026-11-15, the soak's VMs: clifr verify at 05:00 UTC failed
// with "Cannot open file .../04-03.parquet"). The table is listed and
// loaded again, from the merged file: no error, no row lost, no warning
// (the file was not damaged).
func TestFileMergedWhileLoading(t *testing.T) {
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
	count := func(dir string) int {
		dk, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer dk.Close()
		q, err := dk.Prepare(`SELECT count(*) FROM proc_samples`)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		var n int
		if err := dk.QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	want := count(dir)
	if want == 0 {
		t.Fatal("no proc_samples rows")
	}

	var warnings []string
	defer func(w func(string)) { warn = w }(warn)
	warn = func(s string) { warnings = append(warnings, s) }
	merged := 0
	defer func() { beforeExec = nil }()
	beforeExec = func(table string, files []string) {
		if table != "proc_samples" || merged > 0 {
			return
		}
		for _, f := range files {
			if filepath.Base(filepath.Dir(f)) == "open" {
				continue
			}
			// The merged hour file appears, then the part goes.
			if err := os.Rename(f, filepath.Join(filepath.Dir(f), "merged-"+filepath.Base(f))); err != nil {
				t.Fatal(err)
			}
			merged++
			return
		}
	}
	if got := count(dir); got != want {
		t.Errorf("%d rows after the merge, want %d", got, want)
	}
	if merged != 1 {
		t.Fatalf("%d files merged, want 1 (no closed proc_samples file?)", merged)
	}
	if len(warnings) > 0 {
		t.Errorf("warned about a file that was only merged: %q", warnings)
	}
}
