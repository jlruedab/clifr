package duck

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"clifr/internal/bundle"
	"clifr/internal/pqstore"
	"clifr/internal/store"
)

// A process alive in a bundle's window that exits after it: its row is
// written after the window, so the bundle carries it in an after-window
// file. Read back through DuckDB, as clifr does, the process is there. From
// 2026-11-01 to 2026-11-07 that file went under the table's plain name
// beside its Dir directory and was never read: every entity that closed
// after the window was missing (ps, ss, lsof, systemd-cgls of a bundle).
func TestBundleAfterWindow(t *testing.T) {
	dir := t.TempDir()
	pq, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	to := now - 2*time.Hour.Milliseconds() // the window's end: before any file is named
	start := to - time.Hour.Milliseconds()
	exit := now - 1000
	if err := pq.Write(&store.Batch{Sample: store.Sample{TS: start},
		ProcInserts: []store.ProcRow{{ID: 101, PID: 4242, StartTime: start, PPID: 1, Comm: "late", Cmdline: "late -x",
			FirstSeen: start, Source: "sample"}}}); err != nil {
		t.Fatal(err)
	}
	if err := pq.Write(&store.Batch{Sample: store.Sample{TS: exit}, ProcExits: []store.ProcExit{{ID: 101, ExitTS: &exit}},
		ProcCloses: []store.Close{{ID: 101, LastSeen: exit}}}); err != nil {
		t.Fatal(err)
	}
	if err := pq.Close(); err != nil {
		t.Fatal(err)
	}
	// Files are named when written (now); put the samples in the window, as
	// a real recording has them, so the bundle is a data directory.
	dated, _ := pqstore.DataFiles(dir, "samples")
	in := time.UnixMilli(to - 300_000).UTC()
	for i, f := range dated {
		day := filepath.Join(dir, pqstore.Dir("samples"), in.Format("2006-01-02"))
		os.MkdirAll(day, 0o750)
		if err := os.Rename(f, filepath.Join(day, in.Format("15-04")+"-"+strconv.Itoa(i+2)+".parquet")); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	m, err := bundle.Write(bundle.Options{DataDir: dir, From: to - 600_000, To: to, Writer: "test", Now: time.Now()}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	after := ""
	for _, f := range m.Files {
		if bytes.HasSuffix([]byte(f.Path), []byte("after-window.parquet")) {
			after = f.Path
		}
	}
	if want := "data/" + pqstore.Dir("processes") + "/"; len(after) < len(want) || after[:len(want)] != want {
		t.Fatalf("after-window file %q, want it under %s", after, want)
	}
	out := t.TempDir()
	data, _, err := bundle.Extract(bytes.NewReader(buf.Bytes()), out, int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	dk, err := OpenWindow(data, Window{From: to, To: to})
	if err != nil {
		t.Fatal(err)
	}
	defer dk.Close()
	if _, err := dk.Prepare("processes"); err != nil {
		t.Fatal(err)
	}
	var n int
	var comm string
	if err := dk.DB.QueryRow(`SELECT count(*), any_value(comm) FROM processes WHERE id = 101`).Scan(&n, &comm); err != nil || n != 1 || comm != "late" {
		t.Errorf("the process alive at the window's end: %d rows (%q), %v", n, comm, err)
	}
}

// Bundles made from 2026-11-01 to 2026-11-07 have their after-window files
// under the plain table name: still read.
func TestOldAfterWindowDir(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{pqstore.Dir("samples") + "/2026-11-05/10.parquet", "processes/2026-11-05/after-window.parquet",
		pqstore.Dir("processes") + "/2026-11-05/10.parquet"} {
		os.MkdirAll(dir+"/"+p[:len(p)-len("/10.parquet")], 0o755)
	}
	os.MkdirAll(dir+"/processes/2026-11-05", 0o755)
	os.WriteFile(dir+"/processes/2026-11-05/after-window.parquet", nil, 0o644)
	os.WriteFile(dir+"/"+pqstore.Dir("processes")+"/2026-11-05/10.parquet", nil, 0o644)
	dated, _ := pqstore.DataFiles(dir, "processes")
	if len(dated) != 2 {
		t.Errorf("both directories: %v", dated)
	}
}
