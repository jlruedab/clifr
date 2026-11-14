package bundle

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"clifr/internal/pqstore"
)

type nopCloser struct{ *bytes.Buffer }

func (nopCloser) Close() error { return nil }

// TestSplit: the parts are bundles of their own, at most the size asked
// (a bigger file alone), sharing one id, meta in part 1; together they hold
// every file of the whole once, each checked against its part's bundle.json.
func TestSplit(t *testing.T) {
	dir := t.TempDir()
	var names []string
	for i := range 6 {
		name := filepath.Join(pqstore.Dir("samples"), "2026-11-14", time.Date(2026, 11, 14, 1, i, 0, 0, time.UTC).Format("15-04")+".parquet")
		names = append(names, name)
		os.MkdirAll(filepath.Join(dir, filepath.Dir(name)), 0o750)
		os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte{byte(i)}, 300<<10), 0o640)
	}
	meta := filepath.Join(pqstore.Dir("meta"), "2026-11-14", "01-05.parquet")
	os.MkdirAll(filepath.Join(dir, filepath.Dir(meta)), 0o750)
	os.WriteFile(filepath.Join(dir, meta), []byte("meta"), 0o640)
	whole := filepath.Join(t.TempDir(), "whole.tar")
	f, _ := os.Create(whole)
	m, err := Write(Options{DataDir: dir, Writer: "test", Now: time.Unix(1792460000, 0)}, f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	var bufs []*bytes.Buffer
	ms, err := Split(whole, 700<<10, func(int) (io.WriteCloser, error) {
		b := &bytes.Buffer{}
		bufs = append(bufs, b)
		return nopCloser{b}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 3 {
		t.Fatalf("%d parts, want 3 (two 300 KiB files each)", len(ms))
	}
	out := t.TempDir()
	var got []string
	for i, b := range bufs {
		if b.Len() > 700<<10 {
			t.Errorf("part %d: %d bytes", i+1, b.Len())
		}
		_, pm, err := Extract(bytes.NewReader(b.Bytes()), out, int64(b.Len()))
		if err != nil {
			t.Fatalf("part %d: %v", i+1, err)
		}
		if pm.Part != i+1 || pm.Parts != 3 || pm.BundleID != ms[0].BundleID || pm.BundleID == "" {
			t.Errorf("part %d manifest: part %d of %d, id %q", i+1, pm.Part, pm.Parts, pm.BundleID)
		}
		for _, f := range pm.Files {
			got = append(got, f.Path)
		}
	}
	if !isMeta(ms[0].Files[0].Path) {
		t.Errorf("part 1 begins with %s, not meta", ms[0].Files[0].Path)
	}
	var want []string
	for _, f := range m.Files {
		want = append(want, f.Path)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("files of the parts:\n%v\nof the whole:\n%v", got, want)
	}
}
