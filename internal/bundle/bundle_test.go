package bundle

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func touch(t *testing.T, dir string, files ...string) {
	t.Helper()
	for _, f := range files {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func ms(s string) int64 {
	tm, err := time.Parse("2006-01-02 15:04", s)
	if err != nil {
		panic(err)
	}
	return tm.UnixMilli()
}

func TestSelect(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir,
		"samples/2026-10-20/10.parquet", "samples/2026-10-20/11.parquet", "samples/2026-10-20/12.parquet",
		"samples/2026-10-20/13-10.parquet",
		"proc_samples/2026-10-20/03.parquet", "proc_samples/2026-10-20/14.parquet",
		"processes/2026-10-20/12.parquet", "processes/2026-10-20/15.parquet", "processes/open/1.parquet",
		"meta/2026-10-19/23.parquet")
	o := Options{DataDir: dir, From: ms("2026-10-20 12:00"), To: ms("2026-10-20 13:00")}
	sel, err := Select(o, map[string]string{"flush_interval_s": "300", "keyframe_interval_s": "300"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"samples/2026-10-20/11.parquet", "samples/2026-10-20/12.parquet", // 11: the lead-in (20 min)
		"processes/2026-10-20/12.parquet", "processes/open/1.parquet",
		"proc_samples/2026-10-20/03.parquet", // written on change: any time before
		"meta/2026-10-19/23.parquet",
	}
	slices.Sort(want)
	got := slices.Sorted(slices.Values(sel.Copy))
	if !slices.Equal(got, want) {
		t.Errorf("copy:\n got %v\nwant %v", got, want)
	}
	if a := sel.After["processes"]; len(a) != 1 || !strings.HasSuffix(a[0], "processes/2026-10-20/15.parquet") {
		t.Errorf("after: %v", sel.After)
	}
	// No window: everything, copied.
	sel, _ = Select(Options{DataDir: dir}, nil)
	if len(sel.Copy) != 10 || len(sel.After) != 0 {
		t.Errorf("whole recording: %d files, after %v", len(sel.Copy), sel.After)
	}
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, "samples/2026-10-20/12.parquet", "tcp_conns/open/1.parquet")
	var buf bytes.Buffer
	m, err := Write(Options{DataDir: dir, Writer: "test", Now: time.Unix(1792460000, 0)}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 2 || m.BundleVersion != Version {
		t.Fatalf("manifest %+v", m)
	}
	out := t.TempDir()
	data, m2, err := Extract(bytes.NewReader(buf.Bytes()), out, int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(data, "tcp_conns/open/1.parquet"))
	if err != nil || string(b) != "tcp_conns/open/1.parquet" || m2.Writer != "test" {
		t.Errorf("extracted %q, %v, %+v", b, err, m2)
	}
	// A damaged file is refused.
	bad := bytes.Clone(buf.Bytes())
	i := bytes.LastIndex(bad, []byte("tcp_conns/open/1.parquet"))
	bad[i] = 'X' // the content, not a header name (the last occurrence)
	if _, _, err := Extract(bytes.NewReader(bad), t.TempDir(), 0); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("damaged bundle: %v", err)
	}
}

func TestExtractRefusesEscape(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: Root + "/../evil", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	tw.Write([]byte("x"))
	tw.Close()
	if _, _, err := Extract(&buf, t.TempDir(), 0); err == nil {
		t.Error("a path outside the bundle was accepted")
	}
}

func TestNotADataDir(t *testing.T) {
	if _, err := Write(Options{DataDir: t.TempDir()}, &bytes.Buffer{}); err == nil {
		t.Error("an empty directory was bundled")
	}
}

func TestExtractLimit(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: Root + "/data/samples/x.parquet", Mode: 0o640, Size: 10, Typeflag: tar.TypeReg})
	tw.Write([]byte("0123456789"))
	tw.Close()
	dir := t.TempDir()
	if _, _, err := Extract(bytes.NewReader(buf.Bytes()), dir, 5); err == nil || !strings.Contains(err.Error(), "more data") {
		t.Fatalf("10 bytes with a limit of 5: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "samples", "x.parquet")); err == nil {
		t.Error("the file was written")
	}
}
