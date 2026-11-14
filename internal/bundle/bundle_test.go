package bundle

import (
	"archive/tar"
	"bytes"
	"clifr/internal/pqstore"
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
		"meta/2026-10-19/23.parquet",
		"kmsg/2026-10-20/03.parquet",                                 // dmesg: the whole boot up to the window
		"units/2026-10-20/11.parquet", "units/2026-10-20/10.parquet", // the hourly snapshot before the window
		"addrs/2026-10-20/09.parquet") // more than an hour before: not needed
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
		"kmsg/2026-10-20/03.parquet",
		"units/2026-10-20/11.parquet", "units/2026-10-20/10.parquet",
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
	if len(sel.Copy) != 14 || len(sel.After) != 0 {
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

// TestSalvage: a bundle with a changed file or cut short is refused by
// Extract (naming --salvage); Salvage keeps the files whose checksums match
// and names the others.
func TestSalvage(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, "samples/2026-10-20/12.parquet", "tcp_conns/open/1.parquet")
	var buf bytes.Buffer
	if _, err := Write(Options{DataDir: dir, Writer: "test", Now: time.Unix(1792460000, 0)}, &buf); err != nil {
		t.Fatal(err)
	}
	full := buf.Bytes()
	i := -1 // its content: at a 512-byte block boundary (the names are in headers)
	for j := 0; j >= 0 && i < 0; {
		k := bytes.Index(full[j:], []byte("tcp_conns/open/1.parquet"))
		if k < 0 {
			break
		}
		if (j+k)%512 == 0 {
			i = j + k
		}
		j += k + 1
	}
	if i < 0 {
		t.Fatal("content not found")
	}
	changed := bytes.Clone(full)
	changed[i] = 'X'
	for _, c := range []struct {
		name string
		b    []byte
	}{{"changed", changed}} {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := Extract(bytes.NewReader(c.b), t.TempDir(), 0); err == nil || !strings.Contains(err.Error(), "--salvage") {
				t.Errorf("Extract: %v", err)
			}
			out := t.TempDir()
			data, m, bad, err := Salvage(bytes.NewReader(c.b), out, 0)
			if err != nil || m == nil {
				t.Fatalf("Salvage: %v", err)
			}
			if !slices.Equal(bad, []string{"data/tcp_conns/open/1.parquet"}) {
				t.Errorf("left out %v", bad)
			}
			if _, err := os.Stat(filepath.Join(data, "tcp_conns/open/1.parquet")); !os.IsNotExist(err) {
				t.Errorf("damaged file kept: %v", err)
			}
			if b, err := os.ReadFile(filepath.Join(data, "samples/2026-10-20/12.parquet")); err != nil || string(b) != "samples/2026-10-20/12.parquet" {
				t.Errorf("good file: %q %v", b, err)
			}
		})
	}
	// Cut short in a file: bundle.json (the last entry) is lost too. Extract
	// refuses it; Salvage keeps the whole Parquet files, unverified.
	parq := t.TempDir()
	good := filepath.Join(parq, "samples/2026-10-20/12.parquet")
	os.MkdirAll(filepath.Dir(good), 0o750)
	if err := pqstore.WriteEmpty("samples", good); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(parq, "samples/2026-10-20"), 0o750)
	pqstore.WriteEmpty("samples", filepath.Join(parq, "samples/2026-10-20/13.parquet"))
	buf.Reset()
	if _, err := Write(Options{DataDir: parq, Writer: "test", Now: time.Unix(1792460000, 0)}, &buf); err != nil {
		t.Fatal(err)
	}
	cut := buf.Bytes()
	h13 := bytes.Index(cut, []byte("2026-10-20/13.parquet"))
	cut = cut[:h13/512*512+512+100] // its header and 100 bytes of it
	if _, _, err := Extract(bytes.NewReader(cut), t.TempDir(), 0); err == nil || !strings.Contains(err.Error(), "--salvage") {
		t.Errorf("Extract of a cut bundle: %v", err)
	}
	// With the tar's real size as the limit, as clifr passes it: the cut
	// entry claims more than the tar holds.
	if _, _, _, err := Salvage(bytes.NewReader(cut), t.TempDir(), int64(len(cut))); err != nil {
		t.Errorf("Salvage with the size limit: %v", err)
	}
	data, m, bad, err := Salvage(bytes.NewReader(cut), t.TempDir(), 0)
	if err != nil || m != nil {
		t.Fatalf("Salvage of a cut bundle: %v, manifest %v", err, m)
	}
	if len(bad) != 1 || !strings.HasSuffix(bad[0], "2026-10-20/13.parquet") {
		t.Errorf("left out %v", bad)
	}
	if err := pqstore.CheckFile(filepath.Join(data, strings.TrimPrefix(strings.Replace(bad[0], "13.parquet", "12.parquet", 1), "data/"))); err != nil {
		t.Errorf("whole file: %v", err)
	}
}
