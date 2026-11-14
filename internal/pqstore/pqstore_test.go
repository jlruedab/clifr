package pqstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/parquet-go/parquet-go"

	"clifr/internal/store"
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
	// Open moved the files of the old-style directory to Dir's.
	old := day
	day = filepath.Join(dir, Dir("guard_events"), "2026-10-09")
	if _, err := os.Stat(filepath.Join(dir, "guard_events")); !os.IsNotExist(err) {
		t.Errorf("old directory kept: %v", err)
	}
	// 11:30: hour 10 is finished, hour 11 is not.
	if err := s.compact(time.Date(2026, 10, 9, 11, 0, 0, 0, time.UTC), func() {}); err != nil {
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
	// Open removes the parts already merged. Written by an older clifrd (both
	// directories exist): moved file by file.
	writeFile(filepath.Join(old, "10-30.parquet"), guardRows(5, 0))
	os.WriteFile(filepath.Join(day, "11-05.parquet.tmp"), []byte("partial"), 0o644)
	if _, err := Open(dir, Options{}); err != nil {
		t.Fatal(err)
	}
	left, _ = filepath.Glob(filepath.Join(day, "*"))
	if len(left) != 2 {
		t.Errorf("files after recovery: %v", left)
	}
}

// TestFlushDuringExpire: the maintenance goroutine's expire removes empty
// day directories; a flush that has just created one for its first file of
// the day must still write it (it once failed with "open ….parquet.tmp: no
// such file or directory" when Close flushed while maintain ran, losing the
// table's rows of that flush).
func TestFlushDuringExpire(t *testing.T) {
	for i := range 200 {
		s, err := Open(t.TempDir(), Options{})
		if err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
					s.expire(time.Now().UTC())
				}
			}
		}()
		s.guard = guardRows(1, 0)
		err = s.Flush()
		close(stop)
		<-done
		s.Close()
		if err != nil {
			t.Fatalf("flush %d: %v", i, err)
		}
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
	samples := filepath.Join(dir, Dir("samples"))
	if _, err := os.Stat(filepath.Join(samples, "2026-10-06")); !os.IsNotExist(err) {
		t.Error("hour older than the retention was kept (or its empty day directory)")
	}
	one := dirSize(filepath.Join(samples, "2026-10-09"))
	s.opt.MaxBytes = one / 2 // room for one of the three files left
	if err := s.expire(now); err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(samples, "*", "*.parquet"))
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
	if err := copyRows(old, &groupWriter[keyframeRow]{w: w}, make([]keyframeRow, 16)); err != nil {
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

// Closed rows past several chunks: lookups by id, replacement in place and
// the written file keep every row in order.
func TestRowBufChunks(t *testing.T) {
	e := newEntity[guardRow]()
	n := 2*chunkRows + 10
	for i := range n {
		e.insert(int64(i), guardRow{TS: int64(i), Kind: "a"}, true)
	}
	e.insert(int64(n), guardRow{TS: int64(n)}, false)
	if !e.close(int64(n), func(r *guardRow) { r.Kind = "closed" }) {
		t.Fatal("close failed")
	}
	if r := e.get(int64(chunkRows + 1)); r == nil || r.TS != chunkRows+1 {
		t.Fatalf("get: %+v", r)
	}
	e.get(int64(chunkRows)).Kind = "b"
	path := filepath.Join(t.TempDir(), "x.parquet")
	if err := writeFile(path, e.closed.chunks...); err != nil {
		t.Fatal(err)
	}
	rows, err := parquet.ReadFile[guardRow](path)
	if err != nil || len(rows) != n+1 || e.closed.len() != n+1 {
		t.Fatalf("rows=%d len=%d err=%v", len(rows), e.closed.len(), err)
	}
	for i, r := range rows {
		want := "a"
		switch i {
		case chunkRows:
			want = "b"
		case n:
			want = "closed"
		}
		if r.TS != int64(i) || r.Kind != want {
			t.Fatalf("row %d: %+v, want ts %d kind %s", i, r, i, want)
		}
	}
}

// valBuf rows stay within the 128-byte allocation size class.
func TestValBufRowSize(t *testing.T) {
	if n := unsafe.Sizeof(heldRec{}); n > 128 {
		t.Errorf("heldRec is %d bytes", n)
	}
	if n := unsafe.Sizeof(store.TCPConn{}); n > 128 {
		t.Errorf("TCPConn is %d bytes", n)
	}
}

func TestFileSpan(t *testing.T) {
	ms := func(s string) int64 { tm, _ := time.Parse("2006-01-02 15:04", s); return tm.UnixMilli() }
	for _, c := range []struct {
		path   string
		flush  time.Duration
		lo, hi int64
		ok     bool
	}{
		{"x/2026-10-20/05-40.parquet", 5 * time.Minute, ms("2026-10-20 05:34"), ms("2026-10-20 05:42"), true},
		{"x/2026-10-20/05-40-2.parquet", 0, 0, ms("2026-10-20 05:42"), true},
		{"x/2026-10-20/05.parquet", 5 * time.Minute, ms("2026-10-20 04:54"), ms("2026-10-20 06:01"), true},
		{"x/open/1792451773.parquet", 0, 0, 0, false},
	} {
		lo, hi, ok := FileSpan(c.path, c.flush)
		if lo != c.lo || hi != c.hi || ok != c.ok {
			t.Errorf("%s: %d %d %v, want %d %d %v", c.path, lo, hi, ok, c.lo, c.hi, c.ok)
		}
	}
}

func TestStartedBy(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.parquet")
	f, err := os.Create(in)
	if err != nil {
		t.Fatal(err)
	}
	w := parquet.NewGenericWriter[tcpConnRow](f, writerOptions...)
	w.Write([]tcpConnRow{{ID: 1, OpenTS: 100}, {ID: 2, OpenTS: 200}, {ID: 3, OpenTS: 300}})
	w.Close()
	f.Close()
	out := filepath.Join(dir, "out.parquet")
	n, err := StartedBy("tcp_conns", []string{in}, out, 200)
	if err != nil || n != 2 {
		t.Fatalf("kept %d, %v", n, err)
	}
	if _, err := StartedBy("samples", []string{in}, out, 200); err == nil {
		t.Error("a table without entities was accepted")
	}
}

// A run writes its whole meta again hourly, so retention never leaves a
// running recorder without it.
func TestMetaRefresh(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	s.SetMeta("hostname", "old")
	s.SetMeta("hostname", "web1")
	s.SetMeta("os_id", "rhel")
	count := func() (n int64) {
		dated, open := DataFiles(dir, "meta")
		for _, f := range append(dated, open...) {
			n += rowsIn(t, f)
		}
		return n
	}
	// 3 rows set here and writes_stop, set by Open.
	if err := s.Flush(); err != nil || count() != 4 {
		t.Fatalf("first flush: %d rows, %v", count(), err)
	}
	s.Flush()
	if n := count(); n != 4 {
		t.Errorf("copied again within the hour: %d rows", n)
	}
	s.metaAt = time.Now().Add(-time.Hour)
	s.Flush()
	if n := count(); n != 7 { // the latest value of each key
		t.Errorf("after an hour: %d rows, want 7", n)
	}
	if m, _ := ReadMeta(dir); m["hostname"] != "web1" || m["os_id"] != "rhel" {
		t.Errorf("meta %v", m)
	}
}

// Table directories are opaque, distinct and the same on every host.
func TestDirNames(t *testing.T) {
	seen := map[string]string{}
	for _, tb := range Tables {
		d := Dir(tb)
		if len(d) != 8 || strings.Contains(d, tb) {
			t.Errorf("%s: %q", tb, d)
		}
		if o, dup := seen[d]; dup {
			t.Errorf("%s and %s share %s", o, tb, d)
		}
		seen[d] = tb
	}
	if Dir("samples") != "59d5714c" { // fixed: bundles move between hosts
		t.Errorf("samples: %s", Dir("samples"))
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "samples"), 0o750)
	if TableDir(dir, "samples") != filepath.Join(dir, "samples") || IsDataDir(dir) != nil {
		t.Error("an older recording is not read")
	}
}

// TestFlushBytes: rows whose command lines add up to FlushBytes are written
// at once, not at the next flush interval (any user can give every process
// 64 KiB of arguments; FlushRows counts rows alike).
func TestFlushBytes(t *testing.T) {
	s, err := Open(t.TempDir(), Options{FlushInterval: time.Hour, FlushBytes: 10_000})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ts := time.Now().UnixMilli()
	write := func(id int64) {
		last := ts
		p := store.ProcRow{ID: id, PID: int(id), StartTime: ts, FirstSeen: ts, LastSeen: &last, Comm: "x", Cmdline: strings.Repeat("a", 4000)}
		if err := s.Write(&store.Batch{Sample: store.Sample{TS: ts}, ProcInserts: []store.ProcRow{p}}); err != nil {
			t.Fatal(err)
		}
	}
	write(1)
	write(2)
	if s.textBytes != 8000 || s.procs.closed.len() != 2 {
		t.Fatalf("after 8,000 bytes: %d buffered bytes, %d rows; want both kept", s.textBytes, s.procs.closed.len())
	}
	write(3) // 12,000 bytes: flushed
	if s.textBytes != 0 || s.procs.closed.len() != 0 {
		t.Errorf("after 12,000 bytes: %d buffered bytes, %d rows; want a flush", s.textBytes, s.procs.closed.len())
	}
}

// TestMergeRowGroups: compaction ends a row group every rowGroupBytes, so
// an hour of large rows is not held in memory whole.
func TestMergeRowGroups(t *testing.T) {
	dir := t.TempDir()
	var parts []string
	for i := range 3 {
		var rows []processRow
		for j := range 5000 {
			rows = append(rows, processRow{ID: int64(i*5000 + j), Cmdline: fmt.Sprintf("%08d", j) + strings.Repeat("x", 4000)})
		}
		p := filepath.Join(dir, fmt.Sprintf("p%d.parquet", i))
		if err := writeFile(p, rows); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, p)
	}
	out := filepath.Join(dir, "out.parquet")
	if err := merge[processRow](parts, out); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, _ := f.Stat()
	pf, err := parquet.OpenFile(f, fi.Size())
	if err != nil {
		t.Fatal(err)
	}
	// 15,000 rows of about 4.4 KB: 66 MB, so at least 2 row groups of 32 MiB.
	if n := len(pf.RowGroups()); n < 2 || pf.NumRows() != 15000 {
		t.Errorf("%d row groups, %d rows; want >= 2, 15000", n, pf.NumRows())
	}
	if b := rowBytes(&processRow{Cmdline: "abc", Comm: "x"}); b < 4 {
		t.Errorf("rowBytes = %d", b)
	}
}

// TestCompactBusy: while Busy says so, compaction leaves the hour's parts
// for the next try.
func TestCompactBusy(t *testing.T) {
	dir := t.TempDir()
	busy := true
	s, err := Open(dir, Options{Busy: func() bool { return busy }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	day := filepath.Join(dir, Dir("guard_events"), "2026-10-09")
	for _, name := range []string{"10-00", "10-05"} {
		if err := writeFile(filepath.Join(day, name+".parquet"), guardRows(2, 0)); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Date(2026, 10, 9, 11, 0, 0, 0, time.UTC)
	if err := s.compact(at, func() {}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(day, "10.parquet")); !os.IsNotExist(err) {
		t.Fatalf("compacted while busy: %v", err)
	}
	busy = false
	if err := s.compact(at, func() {}); err != nil {
		t.Fatal(err)
	}
	if n := rowsIn(t, filepath.Join(day, "10.parquet")); n != 4 {
		t.Errorf("after busy: %d rows, want 4", n)
	}
}
