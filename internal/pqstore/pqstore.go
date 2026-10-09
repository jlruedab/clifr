// Package pqstore is the recorder's Parquet backend. It writes the v1 tables
// (see internal/store) as append-only files:
//
//	<dir>/<table>/<YYYY-MM-DD>/<HH-MM>.parquet   rows flushed at that time (UTC)
//	<dir>/<table>/<YYYY-MM-DD>/<HH>.parquet      one hour, compacted
//	<dir>/<table>/open/<run>.parquet             entities still open at the last flush
//
// Entities (processes, sockets, socket owners, open files) are time ranges.
// A row is written once, when the entity closes. Entities still open are kept
// in memory and rewritten as a whole to the run's open file at every flush,
// with last_seen set to the last sample that saw them. Readers keep, for each
// id, the row with the largest last_seen (internal/duck), so a closed row
// replaces the open one, and after a crash the open file says how long each
// entity was seen. Ids are unique across runs: run start (Unix seconds) × 1e9
// plus a counter.
//
// Rows are buffered in memory and written every FlushInterval, so a crash
// loses at most that window. A low-priority goroutine compacts each finished
// hour into one file and enforces the retention and size limits.
package pqstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/parquet-go/parquet-go"
	"golang.org/x/sys/unix"

	"sosv/internal/store"
)

type Options struct {
	FlushInterval time.Duration // default 5 minutes
	Retention     time.Duration // 0 = keep everything
	MaxBytes      int64         // 0 = no size cap
	Logf          func(format string, args ...any)
}

// entity holds the open rows of one entity table and the closed rows not
// yet flushed.
type entity[T any] struct {
	open      map[int64]*T
	closed    []T
	closedIdx map[int64]int
}

func newEntity[T any]() *entity[T] {
	return &entity[T]{open: map[int64]*T{}, closedIdx: map[int64]int{}}
}

func (e *entity[T]) insert(id int64, row T, closed bool) {
	if closed {
		e.closedIdx[id] = len(e.closed)
		e.closed = append(e.closed, row)
	} else {
		e.open[id] = &row
	}
}

// get finds an open row, or a closed one still in the buffer.
func (e *entity[T]) get(id int64) *T {
	if r, ok := e.open[id]; ok {
		return r
	}
	if i, ok := e.closedIdx[id]; ok {
		return &e.closed[i]
	}
	return nil
}

// close moves an open row to the closed buffer after fn sets its end.
func (e *entity[T]) close(id int64, fn func(*T)) bool {
	if r, ok := e.open[id]; ok {
		fn(r)
		delete(e.open, id)
		e.insert(id, *r, true)
		return true
	}
	if r := e.get(id); r != nil {
		fn(r)
		return true
	}
	return false
}

func (e *entity[T]) reset() {
	e.closed = nil
	e.closedIdx = map[int64]int{}
}

// keyed is an append-only table where a second row for the same key in the
// same flush window replaces the first (v1: INSERT OR REPLACE).
type keyed[T any] struct {
	rows []T
	idx  map[[2]int64]int
}

func (k *keyed[T]) put(key [2]int64, row T) {
	if k.idx == nil {
		k.idx = map[[2]int64]int{}
	}
	if i, ok := k.idx[key]; ok {
		k.rows[i] = row
		return
	}
	k.idx[key] = len(k.rows)
	k.rows = append(k.rows, row)
}

func (k *keyed[T]) reset() { k.rows, k.idx = nil, nil }

type Store struct {
	dir string
	opt Options
	run int64 // Unix seconds at start; id base is run * 1e9

	samples     []sampleRow
	procs       *entity[processRow]
	procSamples keyed[procSampleRow]
	socks       *entity[socketRow]
	sockSamples keyed[sockSampleRow]
	owners      *entity[ownerRow]
	files       *entity[fileRow]
	conns       *entity[tcpConnRow]
	trans       []tcpTransRow
	keyframes   []keyframeRow
	reconcile   []reconcileRow
	guard       []guardRow
	oom         []oomRow
	stats       []statRow
	verify      []verifyRow
	meta        []metaRow
	verifyID    int64

	lastAny, lastFD int64 // last sample, last fd-walk sample (unix ms)
	lastFlush       time.Time
	unknown         int // updates/closes for ids this run does not hold

	bytes  atomic.Int64
	busy   atomic.Bool // maintenance running
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// Tables lists the table directories, in the order they are flushed.
var Tables = []string{"samples", "processes", "proc_samples", "sockets", "sock_samples", "sock_owners",
	"open_files", "tcp_conns", "tcp_transitions", "tcp_keyframes", "reconcile",
	"oom_events", "recorder_stats", "guard_events", "verify_snapshots", "meta"}

// EntityTables have an open/ directory and are deduplicated by id on read.
var EntityTables = []string{"processes", "sockets", "sock_owners", "open_files", "tcp_conns"}

func Open(dir string, opt Options) (*Store, error) {
	if opt.FlushInterval <= 0 {
		opt.FlushInterval = 5 * time.Minute
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, opt: opt, run: time.Now().Unix(), lastFlush: time.Now(),
		procs: newEntity[processRow](), socks: newEntity[socketRow](),
		owners: newEntity[ownerRow](), files: newEntity[fileRow](), conns: newEntity[tcpConnRow]()}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	if err := s.recover(); err != nil {
		return nil, err
	}
	s.bytes.Store(dirSize(dir))
	return s, nil
}

func (s *Store) idBase() int64 { return s.run * 1_000_000_000 }

func (s *Store) MaxID(string) (int64, error) { return s.idBase(), nil }

func (s *Store) Bytes() int64 { return s.bytes.Load() }

func (s *Store) SetMeta(key, value string) error {
	s.meta = append(s.meta, metaRow{Run: s.run, TS: time.Now().UnixMilli(), Key: key, Value: value})
	return nil
}

func (s *Store) Write(b *store.Batch) error {
	for _, ts := range b.Skips {
		s.samples = append(s.samples, sampleRow{TS: ts, Skipped: 1})
	}
	if b.Sample.TS != 0 {
		s.samples = append(s.samples, sampleOf(b.Sample))
		if !b.Sample.Skipped {
			s.lastAny = b.Sample.TS
			if b.Sample.FDWalk {
				s.lastFD = b.Sample.TS
			}
		}
	}
	for _, p := range b.ProcInserts {
		s.procs.insert(p.ID, processOf(p), p.LastSeen != nil)
	}
	for _, u := range b.ProcUpdates {
		if r := s.procs.get(u.ID); r != nil {
			r.UID, r.PPID, r.Comm, r.Cmdline, r.Source, r.Exe = int32(u.UID), int32(u.PPID), u.Comm, u.Cmdline, u.Source, u.Exe
			r.ExecTS = nil
			if u.ExecTS != 0 {
				r.ExecTS = ptr(u.ExecTS)
			}
		} else {
			s.unknown++
		}
	}
	for _, c := range b.ProcCloses {
		if !s.procs.close(c.ID, func(r *processRow) { r.LastSeen, r.Ended = ptr(c.LastSeen), c.Ended }) {
			s.unknown++
		}
	}
	for _, x := range b.ProcExits {
		r := s.procs.get(x.ID)
		if r == nil {
			s.unknown++
			continue
		}
		if x.ExitTS != nil {
			r.ExitTS = x.ExitTS
		}
		if x.ExitCode != nil {
			r.ExitCode = i32p(x.ExitCode)
		}
		if x.Signal != nil {
			r.Signal = i32p(x.Signal)
		}
		if x.OOMKilled {
			r.OOMKilled = 1
		}
	}
	for _, c := range b.TCPConns {
		// Whole rows: the newest version replaces the open or buffered one.
		row := tcpConnOf(c)
		if c.CloseTS == nil {
			s.conns.open[c.ID] = &row
		} else {
			delete(s.conns.open, c.ID)
			if i, ok := s.conns.closedIdx[c.ID]; ok {
				s.conns.closed[i] = row
			} else {
				s.conns.insert(c.ID, row, true)
			}
		}
	}
	for _, t := range b.TCPTrans {
		s.trans = append(s.trans, tcpTransRow{ConnID: t.ConnID, TS: t.TS, Seq: int32(t.Seq), Old: int32(t.Old), New: int32(t.New)})
	}
	for _, k := range b.Keyframes {
		s.keyframes = append(s.keyframes, keyframeOf(k))
	}
	for _, r := range b.Reconcile {
		s.reconcile = append(s.reconcile, reconcileRow{TS: r.TS, Kind: r.Kind, DumpRows: int32(r.DumpRows),
			Missing: int32(r.MissingFromEvents), Extra: int32(r.ExtraInEvents), Initial: b2i(r.Initial)})
	}
	for _, o := range b.OOMEvents {
		s.oom = append(s.oom, oomRow{TS: o.TS, PID: int32(o.PID), StartTime: o.StartTime, Comm: o.Comm, RSSKB: o.RSSKB, Snapshot: b2i(o.Snapshot)})
	}
	for _, r := range b.Stats {
		s.stats = append(s.stats, statRow{TS: r.TS, Source: r.Source, Events: r.Events, Dropped: r.Dropped})
	}
	for _, p := range b.ProcSamples {
		s.procSamples.put([2]int64{p.ProcID, p.TS}, procSampleOf(p))
	}
	for _, k := range b.SockInserts {
		s.socks.insert(k.ID, socketOf(k), false)
	}
	for _, c := range b.SockCloses {
		if !s.socks.close(c.ID, func(r *socketRow) { r.LastSeen = ptr(c.LastSeen) }) {
			s.unknown++
		}
	}
	for _, k := range b.SockSamples {
		s.sockSamples.put([2]int64{k.SockID, k.TS}, sockSampleRow{SockID: k.SockID, TS: k.TS, State: int32(k.State), RxQ: k.RxQ, TxQ: k.TxQ})
	}
	for _, o := range b.OwnInserts {
		s.owners.insert(o.ID, ownerRow{ID: o.ID, SockID: o.SockID, ProcID: o.ProcID, FD: int32(o.FD), FirstSeen: o.FirstSeen}, false)
	}
	for _, c := range b.OwnCloses {
		if !s.owners.close(c.ID, func(r *ownerRow) { r.LastSeen = ptr(c.LastSeen) }) {
			s.unknown++
		}
	}
	for _, f := range b.FileInserts {
		s.files.insert(f.ID, fileOf(f), false)
	}
	for _, c := range b.FileCloses {
		if !s.files.close(c.ID, func(r *fileRow) { r.LastSeen = ptr(c.LastSeen) }) {
			s.unknown++
		}
	}
	for _, g := range b.Guard {
		s.guard = append(s.guard, guardRow{TS: g.TS, Kind: g.Kind, Detail: g.Detail})
	}
	for _, v := range b.Verify {
		s.verifyID++
		s.verify = append(s.verify, verifyRow{ID: s.idBase() + s.verifyID, TS: v.TS, EndTS: v.EndTS, Cmd: v.Cmd,
			SampleTS: v.SampleTS, IgnorePIDs: v.IgnorePIDs, Output: v.Output})
	}
	if b.Sample.TS != 0 && time.Since(s.lastFlush) >= s.opt.FlushInterval {
		return s.Flush()
	}
	return nil
}

// Flush writes everything buffered and rewrites the open files.
func (s *Store) Flush() error {
	now := time.Now().UTC()
	day, name := now.Format("2006-01-02"), now.Format("15-04")
	var errs []error
	part := func(table string, n int, write func(path string) error) {
		if n == 0 {
			return
		}
		p, err := freePath(filepath.Join(s.dir, table, day), name)
		if err == nil {
			err = write(p)
		}
		errs = append(errs, err)
	}
	part("samples", len(s.samples), func(p string) error { return writeFile(p, s.samples) })
	part("processes", len(s.procs.closed), func(p string) error { return writeFile(p, s.procs.closed) })
	part("proc_samples", len(s.procSamples.rows), func(p string) error { return writeFile(p, s.procSamples.rows) })
	part("sockets", len(s.socks.closed), func(p string) error { return writeFile(p, s.socks.closed) })
	part("sock_samples", len(s.sockSamples.rows), func(p string) error { return writeFile(p, s.sockSamples.rows) })
	part("sock_owners", len(s.owners.closed), func(p string) error { return writeFile(p, s.owners.closed) })
	part("open_files", len(s.files.closed), func(p string) error { return writeFile(p, s.files.closed) })
	part("tcp_conns", len(s.conns.closed), func(p string) error { return writeFile(p, s.conns.closed) })
	part("tcp_transitions", len(s.trans), func(p string) error { return writeFile(p, s.trans) })
	part("tcp_keyframes", len(s.keyframes), func(p string) error { return writeFile(p, s.keyframes) })
	part("reconcile", len(s.reconcile), func(p string) error { return writeFile(p, s.reconcile) })
	part("oom_events", len(s.oom), func(p string) error { return writeFile(p, s.oom) })
	part("recorder_stats", len(s.stats), func(p string) error { return writeFile(p, s.stats) })
	part("guard_events", len(s.guard), func(p string) error { return writeFile(p, s.guard) })
	part("verify_snapshots", len(s.verify), func(p string) error { return writeFile(p, s.verify) })
	part("meta", len(s.meta), func(p string) error { return writeFile(p, s.meta) })
	if err := errors.Join(errs...); err != nil {
		return err // keep the buffers; the next flush retries
	}
	// Open rows, seen until the last sample (open files: the last fd walk).
	errs = append(errs,
		writeOpen(s, "processes", s.procs, s.lastAny, func(r *processRow) *int64 { return &r.FirstSeen }, func(r *processRow, v int64) { r.LastSeen = &v }),
		writeOpen(s, "sockets", s.socks, s.lastAny, func(r *socketRow) *int64 { return &r.FirstSeen }, func(r *socketRow, v int64) { r.LastSeen = &v }),
		writeOpen(s, "sock_owners", s.owners, s.lastAny, func(r *ownerRow) *int64 { return &r.FirstSeen }, func(r *ownerRow, v int64) { r.LastSeen = &v }),
		writeOpen(s, "open_files", s.files, s.lastFD, func(r *fileRow) *int64 { return &r.FirstSeen }, func(r *fileRow, v int64) { r.LastSeen = &v }),
		writeOpen(s, "tcp_conns", s.conns, s.lastAny, func(r *tcpConnRow) *int64 { return &r.OpenTS }, func(r *tcpConnRow, v int64) { r.LastSeen = &v }))
	s.samples, s.guard, s.verify, s.meta, s.oom, s.stats = nil, nil, nil, nil, nil, nil
	s.trans, s.keyframes, s.reconcile = nil, nil, nil
	s.conns.reset()
	s.procs.reset()
	s.socks.reset()
	s.owners.reset()
	s.files.reset()
	s.procSamples.reset()
	s.sockSamples.reset()
	s.lastFlush = time.Now()
	s.bytes.Store(dirSize(s.dir))
	if s.busy.CompareAndSwap(false, true) {
		s.wg.Add(1)
		go s.maintain()
	}
	return errors.Join(errs...)
}

// writeOpen rewrites the run's open file for an entity table.
func writeOpen[T any](s *Store, table string, e *entity[T], last int64, first func(*T) *int64, setLast func(*T, int64)) error {
	p := filepath.Join(s.dir, table, "open", fmt.Sprintf("%d.parquet", s.run))
	if len(e.open) == 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	rows := make([]T, 0, len(e.open))
	for _, r := range e.open {
		x := *r
		setLast(&x, max(last, *first(&x)))
		rows = append(rows, x)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	return writeFile(p, rows)
}

func (s *Store) Close() error {
	err := s.Flush()
	s.cancel()
	s.wg.Wait()
	if s.unknown > 0 {
		s.opt.Logf("pqstore: %d updates or closes referred to rows this run does not hold", s.unknown)
	}
	s.bytes.Store(dirSize(s.dir))
	return err
}

// writerOptions: zstd, and no long min/max bounds. parquet-go stores the
// bounds of a value in the page statistics, the column index and the footer,
// uncompressed: a 3 MB lsof output took 12.6 MB instead of 49 KB. Bounds are
// truncated to 16 bytes (and left out for long text columns), which keeps
// them useful for the numeric and short columns.
var writerOptions = []parquet.WriterOption{
	parquet.Compression(&parquet.Zstd),
	parquet.DataPageStatistics(false),
	parquet.ColumnIndexSizeLimit(func([]string) int { return 16 }),
	parquet.SkipPageBounds("output"), parquet.SkipPageBounds("cmdline"),
	parquet.SkipPageBounds("target"), parquet.SkipPageBounds("detail"),
}

// writeFile writes rows to path atomically (temporary file, fsync, rename).
func writeFile[T any](path string, rows []T) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := parquet.NewGenericWriter[T](f, writerOptions...)
	_, err = w.Write(rows)
	err = errors.Join(err, w.Close(), f.Sync(), f.Close())
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// freePath is dir/name.parquet, or dir/name-2.parquet, ... if taken.
func freePath(dir, name string) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	p := filepath.Join(dir, name+".parquet")
	for i := 2; ; i++ {
		if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
			return p, nil
		}
		p = filepath.Join(dir, fmt.Sprintf("%s-%d.parquet", name, i))
	}
}

func dirSize(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// ---- maintenance: compaction, retention, size cap ----

var (
	partRe = regexp.MustCompile(`^(\d\d)-\d\d(-\d+)?\.parquet$`) // HH-MM[-n].parquet
	hourRe = regexp.MustCompile(`^(\d\d)\.parquet$`)             // HH.parquet
)

// hourFile is one data file with the hour it belongs to.
type hourFile struct {
	path, table, day, hour string
	compacted              bool
}

func (h hourFile) start() time.Time {
	t, _ := time.Parse("2006-01-02 15", h.day+" "+h.hour)
	return t
}

// listHours lists the dated files of every table (not the open files).
func (s *Store) listHours() []hourFile {
	var out []hourFile
	for _, t := range Tables {
		days, _ := os.ReadDir(filepath.Join(s.dir, t))
		for _, d := range days {
			if !d.IsDir() || d.Name() == "open" {
				continue
			}
			files, _ := os.ReadDir(filepath.Join(s.dir, t, d.Name()))
			for _, f := range files {
				h := hourFile{path: filepath.Join(s.dir, t, d.Name(), f.Name()), table: t, day: d.Name()}
				if m := partRe.FindStringSubmatch(f.Name()); m != nil {
					h.hour = m[1]
				} else if m := hourRe.FindStringSubmatch(f.Name()); m != nil {
					h.hour, h.compacted = m[1], true
				} else {
					continue
				}
				out = append(out, h)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// recover removes temporary files and parts already merged into an hour
// file (a crash between the rename and the deletes).
func (s *Store) recover() error {
	filepath.WalkDir(s.dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".tmp") {
			os.Remove(p)
		}
		return nil
	})
	done := map[string]bool{}
	files := s.listHours()
	for _, h := range files {
		if h.compacted {
			done[h.table+"/"+h.day+"/"+h.hour] = true
		}
	}
	for _, h := range files {
		if !h.compacted && done[h.table+"/"+h.day+"/"+h.hour] {
			if err := os.Remove(h.path); err != nil {
				return err
			}
		}
	}
	return nil
}

// maintain runs at the lowest CPU and IO priority, on its own OS thread.
func (s *Store) maintain() {
	defer s.wg.Done()
	defer s.busy.Store(false)
	runtime.LockOSThread() // never unlocked: the thread exits with its lowered priority
	tid := unix.Gettid()
	unix.Setpriority(unix.PRIO_PROCESS, tid, 19)
	const ioprioClassIdle, ioprioWhoProcess = 3, 1
	unix.Syscall(unix.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprioClassIdle<<13)

	if err := s.compact(time.Now().UTC().Truncate(time.Hour)); err != nil {
		s.opt.Logf("pqstore: compaction: %v", err)
	}
	if err := s.expire(time.Now().UTC()); err != nil {
		s.opt.Logf("pqstore: retention: %v", err)
	}
	s.bytes.Store(dirSize(s.dir))
}

// compact merges the files of every hour that ended before current into
// <HH>.parquet (including an earlier hour file, if any).
func (s *Store) compact(current time.Time) error {
	groups := map[string][]hourFile{}
	var keys []string
	for _, h := range s.listHours() {
		if !h.start().Before(current) {
			continue
		}
		k := h.table + "/" + h.day + "/" + h.hour
		if groups[k] == nil {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], h)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := groups[k]
		if len(g) == 1 && g[0].compacted {
			continue
		}
		if s.ctx.Err() != nil {
			return nil
		}
		var paths []string
		for _, h := range g {
			paths = append(paths, h.path)
		}
		out := filepath.Join(s.dir, g[0].table, g[0].day, g[0].hour+".parquet")
		if err := compactors[g[0].table](paths, out); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		for _, h := range g {
			if h.path != out {
				os.Remove(h.path)
			}
		}
	}
	return nil
}

var compactors = map[string]func(parts []string, out string) error{
	"samples": merge[sampleRow], "processes": merge[processRow], "proc_samples": merge[procSampleRow],
	"sockets": merge[socketRow], "sock_samples": merge[sockSampleRow], "sock_owners": merge[ownerRow],
	"open_files": merge[fileRow], "oom_events": merge[oomRow], "recorder_stats": merge[statRow],
	"tcp_conns": merge[tcpConnRow], "tcp_transitions": merge[tcpTransRow], "tcp_keyframes": merge[keyframeRow],
	"reconcile":    merge[reconcileRow],
	"guard_events": merge[guardRow], "verify_snapshots": merge[verifyRow],
	"meta": merge[metaRow],
}

// merge streams the rows of parts into out (atomically replaced).
func merge[T any](parts []string, out string) error {
	tmp := out + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := parquet.NewGenericWriter[T](f, writerOptions...)
	buf := make([]T, 4096)
	for _, p := range parts {
		if err = copyRows(p, w, buf); err != nil {
			break
		}
	}
	err = errors.Join(err, w.Close(), f.Sync(), f.Close())
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, out)
}

func copyRows[T any](path string, w *parquet.GenericWriter[T], buf []T) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := parquet.NewGenericReader[T](f)
	defer r.Close()
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// expire deletes hours older than the retention, other runs' open files
// older than the retention, and then the oldest hours while the data exceeds
// the size cap (never the current hour).
func (s *Store) expire(now time.Time) error {
	var errs []error
	if r := s.opt.Retention; r > 0 {
		for _, h := range s.listHours() {
			if h.start().Add(time.Hour).Before(now.Add(-r)) {
				errs = append(errs, os.Remove(h.path))
			}
		}
		own := fmt.Sprintf("%d.parquet", s.run)
		for _, t := range EntityTables {
			files, _ := os.ReadDir(filepath.Join(s.dir, t, "open"))
			for _, f := range files {
				if fi, err := f.Info(); err == nil && f.Name() != own && fi.ModTime().Before(now.Add(-r)) {
					errs = append(errs, os.Remove(filepath.Join(s.dir, t, "open", f.Name())))
				}
			}
		}
	}
	if s.opt.MaxBytes > 0 {
		hours := s.listHours()
		sort.SliceStable(hours, func(i, j int) bool { return hours[i].start().Before(hours[j].start()) })
		size := dirSize(s.dir)
		current := now.Truncate(time.Hour)
		for i := 0; size > s.opt.MaxBytes && i < len(hours); {
			start := hours[i].start()
			if !start.Before(current) {
				s.opt.Logf("pqstore: %d bytes exceed the size cap %d; only the current hour is left", size, s.opt.MaxBytes)
				break
			}
			for ; i < len(hours) && hours[i].start().Equal(start); i++ {
				if fi, err := os.Stat(hours[i].path); err == nil {
					size -= fi.Size()
				}
				errs = append(errs, os.Remove(hours[i].path))
			}
		}
	}
	// Remove empty day directories.
	for _, t := range Tables {
		days, _ := os.ReadDir(filepath.Join(s.dir, t))
		for _, d := range days {
			if d.IsDir() && d.Name() != "open" {
				os.Remove(filepath.Join(s.dir, t, d.Name())) // fails unless empty
			}
		}
	}
	return errors.Join(errs...)
}

// WriteEmpty writes a Parquet file with the table's schema and no rows, so
// readers can load a table that has no data yet.
func WriteEmpty(table, path string) error {
	w, ok := emptyWriters[table]
	if !ok {
		return fmt.Errorf("unknown table %q", table)
	}
	return w(path)
}

var emptyWriters = map[string]func(string) error{
	"samples":          func(p string) error { return writeFile[sampleRow](p, nil) },
	"processes":        func(p string) error { return writeFile[processRow](p, nil) },
	"proc_samples":     func(p string) error { return writeFile[procSampleRow](p, nil) },
	"sockets":          func(p string) error { return writeFile[socketRow](p, nil) },
	"sock_samples":     func(p string) error { return writeFile[sockSampleRow](p, nil) },
	"sock_owners":      func(p string) error { return writeFile[ownerRow](p, nil) },
	"open_files":       func(p string) error { return writeFile[fileRow](p, nil) },
	"oom_events":       func(p string) error { return writeFile[oomRow](p, nil) },
	"tcp_conns":        func(p string) error { return writeFile[tcpConnRow](p, nil) },
	"tcp_transitions":  func(p string) error { return writeFile[tcpTransRow](p, nil) },
	"tcp_keyframes":    func(p string) error { return writeFile[keyframeRow](p, nil) },
	"reconcile":        func(p string) error { return writeFile[reconcileRow](p, nil) },
	"recorder_stats":   func(p string) error { return writeFile[statRow](p, nil) },
	"guard_events":     func(p string) error { return writeFile[guardRow](p, nil) },
	"verify_snapshots": func(p string) error { return writeFile[verifyRow](p, nil) },
	"meta":             func(p string) error { return writeFile[metaRow](p, nil) },
}
