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
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/parquet-go/parquet-go"
	"golang.org/x/sys/unix"

	"clifr/internal/store"
)

type Options struct {
	FlushInterval time.Duration // default 5 minutes
	FlushRows     int           // also flush once this many rows are buffered (0: only by time)
	// FlushBytes: also flush once the command lines and paths of the rows
	// buffered since the last flush add up to this many bytes (0: not by
	// size). Rows count alike, but any user can give every process 64 KiB
	// of arguments.
	FlushBytes int64
	// Busy, if set, is asked before each table-hour of compaction: while it
	// says so, compaction stops and is tried again at the next flush (it
	// needs memory, and an hour of a flood is the largest to compact).
	Busy func() bool
	// EarlyFlush: after an OOM kill, a kernel message that may come before a
	// crash (earlyKernel) or RequestFlush, flush at the next sample once the
	// last flush is this old, instead of waiting for FlushInterval: what
	// came just before a crash is what is wanted most. 0 = never early.
	EarlyFlush time.Duration
	Retention  time.Duration // 0 = keep everything
	MaxBytes   int64         // 0 = no size cap
	Logf       func(format string, args ...any)
}

// entity holds the open rows of one entity table and the closed rows not
// yet flushed.
type entity[T any] struct {
	open      map[int64]*T
	closed    rowBuf[T]
	closedIdx map[int64]int
	scratch   []T // writeOpen's rows, reused at every flush
}

// chunkRows is the size of a rowBuf chunk.
const chunkRows = 4096

// rowBuf is an append-only row buffer in chunks of chunkRows (the first one
// grows like a slice up to that size). Unlike one slice, it never copies the
// rows it holds when it grows: at the busy load, regrowing the closed
// connections' buffer was about an eighth of everything the recorder
// allocated, and so of its garbage collection.
type rowBuf[T any] struct {
	chunks [][]T
	n      int
}

func (b *rowBuf[T]) add(row T) {
	if len(b.chunks) == 0 || len(b.chunks[len(b.chunks)-1]) == chunkRows {
		var c []T
		if len(b.chunks) > 0 {
			c = make([]T, 0, chunkRows)
		}
		b.chunks = append(b.chunks, c)
	}
	c := &b.chunks[len(b.chunks)-1]
	*c = append(*c, row)
	b.n++
}

func (b *rowBuf[T]) at(i int) *T { return &b.chunks[i/chunkRows][i%chunkRows] }
func (b *rowBuf[T]) len() int    { return b.n }

func newEntity[T any]() *entity[T] {
	return &entity[T]{open: map[int64]*T{}, closedIdx: map[int64]int{}}
}

func (e *entity[T]) insert(id int64, row T, closed bool) {
	if closed {
		e.closedIdx[id] = e.closed.len()
		e.closed.add(row)
	} else {
		p := new(T) // not &row: that would move every row to the heap
		*p = row
		e.open[id] = p
	}
}

// get finds an open row, or a closed one still in the buffer.
func (e *entity[T]) get(id int64) *T {
	if r, ok := e.open[id]; ok {
		return r
	}
	if i, ok := e.closedIdx[id]; ok {
		return e.closed.at(i)
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
	e.closed = rowBuf[T]{}
	clear(e.closedIdx) // keeps its size for the next window
}

// valBuf holds an entity table the recorder keeps by the ten thousand (TCP
// connections, held fds): like entity, but rows are kept in a compact form
// (no pointers for TCP connections, none per time for held fds) and
// converted to file rows a chunk at a time when written. Open rows are
// separate objects: a map with the rows inline was larger, as the table
// grows in powers of two and stays partly empty.
type valBuf[S any] struct {
	open      map[int64]*S
	closed    rowBuf[S]
	closedIdx map[int64]int
}

func newValBuf[S any]() valBuf[S] {
	return valBuf[S]{open: map[int64]*S{}, closedIdx: map[int64]int{}}
}

func (e *valBuf[S]) addClosed(id int64, row S) {
	e.closedIdx[id] = e.closed.len()
	e.closed.add(row)
}

func (e *valBuf[S]) reset() {
	e.closed = rowBuf[S]{}
	clear(e.closedIdx)
}

// heldRec is a held fd in memory: the recorder's row and its end.
type heldRec struct {
	store.HeldFD
	LastSeen int64 // 0 while open
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
	conns       valBuf[store.TCPConn]
	held        valBuf[heldRec]
	mounts      []mountRow
	sys         []sysRow
	cpus        []cpuRow
	disks       []diskRow
	netCounters []netCounterRow
	links       []linkRow
	ifAddrs     []addrRow
	routing     []routingRow
	kmsg        []kmsgRow
	units       []unitRow
	cgroups     []cgroupRow
	snapshots   []snapshotRow
	blockDevs   []blockDevRow
	neighs      []neighRow
	fs          []fsRow
	trans       []tcpTransRow
	keyframes   rowBuf[store.KeyframeRow]
	addrs       addrCache
	reconcile   []reconcileRow
	guard       []guardRow
	oom         []oomRow
	stats       []statRow
	verify      []verifyRow
	meta        []metaRow
	metaAll     map[string]string // the run's meta, written again hourly
	metaAt      time.Time         // its last full copy
	verifyID    int64

	lastAny, lastFD int64 // last sample, last fd-walk sample (unix ms)
	lastFlush       time.Time
	early           string                 // why the next sample flushes early ("": no reason)
	requested       atomic.Pointer[string] // RequestFlush's reason, from any goroutine
	openMonoUS      int64                  // CLOCK_MONOTONIC at Open: older kernel messages are a replay
	prev            PrevRun                // the run before this one (PrevRun)
	noSpaceUntil    time.Time              // the disk was full: next flush try (diskfull.go)
	diskFull        bool                   // the last flush failed for space
	ilog            *integrityLog          // checksums of the files written (integrity.go)
	textBytes       int64                  // command lines and paths written since the last flush (FlushBytes)
	unknown         int                    // updates/closes for ids this run does not hold

	bytes atomic.Int64
	busy  atomic.Bool // maintenance running
	// dirs is held while Flush writes and while expire removes empty day
	// directories: a flush creates a day directory before its first file
	// there, and expire would remove it in between.
	dirs sync.Mutex
	// maintUS is the CPU the maintenance thread used so far (µs), updated
	// after each table it compacts.
	maintUS atomic.Int64
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

// Tables lists the table directories, in the order they are flushed.
var Tables = []string{"samples", "processes", "proc_samples", "sockets", "sock_samples", "sock_owners",
	"open_files", "fds_held", "mounts", "tcp_conns", "tcp_transitions", "tcp_keyframes", "reconcile",
	"oom_events", "recorder_stats", "guard_events", "verify_snapshots", "sys_samples", "cpu_samples", "disk_samples", "fs_samples", "net_counters", "links", "addrs", "routing", "kmsg", "units", "cgroups", "snapshots", "blockdevs", "neighs", "meta"}

// EntityTables have an open/ directory and are deduplicated by id on read.
var EntityTables = []string{"processes", "sockets", "sock_owners", "open_files", "fds_held", "tcp_conns"}

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
	s := &Store{dir: dir, opt: opt, run: time.Now().Unix(), lastFlush: time.Now(), metaAll: map[string]string{}, metaAt: time.Now(),
		procs: newEntity[processRow](), socks: newEntity[socketRow](),
		owners: newEntity[ownerRow](), files: newEntity[fileRow](), held: newValBuf[heldRec](), conns: newValBuf[store.TCPConn]()}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) == nil {
		s.openMonoUS = ts.Nano() / 1000
	}
	if err := renameDirs(dir, opt.Logf); err != nil {
		return nil, fmt.Errorf("rename table directories: %w", err)
	}
	s.ilog = newIntegrityLog(dir, opt.Logf)
	s.ilog.sealOpen(s.run)
	s.ilog.sealLate() // before recover: what it logs is this run's
	if err := s.recover(); err != nil {
		return nil, err
	}
	s.prev = readPrevRun(dir, s.run)
	s.SetMeta(MetaWritesStop, "1")
	s.bytes.Store(dirSize(dir))
	return s, nil
}

func (s *Store) idBase() int64 { return s.run * 1_000_000_000 }

func (s *Store) MaxID(string) (int64, error) { return s.idBase(), nil }

func (s *Store) Bytes() int64 { return s.bytes.Load() }

// MaintenanceCPUUS is the CPU time compaction and retention used so far
// (µs, their own low-priority thread): the recorder's CPU guard rail leaves
// it out, as it runs only on idle CPU and does not depend on sampling.
func (s *Store) MaintenanceCPUUS() int64 { return s.maintUS.Load() }

func (s *Store) SetMeta(key, value string) error {
	s.meta = append(s.meta, metaRow{Run: s.run, TS: time.Now().UnixMilli(), Key: key, Value: value})
	s.metaAll[key] = value
	return nil
}

// refreshMeta copies the run's whole meta into the first flush of each UTC
// hour (store.OtherHour). Retention deletes hours, and meta is
// written at the start: without the copies a run that outlives the
// retention loses its host, schema and distribution.
func (s *Store) refreshMeta(now time.Time) {
	if !store.OtherHour(s.metaAt.UnixMilli(), now.UnixMilli()) {
		return
	}
	for _, k := range slices.Sorted(maps.Keys(s.metaAll)) {
		s.meta = append(s.meta, metaRow{Run: s.run, TS: now.UnixMilli(), Key: k, Value: s.metaAll[k]})
	}
	s.metaAt = now
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
		s.textBytes += int64(len(p.Cmdline) + len(p.Exe) + len(p.Cgroup) + len(p.Label))
	}
	for _, u := range b.ProcUpdates {
		s.textBytes += int64(len(u.Cmdline) + len(u.Exe) + len(u.Cgroup) + len(u.Label))
		if r := s.procs.get(u.ID); r != nil {
			r.UID, r.PPID, r.Comm, r.Cmdline, r.Source, r.Exe = int32(u.UID), int32(u.PPID), u.Comm, u.Cmdline, u.Source, u.Exe
			r.Argv0Len = int32(u.Argv0Len)
			r.ExecTS = u.ExecTS
			r.Label, r.Cgroup, r.RUID, r.NetNS = u.Label, u.Cgroup, int32(u.RUID), int64(u.NetNS)
			if u.CmdlinePad != 0 {
				r.CmdlinePad = int32(u.CmdlinePad)
			}
		} else {
			s.unknown++
		}
	}
	for _, c := range b.ProcCloses {
		if !s.procs.close(c.ID, func(r *processRow) { r.LastSeen, r.Ended = c.LastSeen, val(c.Ended) }) {
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
			r.ExitTS = *x.ExitTS
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
	for _, f := range b.HeldInserts {
		s.textBytes += int64(len(f.Target) + len(f.Name))
		s.held.open[f.ID] = &heldRec{HeldFD: f}
	}
	for _, c := range b.HeldCloses {
		if r := s.held.open[c.ID]; r != nil {
			r.LastSeen = c.LastSeen
			delete(s.held.open, c.ID)
			s.held.addClosed(c.ID, *r)
		} else if i, ok := s.held.closedIdx[c.ID]; ok {
			s.held.closed.at(i).LastSeen = c.LastSeen
		} else {
			s.unknown++
		}
	}
	for _, m := range b.Mounts {
		s.mounts = append(s.mounts, mountRow{TS: m.TS, Action: m.Action, MountID: int32(m.MountID), Point: m.Point,
			Source: m.Source, FSType: m.FSType, Options: m.Options, SuperOptions: m.SuperOptions, Dev: m.Dev, Root: m.Root,
			Seq: int32(m.Seq), LoopFile: m.LoopFile, UserOptions: m.UserOptions})
	}
	for _, f := range b.FSSamples {
		s.fs = append(s.fs, fsRow{TS: f.TS, MountID: int32(f.MountID), FrSize: f.FrSize, Blocks: f.Blocks,
			BFree: f.BFree, BAvail: f.BAvail, Files: f.Files, FFree: f.FFree})
	}
	for i := range b.Sys {
		s.sys = append(s.sys, sysOf(&b.Sys[i]))
	}
	for _, c := range b.CPUs {
		s.cpus = append(s.cpus, cpuOf(c))
	}
	for _, d := range b.Disks {
		s.disks = append(s.disks, diskOf(d))
	}
	for _, n := range b.Snapshots {
		s.snapshots = append(s.snapshots, snapshotRow{TS: n.TS, Source: n.Source, Key: n.Key, Pos: int32(n.Pos), Full: b2i(n.Full), Line: n.Line})
	}
	for _, d := range b.BlockDevs {
		s.blockDevs = append(s.blockDevs, blockDevRow{TS: d.TS, Name: d.Name, Parent: d.Parent, Gone: b2i(d.Gone),
			Hidden: b2i(d.Hidden), Maj: int32(d.Maj), Min: int32(d.Min), Size: d.Size, RO: int32(d.RO), RM: int32(d.RM),
			SCSIType: int32(d.SCSIType), DMName: d.DMName, DMUUID: d.DMUUID, MDLevel: d.MDLevel, LoopFile: d.LoopFile,
			Holders: d.Holders, Slaves: d.Slaves, FSType: d.FSType, FSVer: d.FSVer, Label: d.Label, UUID: d.UUID})
	}
	for _, n := range b.Neighs {
		s.neighs = append(s.neighs, neighRow{TS: n.TS, Pos: int32(n.Pos), Whole: b2i(n.Whole), Family: int32(n.Family),
			Index: int32(n.Index), State: int32(n.State), Flags: int32(n.Flags), Type: int32(n.Type), ExtFlags: n.ExtFlags,
			Dst: n.Dst, LLAddr: n.LLAddr, HasLLAddr: b2i(n.HasLLAddr), Probes: n.Probes, Protocol: n.Protocol,
			ConfirmedMS: n.ConfirmedMS, UsedMS: n.UsedMS, UpdatedMS: n.UpdatedMS, RefCnt: n.RefCnt})
	}
	for _, c := range b.Cgroups {
		s.cgroups = append(s.cgroups, cgroupRow{TS: c.TS, Path: c.Path, Delegate: b2i(c.Delegate), ID: c.ID, Xattrs: c.Xattrs})
	}
	for _, u := range b.Units {
		s.units = append(s.units, unitRow{TS: u.TS, Action: u.Action, Seq: int32(u.Seq), Name: u.Name,
			Description: u.Description, Load: u.Load, Active: u.Active, Sub: u.Sub, Following: u.Following,
			JobID: u.JobID, JobType: u.JobType})
	}
	for _, k := range b.Kmsg {
		s.kmsg = append(s.kmsg, kmsgRow{TS: k.TS, BootID: k.BootID, Kind: k.Kind, Seq: k.Seq, Prio: int32(k.Prio),
			MonoUS: k.MonoUS, Caller: k.Caller, Msg: k.Msg, BootUS: k.BootUS, SuspUS: k.SuspUS})
	}
	for _, r := range b.Routing {
		s.routing = append(s.routing, routingRow{TS: r.TS, Kind: r.Kind, Action: r.Action, Key: r.Key, Seq: int32(r.Seq),
			Family: int32(r.Family), Msg: r.Msg})
	}
	for i := range b.Addrs {
		s.ifAddrs = append(s.ifAddrs, addrOf(&b.Addrs[i]))
	}
	for i := range b.Links {
		s.links = append(s.links, linkOf(&b.Links[i]))
	}
	for _, n := range b.NetCounters {
		s.netCounters = append(s.netCounters, netCounterRow{TS: n.TS, Pos: int32(n.Pos), Section: n.Section, Name: n.Name, Value: n.Value})
	}
	for i := range b.TCPConns {
		// Whole rows: the newest version replaces the open or buffered one.
		c := &b.TCPConns[i]
		if c.CloseTS == 0 {
			if p := s.conns.open[c.ID]; p != nil {
				*p = *c
			} else {
				p = new(store.TCPConn)
				*p = *c
				s.conns.open[c.ID] = p
			}
		} else {
			delete(s.conns.open, c.ID)
			if i, ok := s.conns.closedIdx[c.ID]; ok {
				*s.conns.closed.at(i) = *c
			} else {
				s.conns.addClosed(c.ID, *c)
			}
		}
	}
	for _, t := range b.TCPTrans {
		s.trans = append(s.trans, tcpTransRow{ConnID: t.ConnID, TS: t.TS, Seq: int32(t.Seq), Old: int32(t.Old), New: int32(t.New)})
	}
	for _, k := range b.Keyframes {
		s.keyframes.add(k)
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
		if !s.socks.close(c.ID, func(r *socketRow) { r.LastSeen = c.LastSeen }) {
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
		if !s.owners.close(c.ID, func(r *ownerRow) { r.LastSeen = c.LastSeen }) {
			s.unknown++
		}
	}
	for _, f := range b.FileInserts {
		s.files.insert(f.ID, fileOf(f), false)
	}
	for _, c := range b.FileCloses {
		if !s.files.close(c.ID, func(r *fileRow) { r.LastSeen = c.LastSeen }) {
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
	if s.early == "" {
		s.early = s.earlyReason(b)
	}
	if r := s.requested.Swap(nil); r != nil && s.early == "" {
		s.early = *r
	}
	if time.Now().Before(s.noSpaceUntil) {
		return nil // the disk was full: no flush before the next try (Flush)
	}
	if b.Sample.TS != 0 && s.early != "" && s.opt.EarlyFlush > 0 && time.Since(s.lastFlush) >= s.opt.EarlyFlush {
		s.opt.Logf("pqstore: early flush: %s", s.early)
		return s.Flush()
	}
	if b.Sample.TS != 0 && (time.Since(s.lastFlush) >= s.opt.FlushInterval || s.opt.FlushRows > 0 && s.buffered() >= s.opt.FlushRows ||
		s.opt.FlushBytes > 0 && s.textBytes >= s.opt.FlushBytes) {
		return s.Flush()
	}
	return nil
}

// buffered counts the rows waiting for the next flush in the tables that
// grow with the load: they are what the store's memory consists of.
func (s *Store) buffered() int {
	return len(s.trans) + s.conns.closed.len() + s.keyframes.len() + s.procs.closed.len() + len(s.procSamples.rows) +
		s.held.closed.len() + s.socks.closed.len() + len(s.sockSamples.rows) + s.owners.closed.len() + s.files.closed.len()
}

// stageSuffix marks a flush's file written but not yet in place: readers
// glob *.parquet and do not see it. A flush renames all its files into place
// only when every one was written (all or nothing); recover puts complete
// ones left by a crash in between in place.
const stageSuffix = ".stage"

// flushOnce writes everything buffered and rewrites the open files.
func (s *Store) flushOnce() error {
	s.dirs.Lock()
	defer s.dirs.Unlock()
	now := time.Now().UTC()
	s.refreshMeta(now)
	day, name := now.Format("2006-01-02"), now.Format("15-04")
	var errs []error
	var staged [][2]string // stage path, final path
	part := func(table string, n int, write func(path string) error) {
		if n == 0 {
			return
		}
		p, err := freePath(filepath.Join(s.dir, Dir(table), day), name)
		if err == nil {
			err = write(p + stageSuffix)
		}
		if err == nil {
			staged = append(staged, [2]string{p + stageSuffix, p})
		}
		errs = append(errs, err)
	}
	part("samples", len(s.samples), func(p string) error { return writeFile(p, s.samples) })
	part("processes", s.procs.closed.len(), func(p string) error { return writeFile(p, s.procs.closed.chunks...) })
	part("proc_samples", len(s.procSamples.rows), func(p string) error { return writeFile(p, s.procSamples.rows) })
	part("sockets", s.socks.closed.len(), func(p string) error { return writeFile(p, s.socks.closed.chunks...) })
	part("sock_samples", len(s.sockSamples.rows), func(p string) error { return writeFile(p, s.sockSamples.rows) })
	part("sock_owners", s.owners.closed.len(), func(p string) error { return writeFile(p, s.owners.closed.chunks...) })
	part("open_files", s.files.closed.len(), func(p string) error { return writeFile(p, s.files.closed.chunks...) })
	part("fds_held", s.held.closed.len(), func(p string) error { return writeConv(p, heldOf, s.held.closed.chunks...) })
	part("mounts", len(s.mounts), func(p string) error { return writeFile(p, s.mounts) })
	part("tcp_conns", s.conns.closed.len(), func(p string) error {
		return writeConv(p, func(r *tcpConnRow, c *store.TCPConn) { tcpConnOf(r, c, &s.addrs) }, s.conns.closed.chunks...)
	})
	part("tcp_transitions", len(s.trans), func(p string) error { return writeFile(p, s.trans) })
	part("tcp_keyframes", s.keyframes.len(), func(p string) error {
		return writeConv(p, func(r *keyframeRow, k *store.KeyframeRow) { keyframeOf(r, k, &s.addrs) }, s.keyframes.chunks...)
	})
	part("reconcile", len(s.reconcile), func(p string) error { return writeFile(p, s.reconcile) })
	part("oom_events", len(s.oom), func(p string) error { return writeFile(p, s.oom) })
	part("recorder_stats", len(s.stats), func(p string) error { return writeFile(p, s.stats) })
	part("guard_events", len(s.guard), func(p string) error { return writeFile(p, s.guard) })
	part("verify_snapshots", len(s.verify), func(p string) error { return writeFile(p, s.verify) })
	part("sys_samples", len(s.sys), func(p string) error { return writeFile(p, s.sys) })
	part("cpu_samples", len(s.cpus), func(p string) error { return writeFile(p, s.cpus) })
	part("disk_samples", len(s.disks), func(p string) error { return writeFile(p, s.disks) })
	part("fs_samples", len(s.fs), func(p string) error { return writeFile(p, s.fs) })
	part("net_counters", len(s.netCounters), func(p string) error { return writeFile(p, s.netCounters) })
	part("links", len(s.links), func(p string) error { return writeFile(p, s.links) })
	part("addrs", len(s.ifAddrs), func(p string) error { return writeFile(p, s.ifAddrs) })
	part("routing", len(s.routing), func(p string) error { return writeFile(p, s.routing) })
	part("kmsg", len(s.kmsg), func(p string) error { return writeFile(p, s.kmsg) })
	part("units", len(s.units), func(p string) error { return writeFile(p, s.units) })
	part("cgroups", len(s.cgroups), func(p string) error { return writeFile(p, s.cgroups) })
	part("snapshots", len(s.snapshots), func(p string) error { return writeFile(p, s.snapshots) })
	part("blockdevs", len(s.blockDevs), func(p string) error { return writeFile(p, s.blockDevs) })
	part("neighs", len(s.neighs), func(p string) error { return writeFile(p, s.neighs) })
	part("meta", len(s.meta), func(p string) error { return writeFile(p, s.meta) })
	if err := errors.Join(errs...); err != nil {
		// Keep the buffers; the next flush writes them all again. Nothing of
		// this one is in place, so nothing is written twice.
		for _, f := range staged {
			os.Remove(f[0])
		}
		return err
	}
	dirs := map[string]bool{}
	for _, f := range staged {
		if err := os.Rename(f[0], f[1]); err != nil {
			s.opt.Logf("pqstore: %v (recover puts it in place at the next start)", err)
			continue
		}
		dirs[filepath.Dir(f[1])] = true
	}
	for d := range dirs {
		if err := SyncDir(d); err != nil {
			s.opt.Logf("pqstore: %v", err)
		}
	}
	for _, f := range staged {
		s.logFile(f[1])
	}
	// Open rows, seen until the last sample (open files: the last fd walk).
	errs = append(errs,
		writeOpen(s, "processes", s.procs, s.lastAny, func(r *processRow) int64 { return r.FirstSeen }, func(r *processRow, v int64) { r.LastSeen = v }),
		writeOpen(s, "sockets", s.socks, s.lastAny, func(r *socketRow) int64 { return r.FirstSeen }, func(r *socketRow, v int64) { r.LastSeen = v }),
		writeOpen(s, "sock_owners", s.owners, s.lastAny, func(r *ownerRow) int64 { return r.FirstSeen }, func(r *ownerRow, v int64) { r.LastSeen = v }),
		writeOpen(s, "open_files", s.files, s.lastFD, func(r *fileRow) int64 { return r.FirstSeen }, func(r *fileRow, v int64) { r.LastSeen = v }),
		writeOpenConv(s, "fds_held", s.held.open, func(r *heldRow, h *heldRec) {
			h.LastSeen = max(h.FirstSeen, s.lastFD)
			heldOf(r, h)
		}),
		writeOpenConv(s, "tcp_conns", s.conns.open, func(r *tcpConnRow, c *store.TCPConn) {
			c.LastSeen = max(c.OpenTS, s.lastAny)
			tcpConnOf(r, c, &s.addrs)
		}))
	s.samples, s.guard, s.verify, s.meta, s.oom, s.stats = nil, nil, nil, nil, nil, nil
	s.trans = s.trans[:0] // no pointers: keep the array
	s.keyframes, s.reconcile, s.mounts = rowBuf[store.KeyframeRow]{}, nil, nil
	s.sys, s.cpus, s.disks, s.fs, s.netCounters, s.links, s.ifAddrs, s.routing, s.kmsg, s.units, s.cgroups, s.snapshots, s.blockDevs, s.neighs = s.sys[:0], s.cpus[:0], s.disks[:0], s.fs[:0], s.netCounters[:0], s.links[:0], s.ifAddrs[:0], s.routing[:0], s.kmsg[:0], s.units[:0], s.cgroups[:0], s.snapshots[:0], s.blockDevs[:0], s.neighs[:0]
	s.conns.reset()
	s.held.reset()
	s.procs.reset()
	s.socks.reset()
	s.owners.reset()
	s.files.reset()
	s.procSamples.reset()
	s.sockSamples.reset()
	s.lastFlush, s.textBytes, s.early = time.Now(), 0, ""
	if err := s.ilog.sync(); err != nil {
		s.opt.Logf("pqstore: integrity log: %v", err)
	}
	s.ilog.seal("-")
	s.bytes.Store(dirSize(s.dir))
	if s.busy.CompareAndSwap(false, true) {
		s.wg.Add(1)
		go s.maintain()
	}
	return errors.Join(errs...)
}

// writeOpen rewrites the run's open file for an entity table: each row seen
// until last (or its first sighting, if later).
func writeOpen[T any](s *Store, table string, e *entity[T], last int64, first func(*T) int64, setLast func(*T, int64)) error {
	p := filepath.Join(s.dir, Dir(table), "open", fmt.Sprintf("%d.parquet", s.run))
	if len(e.open) == 0 {
		if err := s.removeData(p, "closed"); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	rows := slices.Grow(e.scratch[:0], len(e.open))
	for _, r := range e.open {
		rows = append(rows, *r)
		x := &rows[len(rows)-1]
		setLast(x, max(first(x), last))
	}
	err := writeFile(p, rows)
	clear(rows[:cap(rows)]) // keep the array, not the strings
	e.scratch = rows
	if err == nil {
		s.logFile(p)
	}
	return err
}

// removeData removes a data file (or a day's integrity log) the store wrote
// and records the removal in the integrity log ("del REASON PATH").
func (s *Store) removeData(p, reason string) error {
	err := os.Remove(p)
	if err == nil {
		if lerr := s.ilog.removed(p, reason); lerr != nil {
			s.opt.Logf("pqstore: integrity log: %v", lerr)
		}
	}
	return err
}

// logFile records a file just written in the integrity log; a failure is
// logged, not returned (the data is written).
func (s *Store) logFile(p string) {
	if err := s.ilog.record(p); err != nil {
		s.opt.Logf("pqstore: integrity log: %v", err)
	}
}

// writeOpenConv rewrites the run's open file of a valBuf table; conv
// converts a row (a copy: it may set its last_seen).
func writeOpenConv[S, T any](s *Store, table string, open map[int64]*S, conv func(*T, *S)) error {
	p := filepath.Join(s.dir, Dir(table), "open", fmt.Sprintf("%d.parquet", s.run))
	if len(open) == 0 {
		if err := s.removeData(p, "closed"); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	defer func() {
		if _, err := os.Stat(p); err == nil {
			s.logFile(p)
		}
	}()
	return writeRows(p, func(w *parquet.GenericWriter[T]) error {
		buf := make([]T, 0, min(len(open), chunkRows))
		for _, p := range open {
			row := *p
			buf = buf[:len(buf)+1]
			conv(&buf[len(buf)-1], &row)
			if len(buf) == cap(buf) {
				if _, err := w.Write(buf); err != nil {
					return err
				}
				buf = buf[:0]
			}
		}
		_, err := w.Write(buf)
		return err
	})
}

func (s *Store) Close() error {
	s.SetMeta(MetaStopMS, strconv.FormatInt(time.Now().UnixMilli(), 10)) // a clean stop (PrevRun)
	err := s.Flush()
	s.cancel()
	s.wg.Wait()
	s.ilog.seal("end")
	err = errors.Join(err, s.ilog.close())
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
	parquet.Compression(zstdPages),
	parquet.DataPageStatistics(false),
	parquet.ColumnIndexSizeLimit(func([]string) int { return 16 }),
	parquet.SkipPageBounds("output"), parquet.SkipPageBounds("cmdline"),
	parquet.SkipPageBounds("target"), parquet.SkipPageBounds("detail"),
}

// writeFile writes the rows, given as one or more slices, to a new file.
func writeFile[T any](path string, rows ...[]T) error {
	return writeRows(path, func(w *parquet.GenericWriter[T]) error {
		g := &groupWriter[T]{w: w}
		for _, r := range rows {
			for len(r) > 0 {
				n := min(len(r), chunkRows)
				if err := g.write(r[:n]); err != nil {
					return err
				}
				r = r[n:]
			}
		}
		return nil
	})
}

// writeConv writes rows kept in a compact form, converted to the file's row
// type a chunk at a time.
func writeConv[S, T any](path string, conv func(*T, *S), rows ...[]S) error {
	return writeRows(path, func(w *parquet.GenericWriter[T]) error {
		g := &groupWriter[T]{w: w}
		var buf []T
		for _, r := range rows {
			for len(r) > 0 {
				n := min(len(r), chunkRows)
				if cap(buf) < n {
					buf = make([]T, n)
				}
				buf = buf[:n]
				for i := range buf {
					conv(&buf[i], &r[i])
				}
				if err := g.write(buf); err != nil {
					return err
				}
				r = r[n:]
			}
		}
		return nil
	})
}

// writeRows writes a new file atomically and durably (temporary file, fsync,
// rename, directory fsync);
// fill writes its rows.
func writeRows[T any](path string, fill func(*parquet.GenericWriter[T]) error) error {
	if err := mkdirDurable(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := parquet.NewGenericWriter[T](f, writerOptions...)
	err = errors.Join(fill(w), w.Close(), f.Sync(), f.Close())
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return RenameDurable(tmp, path)
}

// freePath is dir/name.parquet, or dir/name-2.parquet, ... if taken.
func freePath(dir, name string) (string, error) {
	if err := mkdirDurable(dir, 0o750); err != nil {
		return "", err
	}
	p := filepath.Join(dir, name+".parquet")
	for i := 2; ; i++ {
		if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
			return p, nil
		} else if err != nil {
			return "", err // not "taken": asking again would loop forever
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
		days, _ := os.ReadDir(filepath.Join(s.dir, Dir(t)))
		for _, d := range days {
			if !d.IsDir() || d.Name() == "open" {
				continue
			}
			files, _ := os.ReadDir(filepath.Join(s.dir, Dir(t), d.Name()))
			for _, f := range files {
				h := hourFile{path: filepath.Join(s.dir, Dir(t), d.Name(), f.Name()), table: t, day: d.Name()}
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
// file (a crash between the rename and the deletes), and puts in place the
// complete files of a flush that a crash stopped before its renames (its
// buffers are gone with the crash: nothing is written twice).
func (s *Store) recover() error {
	filepath.WalkDir(s.dir, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil || d.IsDir():
		case strings.HasSuffix(p, ".tmp"):
			os.Remove(p)
		case strings.HasSuffix(p, stageSuffix):
			final := strings.TrimSuffix(p, stageSuffix)
			if _, err := os.Stat(final); err == nil {
				final, err = freePath(filepath.Dir(final), strings.TrimSuffix(filepath.Base(final), ".parquet"))
				if err != nil {
					return nil
				}
			}
			if err := RenameDurable(p, final); err == nil {
				s.logFile(final)
			}
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
			if err := s.removeData(h.path, "compacted"); err != nil {
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

	threadCPU := func() int64 {
		var ru unix.Rusage
		if unix.Getrusage(unix.RUSAGE_THREAD, &ru) != nil {
			return 0
		}
		return ru.Utime.Sec*1e6 + int64(ru.Utime.Usec) + ru.Stime.Sec*1e6 + int64(ru.Stime.Usec)
	}
	last := threadCPU()
	account := func() {
		now := threadCPU()
		s.maintUS.Add(now - last)
		last = now
	}
	if err := s.compact(time.Now().UTC().Truncate(time.Hour), account); err != nil {
		s.opt.Logf("pqstore: compaction: %v", err)
	}
	if err := s.expire(time.Now().UTC()); err != nil {
		s.opt.Logf("pqstore: retention: %v", err)
	}
	s.bytes.Store(dirSize(s.dir))
	account()
}

// compact merges the files of every hour that ended before current into
// <HH>.parquet (including an earlier hour file, if any), calling done after
// each table-hour.
func (s *Store) compact(current time.Time, done func()) error {
	var errs []error
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
		if s.ctx.Err() != nil || s.opt.Busy != nil && s.opt.Busy() {
			return errors.Join(errs...)
		}
		var paths []string
		for _, h := range g {
			paths = append(paths, h.path)
		}
		out := filepath.Join(s.dir, Dir(g[0].table), g[0].day, g[0].hour+".parquet")
		if err := compactors[g[0].table](paths, out); err != nil {
			// That hour keeps its parts (readers skip a damaged one); the
			// other hours are still compacted.
			errs = append(errs, fmt.Errorf("%s: %w", k, err))
			continue
		}
		s.logFile(out)
		if err := s.ilog.sync(); err != nil { // before the parts it replaces go
			s.opt.Logf("pqstore: integrity log: %v", err)
		}
		for _, h := range g {
			if h.path != out {
				s.removeData(h.path, "compacted")
			}
		}
		done()
	}
	return errors.Join(errs...)
}

var compactors = map[string]func(parts []string, out string) error{
	"samples": merge[sampleRow], "processes": merge[processRow], "proc_samples": merge[procSampleRow],
	"sockets": merge[socketRow], "sock_samples": merge[sockSampleRow], "sock_owners": merge[ownerRow],
	"open_files": merge[fileRow], "oom_events": merge[oomRow], "recorder_stats": merge[statRow],
	"tcp_conns": merge[tcpConnRow], "fds_held": merge[heldRow], "mounts": merge[mountRow], "tcp_transitions": merge[tcpTransRow], "tcp_keyframes": merge[keyframeRow],
	"reconcile":    merge[reconcileRow],
	"guard_events": merge[guardRow], "verify_snapshots": merge[verifyRow],
	"sys_samples": merge[sysRow], "cpu_samples": merge[cpuRow], "disk_samples": merge[diskRow], "fs_samples": merge[fsRow],
	"net_counters": merge[netCounterRow], "links": merge[linkRow], "addrs": merge[addrRow], "routing": merge[routingRow], "kmsg": merge[kmsgRow], "units": merge[unitRow], "cgroups": merge[cgroupRow], "snapshots": merge[snapshotRow], "blockdevs": merge[blockDevRow], "neighs": merge[neighRow], "meta": merge[metaRow],
}

// merge streams the rows of parts into out (atomically replaced).
func merge[T any](parts []string, out string) error {
	tmp := out + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := parquet.NewGenericWriter[T](f, writerOptions...)
	g := &groupWriter[T]{w: w}
	buf := make([]T, 4096)
	for _, p := range parts {
		if err = copyRows(p, g, buf); err != nil {
			break
		}
	}
	err = errors.Join(err, w.Close(), f.Sync(), f.Close())
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return RenameDurable(tmp, out) // durable before compact deletes the parts
}

func copyRows[T any](path string, w *groupWriter[T], buf []T) error {
	if err := CheckFile(path); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := newReader[T](f)
	if err != nil {
		return err
	}
	defer r.Close()
	return readSafely(path, func() error { return copyAll(r, w, buf) })
}

func copyAll[T any](r *parquet.GenericReader[T], w *groupWriter[T], buf []T) error {
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if werr := w.write(buf[:n]); werr != nil {
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
				errs = append(errs, s.removeData(h.path, "retention"))
			}
		}
		// Integrity logs: a day's log lists files of that day and, for open
		// files, later ones; kept one day longer than the data.
		logs, _ := filepath.Glob(filepath.Join(s.dir, IntegrityDir, "*.log"))
		for _, l := range logs {
			if d, err := time.Parse("2006-01-02", strings.TrimSuffix(filepath.Base(l), ".log")); err == nil &&
				d.Add(48*time.Hour).Before(now.Add(-r)) {
				errs = append(errs, s.removeData(l, "retention"))
			}
		}
		own := fmt.Sprintf("%d.parquet", s.run)
		for _, t := range EntityTables {
			open := filepath.Join(s.dir, Dir(t), "open")
			files, _ := os.ReadDir(open)
			for _, f := range files {
				if fi, err := f.Info(); err == nil && f.Name() != own && fi.ModTime().Before(now.Add(-r)) {
					errs = append(errs, s.removeData(filepath.Join(open, f.Name()), "retention"))
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
				errs = append(errs, s.removeData(hours[i].path, "size-cap"))
			}
		}
	}
	// Remove empty day directories (not while a flush may have just made one).
	s.dirs.Lock()
	defer s.dirs.Unlock()
	for _, t := range Tables {
		days, _ := os.ReadDir(filepath.Join(s.dir, Dir(t)))
		for _, d := range days {
			if d.IsDir() && d.Name() != "open" {
				os.Remove(filepath.Join(s.dir, Dir(t), d.Name())) // fails unless empty
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
	"fds_held":         func(p string) error { return writeFile[heldRow](p, nil) },
	"mounts":           func(p string) error { return writeFile[mountRow](p, nil) },
	"tcp_transitions":  func(p string) error { return writeFile[tcpTransRow](p, nil) },
	"tcp_keyframes":    func(p string) error { return writeFile[keyframeRow](p, nil) },
	"reconcile":        func(p string) error { return writeFile[reconcileRow](p, nil) },
	"recorder_stats":   func(p string) error { return writeFile[statRow](p, nil) },
	"guard_events":     func(p string) error { return writeFile[guardRow](p, nil) },
	"verify_snapshots": func(p string) error { return writeFile[verifyRow](p, nil) },
	"sys_samples":      func(p string) error { return writeFile[sysRow](p, nil) },
	"cpu_samples":      func(p string) error { return writeFile[cpuRow](p, nil) },
	"disk_samples":     func(p string) error { return writeFile[diskRow](p, nil) },
	"fs_samples":       func(p string) error { return writeFile[fsRow](p, nil) },
	"net_counters":     func(p string) error { return writeFile[netCounterRow](p, nil) },
	"links":            func(p string) error { return writeFile[linkRow](p, nil) },
	"addrs":            func(p string) error { return writeFile[addrRow](p, nil) },
	"routing":          func(p string) error { return writeFile[routingRow](p, nil) },
	"kmsg":             func(p string) error { return writeFile[kmsgRow](p, nil) },
	"units":            func(p string) error { return writeFile[unitRow](p, nil) },
	"cgroups":          func(p string) error { return writeFile[cgroupRow](p, nil) },
	"snapshots":        func(p string) error { return writeFile[snapshotRow](p, nil) },
	"blockdevs":        func(p string) error { return writeFile[blockDevRow](p, nil) },
	"neighs":           func(p string) error { return writeFile[neighRow](p, nil) },
	"meta":             func(p string) error { return writeFile[metaRow](p, nil) },
}
