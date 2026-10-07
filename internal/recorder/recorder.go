// Package recorder runs the sampling loop: each sample reads processes (and,
// in later phases, sockets and open files), updates the in-memory interval
// trackers and writes the resulting changes in one SQLite transaction.
package recorder

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sosv/internal/procfs"
	"sosv/internal/sockdiag"
	"sosv/internal/store"
)

type Config struct {
	DB          string
	Interval    time.Duration
	FDInterval  time.Duration
	Duration    time.Duration // 0 = until signalled
	ProcRoot    string
	CPUBudget   float64 // fraction of one core, e.g. 0.02
	VerifyEvery time.Duration
}

type procKey struct {
	pid   int
	start int64 // unix ms
}

type procEntry struct {
	id      int64
	key     procKey
	gen     uint64 // generation of the last sample that saw it
	first   int64  // first_seen
	last    int64  // ts of the last sample that saw it
	owns    bool   // held sockets at its last fd walk
	walked  uint64 // generation of its last fd walk
	closed  bool   // closed in the current sample
	sample  store.ProcSample
	hasSamp bool
	upd     store.ProcUpdate // current slow attributes
}

type Recorder struct {
	cfg   Config
	fs    procfs.FS
	db    *store.DB
	log   *log.Logger
	boot  int64 // boot time, unix ms
	gen   uint64
	procs map[procKey]*procEntry
	ids   map[string]int64 // next id per table

	listSockets func() ([]sockdiag.Socket, error)
	sockSource  string // "sock_diag" or "proc_net"
	socks       map[sockKey]*sockEntry
	byInode     map[uint64]*sockEntry
	owners      map[ownKey]*ownEntry
	// pending holds rows produced outside a sample (skips, guard events);
	// they are written with the next sample's transaction.
	pending   store.Batch
	lastDBDur time.Duration
	lastTS    int64
}

func New(cfg Config, logger *log.Logger) (*Recorder, error) {
	fs := procfs.New(cfg.ProcRoot)
	btime, err := fs.BootTime()
	if err != nil {
		return nil, err
	}
	db, err := store.Open(cfg.DB, false)
	if err != nil {
		return nil, err
	}
	r := &Recorder{cfg: cfg, fs: fs, db: db, log: logger, boot: btime * 1000,
		procs: map[procKey]*procEntry{}, ids: map[string]int64{},
		socks: map[sockKey]*sockEntry{}, byInode: map[uint64]*sockEntry{}, owners: map[ownKey]*ownEntry{}}
	r.initSockets()
	if n, err := db.Recover(); err != nil {
		return nil, fmt.Errorf("recover open rows: %w", err)
	} else if n > 0 {
		logger.Printf("closed %d rows left open by a previous run", n)
	}
	for _, t := range []string{"processes", "sockets", "sock_owners", "open_files"} {
		n, err := db.MaxID(t)
		if err != nil {
			return nil, err
		}
		r.ids[t] = n
	}
	memKB, _ := fs.MemTotalKB()
	host, _ := os.Hostname()
	for k, v := range map[string]string{
		"hostname": host, "mem_total_kb": strconv.FormatInt(memKB, 10),
		"boot_time": strconv.FormatInt(btime, 10), "clk_tck": strconv.Itoa(procfs.ClockTicks),
		"interval_s": fmt.Sprint(cfg.Interval.Seconds()), "fd_interval_s": fmt.Sprint(cfg.FDInterval.Seconds()),
	} {
		if err := db.SetMeta(k, v); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *Recorder) nextID(table string) int64 {
	r.ids[table]++
	return r.ids[table]
}

// Run samples every Interval until ctx is cancelled or Duration elapses.
func (r *Recorder) Run(ctx context.Context) error {
	defer r.db.Close()
	start := time.Now()
	next := start
	var lastFD time.Time
	for {
		if r.cfg.Duration > 0 && time.Since(start) >= r.cfg.Duration {
			break
		}
		if d := time.Until(next); d > 0 {
			select {
			case <-ctx.Done():
				return r.shutdown()
			case <-time.After(d):
			}
		}
		if ctx.Err() != nil {
			return r.shutdown()
		}
		now := time.Now()
		// A full fd walk is due when FDInterval has passed (with half an
		// interval of slack so 120s/30s lands on every 4th sample).
		fdWalk := lastFD.IsZero() || now.Sub(lastFD) >= r.cfg.FDInterval-r.cfg.Interval/2
		if fdWalk {
			lastFD = now
		}
		if err := r.sample(now, fdWalk); err != nil {
			return fmt.Errorf("sample: %w", err)
		}
		next = next.Add(r.cfg.Interval)
		// Guard rail: if the sample overran, skip the missed slots instead of
		// running them back to back.
		for !time.Now().Before(next) {
			ts := next.UnixMilli()
			r.pending.Guard = append(r.pending.Guard, store.GuardEvent{TS: ts, Kind: "skip",
				Detail: fmt.Sprintf("sample at %s overran the %s interval", now.Format(time.TimeOnly), r.cfg.Interval)})
			r.pending.Skips = append(r.pending.Skips, ts)
			next = next.Add(r.cfg.Interval)
		}
	}
	return r.shutdown()
}

// shutdown closes every open row at the last sample time.
func (r *Recorder) shutdown() error {
	if r.lastTS == 0 {
		return nil
	}
	b := &store.Batch{}
	for _, e := range r.procs {
		b.ProcCloses = append(b.ProcCloses, store.Close{ID: e.id, LastSeen: e.last})
	}
	for _, e := range r.socks {
		b.SockCloses = append(b.SockCloses, store.Close{ID: e.id, LastSeen: e.last})
	}
	for _, o := range r.owners {
		b.OwnCloses = append(b.OwnCloses, store.Close{ID: o.id, LastSeen: o.last})
	}
	if err := r.db.Write(b); err != nil {
		return err
	}
	r.log.Printf("shutdown: closed %d processes, %d sockets, %d socket owners",
		len(b.ProcCloses), len(b.SockCloses), len(b.OwnCloses))
	return nil
}

// sample takes one snapshot and writes it.
func (r *Recorder) sample(now time.Time, fdWalk bool) error {
	ts := now.UnixMilli()
	r.gen++
	b := r.pending
	r.pending = store.Batch{}

	t0 := time.Now()
	nproc := r.sampleProcs(ts, fdWalk, &b)
	durProc := time.Since(t0)

	t0 = time.Now()
	nsock := r.sampleSockets(ts, &b)
	if !fdWalk {
		r.walkOwners(ts, false, &b) // socket-owning and new processes only
	}
	durSock := time.Since(t0)

	t0 = time.Now()
	var nfd int
	if fdWalk {
		nfd = r.walkOwners(ts, true, &b)
	}
	durFD := time.Since(t0)
	r.sweepOwners(ts, &b)
	r.dropClosedProcs()

	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	cpuUS := ru.Utime.Sec*1e6 + int64(ru.Utime.Usec) + ru.Stime.Sec*1e6 + int64(ru.Stime.Usec)

	b.Sample = store.Sample{
		TS: ts, FDWalk: fdWalk,
		DurProcUS: durProc.Microseconds(),
		DurSockUS: durSock.Microseconds(),
		DurFDUS:   durFD.Microseconds(),
		DurDBUS:   r.lastDBDur.Microseconds(),
		NProc:     nproc, NSock: nsock, NFD: nfd,
		Rows:  b.Rows(),
		CPUUS: cpuUS, RSSKB: selfRSSKB(), DBBytes: r.db.LogicalBytes(),
		FDIntervalS: int64(r.cfg.FDInterval.Seconds()),
	}
	t1 := time.Now()
	if err := r.db.Write(&b); err != nil {
		return err
	}
	r.lastDBDur = time.Since(t1)
	r.lastTS = ts
	return nil
}

// sampleProcs walks the process list and fills the batch with new, changed
// and closed processes. It returns the number of processes seen.
func (r *Recorder) sampleProcs(ts int64, refresh bool, b *store.Batch) int {
	pids, err := r.fs.PIDs()
	if err != nil {
		r.log.Printf("list processes: %v", err)
		return 0
	}
	n := 0
	for _, pid := range pids {
		st, err := r.fs.ReadStat(pid)
		if err != nil {
			continue // vanished, or unreadable: skip silently
		}
		key := procKey{pid: pid, start: r.boot + int64(st.StartTime)*1000/procfs.ClockTicks}
		e := r.procs[key]
		if e == nil {
			e = r.newProc(key, st, ts, b)
			if e == nil {
				continue
			}
		} else if refresh {
			r.refreshProc(e, st, b)
		}
		e.gen = r.gen
		e.last = ts
		n++
		rss := st.RSS
		if _, res, err := r.fs.ReadStatm(pid); err == nil {
			rss = res
		}
		s := store.ProcSample{ProcID: e.id, TS: ts, State: string(st.State), Nice: st.Nice, TPGID: st.TPGID,
			CPUTicks: int64(st.Utime + st.Stime), RSSKB: rss * int64(pageKB),
			VSZKB: int64(st.VSize / 1024), Threads: st.NumThreads}
		if !e.hasSamp || !sameProcSample(e.sample, s) {
			b.ProcSamples = append(b.ProcSamples, s)
			e.sample, e.hasSamp = s, true
		}
	}
	for _, e := range r.procs {
		if e.gen != r.gen {
			ended := ts // found gone at this sample
			b.ProcCloses = append(b.ProcCloses, store.Close{ID: e.id, LastSeen: e.last, Ended: &ended})
			e.closed = true // removed by dropClosedProcs after owners are swept
		}
	}
	return n
}

func (r *Recorder) dropClosedProcs() {
	for k, e := range r.procs {
		if e.closed {
			delete(r.procs, k)
		}
	}
}

func (r *Recorder) newProc(key procKey, st procfs.Stat, ts int64, b *store.Batch) *procEntry {
	status, err := r.fs.ReadStatus(key.pid)
	if err != nil {
		return nil
	}
	cmd, err := r.fs.ReadCmdline(key.pid)
	if err != nil {
		return nil
	}
	e := &procEntry{id: r.nextID("processes"), key: key, first: ts,
		upd: store.ProcUpdate{UID: status.UID, PPID: st.PPID, Comm: st.Comm, Cmdline: cmd, Source: "sample"}}
	e.upd.ID = e.id
	r.procs[key] = e
	b.ProcInserts = append(b.ProcInserts, store.ProcRow{ID: e.id, PID: key.pid, StartTime: key.start,
		PPID: st.PPID, UID: status.UID, Comm: st.Comm, Cmdline: cmd, TTY: st.TTY, SID: st.Session,
		PGRP: st.PGRP, Locked: status.VmLckK > 0, FirstSeen: ts, Source: "sample"})
	return e
}

// refreshProc re-reads attributes that rarely change (cmdline via
// setproctitle, uid via setuid, ppid via reparenting). It runs on fd-walk
// samples only, to keep the per-interval cost to one read of stat.
func (r *Recorder) refreshProc(e *procEntry, st procfs.Stat, b *store.Batch) {
	u := e.upd
	u.PPID, u.Comm = st.PPID, st.Comm
	if status, err := r.fs.ReadStatus(e.key.pid); err == nil {
		u.UID = status.UID
	}
	if cmd, err := r.fs.ReadCmdline(e.key.pid); err == nil && (cmd != "" || st.State == 'Z') {
		u.Cmdline = cmd
	}
	if u != e.upd {
		e.upd = u
		b.ProcUpdates = append(b.ProcUpdates, u)
	}
}

func sameProcSample(a, b store.ProcSample) bool {
	a.TS, b.TS = 0, 0
	return a == b
}

var pageKB = os.Getpagesize() / 1024

func selfRSSKB() int64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0
	}
	n, _ := strconv.ParseInt(f[1], 10, 64)
	return n * int64(pageKB)
}
