// Package recorder runs the sampling loop: each sample reads processes (and,
// in later phases, sockets and open files), updates the in-memory interval
// trackers and writes the resulting changes as one batch to the storage
// backend (SQLite: one transaction; Parquet: buffered, flushed periodically).
package recorder

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/bpfproc"
	"clifr/internal/bpftcp"
	"clifr/internal/pqstore"
	"clifr/internal/procfs"
	"clifr/internal/sockdiag"
	"clifr/internal/store"
)

type Config struct {
	Version string // clifrd's version, stored in meta
	DB      string // SQLite database (v1 schema); "" = none
	DataDir string // Parquet data directory; "" = none. Both set: write both.
	Parquet pqstore.Options
	// Events: "auto" (eBPF, else the proc connector), "ebpf",
	// "proc_connector" or "none".
	Events string
	EBPF   bpfproc.Options
	// TCP: "auto" (eBPF events and keyframes, else v1 sampling), "ebpf" or
	// "sample" (v1: a socket dump every interval).
	// FDMode: "held" (v2: fds_held, fds held across two walks and deleted
	// files) or "all" (v1: every fd in open_files).
	FDMode           string
	FDFullEvery      int // held mode: read every process's fds on every n-th walk (default 5)
	TCP              string
	TCPBPF           bpftcp.Options
	KeyframeInterval time.Duration // full socket dump with events (default 5m)
	Interval         time.Duration
	FDInterval       time.Duration
	Duration         time.Duration // 0 = until signalled
	ProcRoot         string
	CPUBudget        float64 // fraction of one core, e.g. 0.02; 0 disables the guard
	// BudgetWindow is how much recent CPU history the budget guard looks at.
	BudgetWindow time.Duration
	VerifyEvery  time.Duration
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
	files   map[fileKey]*fileEntry
	fdCount int    // fds at its last walk (held mode: unchanged count = presumed unchanged)
	exit    int64  // exit time from a proc connector event, 0 if unknown
	born    uint64 // generation of the sample that first saw it
	closed  bool   // closed in the current sample
	sample  store.ProcSample
	hasSamp bool
	upd     store.ProcUpdate // current slow attributes
}

type Recorder struct {
	cfg   Config
	fs    procfs.FS
	db    store.Backend
	log   *Logger
	boot  int64 // boot time, unix ms
	sys   *sysSampler
	gen   uint64
	procs map[procKey]*procEntry
	ids   map[string]int64 // next id per table

	listSockets func() ([]sockdiag.Socket, error)
	sockSource  string // "sock_diag" or "proc_net"
	socks       map[sockKey]*sockEntry
	byInode     map[uint64]*sockEntry
	owners      map[ownKey]*ownEntry

	events       *eventQueue // nil if the proc connector is unavailable
	tcp          *tcpTracker // nil: v1 socket sampling
	fdWalks      uint64      // full fd walks so far
	mounts       *mountWatch
	fsUsage      fsUsage
	lostReported int
	evProcs      map[procKey]*evProc // known from events, not (yet) sampled
	evByPID      map[int]procKey
	byPID        map[int]*procEntry
	// pending holds rows produced outside a sample (skips, guard events);
	// they are written with the next sample's transaction.
	pending   store.Batch
	lastDBDur time.Duration
	lastTS    int64

	fdInterval      time.Duration // current; the CPU guard may lengthen it
	cpuHist         []cpuPoint
	fdWalkUS        int64 // time spent in fd walks since the start
	budgetExhausted bool
	afterSample     func() // test hook
}

func New(cfg Config, logger *Logger) (*Recorder, error) {
	fs := procfs.New(cfg.ProcRoot)
	btime, err := fs.BootTime()
	if err != nil {
		return nil, err
	}
	db, err := openBackend(cfg, logger)
	if err != nil {
		return nil, err
	}
	r := &Recorder{cfg: cfg, fs: fs, db: db, log: logger, boot: preciseBootMS(fs, btime), sys: newSysSampler(cfg.ProcRoot),
		procs: map[procKey]*procEntry{}, ids: map[string]int64{},
		socks: map[sockKey]*sockEntry{}, byInode: map[uint64]*sockEntry{}, owners: map[ownKey]*ownEntry{},
		evProcs: map[procKey]*evProc{}, evByPID: map[int]procKey{}, byPID: map[int]*procEntry{}}
	r.initSockets()
	if r.cfg.FDFullEvery == 0 {
		r.cfg.FDFullEvery = 5
	}
	r.fdInterval = cfg.FDInterval
	if r.cfg.BudgetWindow == 0 {
		r.cfg.BudgetWindow = 5 * time.Minute
	}
	for _, t := range []string{"processes", "sockets", "sock_owners", "open_files", "tcp_conns"} {
		n, err := db.MaxID(t)
		if err != nil {
			return nil, err
		}
		r.ids[t] = n
	}
	memKB, _ := fs.MemTotalKB()
	host, _ := os.Hostname()
	bootID, _ := fs.ReadBootID()
	_, offset := time.Now().Zone()
	for k, v := range map[string]string{
		"schema_version": strconv.Itoa(store.SchemaVersion), "clifrd_version": cfg.Version,
		"machine_id": machineID(), "boot_id": bootID, "timezone": timeZone(), "tz_offset_s": strconv.Itoa(offset),
		"hostname": host, "mem_total_kb": strconv.FormatInt(memKB, 10),
		"boot_time": strconv.FormatInt(btime, 10), "boot_ms": strconv.FormatInt(r.boot, 10), "clk_tck": strconv.Itoa(procfs.ClockTicks), "page_kb": strconv.Itoa(os.Getpagesize() / 1024),
		"interval_s": fmt.Sprint(cfg.Interval.Seconds()), "fd_interval_s": fmt.Sprint(cfg.FDInterval.Seconds()),
	} {
		if err := db.SetMeta(k, v); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// startTCPMode starts eBPF TCP events unless sampling is configured or
// eBPF is unavailable (then: v1 socket sampling, unless "ebpf" was asked for).
func (r *Recorder) startTCPMode(done <-chan struct{}) (stop func(), err error) {
	mode := r.cfg.TCP
	if mode == "" {
		mode = "auto"
	}
	if r.cfg.KeyframeInterval <= 0 {
		r.cfg.KeyframeInterval = 5 * time.Minute
	}
	if mode == "sample" || r.fs.Root != "/proc" {
		r.db.SetMeta("tcp", "sample")
		r.v1FDs("TCP is sampled")
		return nil, nil
	}
	stop, err = r.startTCP(done)
	if err != nil {
		if mode == "ebpf" {
			return nil, fmt.Errorf("eBPF TCP events: %w", err)
		}
		r.log.Warnf("eBPF TCP events unavailable, sampling sockets every interval (v1): %v", err)
		r.db.SetMeta("tcp", "sample")
		r.v1FDs("TCP is sampled")
		return nil, nil
	}
	tw := "time-wait end estimated"
	if r.tcp.src.TWEnd {
		tw = "time-wait end exact"
	}
	desc := fmt.Sprintf("events (%s, %s, state %s, %s), keyframe every %s", r.tcp.src.Buffer, r.tcp.src.Probes, r.tcp.src.State, tw, r.cfg.KeyframeInterval)
	if len(r.tcp.src.Missing) > 0 {
		desc += ", missing " + strings.Join(r.tcp.src.Missing, " ")
	}
	r.db.SetMeta("tcp", desc)
	r.db.SetMeta("keyframe_interval_s", fmt.Sprint(r.cfg.KeyframeInterval.Seconds()))
	r.log.Printf("TCP: %s", desc)
	return stop, nil
}

// v1FDs switches open files to v1 (every fd in open_files): held fds rely on
// TCP events to tell which socket fds are connections.
func (r *Recorder) v1FDs(why string) {
	if r.cfg.FDMode != "all" && r.fs.Root == "/proc" {
		r.log.Printf("open files: every fd (v1), since %s", why)
	}
	if r.fs.Root == "/proc" {
		r.cfg.FDMode = "all"
	}
}

// openBackend opens the SQLite database, the Parquet directory, or both.
func openBackend(cfg Config, logger *Logger) (store.Backend, error) {
	var lite store.Backend
	if cfg.DB != "" {
		db, err := store.Open(cfg.DB, false)
		if err != nil {
			return nil, err
		}
		if n, err := db.Recover(); err != nil {
			db.Close()
			return nil, fmt.Errorf("recover open rows: %w", err)
		} else if n > 0 {
			logger.Printf("closed %d rows left open by a previous run", n)
		}
		lite = db
	}
	if cfg.DataDir == "" {
		if lite == nil {
			return nil, fmt.Errorf("no storage: set a database file or a data directory")
		}
		return lite, nil
	}
	opt := cfg.Parquet
	if opt.Logf == nil {
		opt.Logf = logger.Warnf
	}
	pq, err := pqstore.Open(cfg.DataDir, opt)
	if err != nil {
		if lite != nil {
			lite.Close()
		}
		return nil, err
	}
	if lite == nil {
		return pq, nil
	}
	return store.Tee(pq, lite), nil
}

// preciseBootMS returns the boot time in unix ms. /proc/stat's btime is
// truncated to whole seconds, which would skew process start times (and
// so durations against exit events) by up to a second; CLOCK_BOOTTIME is the
// clock /proc/<pid>/stat start times are measured on.
func preciseBootMS(fs procfs.FS, btime int64) int64 {
	if fs.Root != "/proc" {
		return btime * 1000 // fixtures describe their own boot time
	}
	var bt unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &bt); err != nil {
		return btime * 1000
	}
	return time.Now().UnixMilli() - bt.Nano()/1e6
}

func (r *Recorder) nextID(table string) int64 {
	r.ids[table]++
	return r.ids[table]
}

// Run samples every Interval until ctx is cancelled or Duration elapses.
func (r *Recorder) Run(ctx context.Context) error {
	defer r.db.Close()
	stopEvents, err := r.startEvents(ctx)
	if err != nil {
		return err
	}
	defer stopEvents()
	mountsDone := make(chan struct{})
	if stop := r.startMounts(mountsDone); stop != nil {
		defer stop()
		defer close(mountsDone)
	}
	tcpDone := make(chan struct{})
	if stop, err := r.startTCPMode(tcpDone); err != nil {
		return err
	} else if stop != nil {
		defer stop()
		defer close(tcpDone)
	}
	if r.heldMode() {
		r.db.SetMeta("fds", "held")
	} else {
		r.db.SetMeta("fds", "all")
	}
	start := time.Now()
	next := start
	var lastFD, lastVerify time.Time
	for {
		if r.cfg.Duration > 0 && time.Since(start) >= r.cfg.Duration {
			break
		}
		for {
			d := time.Until(next)
			if d <= 0 {
				break
			}
			if r.tcp != nil {
				d = min(d, tcpDrainEvery)
			}
			select {
			case <-ctx.Done():
				return r.shutdown()
			case <-time.After(d):
			}
			if r.tcp != nil && time.Until(next) > 0 {
				r.drainTCP()
			}
		}
		if ctx.Err() != nil {
			return r.shutdown()
		}
		now := time.Now()
		// A full fd walk is due when FDInterval has passed (with half an
		// interval of slack so 120s/30s lands on every 4th sample).
		fdWalk := lastFD.IsZero() || now.Sub(lastFD) >= r.fdInterval-r.cfg.Interval/2
		// Verify checkpoints force a full walk so ps, ss and lsof are all
		// compared with the same sample.
		verify := r.cfg.VerifyEvery > 0 && !lastFD.IsZero() &&
			(lastVerify.IsZero() || now.Sub(lastVerify) >= r.cfg.VerifyEvery-r.cfg.Interval/2)
		if verify {
			fdWalk, lastVerify = true, now
		}
		if fdWalk {
			lastFD = now
		}
		if err := r.sample(now, fdWalk); err != nil {
			return fmt.Errorf("sample: %w", err)
		}
		if verify {
			r.captureVerify(now.UnixMilli())
			// A full sample right after the real commands finish: anything
			// that appeared or vanished while they ran is then classified as
			// churn by `clifr verify` instead of missing/extra.
			if err := r.sample(time.Now(), true); err != nil {
				return fmt.Errorf("post-checkpoint sample: %w", err)
			}
			lastFD = time.Now()
		}
		if r.afterSample != nil {
			r.afterSample()
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

const openRowsFlushAll = int64(1) << 62

// shutdown closes every open row at the last sample time.
func (r *Recorder) shutdown() error {
	if r.lastTS == 0 {
		return nil
	}
	b := &r.pending // skips, guard events and verify output not yet written
	r.applyEvents(r.lastTS, b)
	r.flushEventProcs(openRowsFlushAll, b)
	if r.tcp != nil {
		r.applyTCP(b)
		r.flushTCP(r.lastTS, b)
		r.closeAllTCP(r.lastTS, b)
	}
	for _, e := range r.procs {
		b.ProcCloses = append(b.ProcCloses, store.Close{ID: e.id, LastSeen: e.last})
		r.closeFiles(e, b)
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
	r.log.Printf("shutdown: closed %d processes, %d sockets, %d socket owners, %d open files",
		len(b.ProcCloses), len(b.SockCloses), len(b.OwnCloses), len(b.FileCloses))
	return nil
}

// sample takes one snapshot and writes it.
func (r *Recorder) sample(now time.Time, fdWalk bool) error {
	ts := now.UnixMilli()
	r.gen++
	b := r.pending
	r.pending = store.Batch{}

	t0 := time.Now()
	r.sampleSystem(ts, &b) // first: its counters belong to ts
	nev := r.applyEvents(ts, &b)
	if r.mounts != nil {
		b.Mounts = append(b.Mounts, r.mounts.take()...)
		b.FSSamples = append(b.FSSamples, r.fsUsage.take()...)
		r.fsUsage.start(ts, r.mounts.table(), r.log)
	}
	if r.events != nil {
		b.Stats = append(b.Stats, r.events.stats(ts)...)
	}
	nproc := r.sampleProcs(ts, fdWalk, &b)
	r.flushEventProcs(ts, &b)
	durProc := time.Since(t0)

	t0 = time.Now()
	var nsock int
	keyframe := false
	if r.tcp != nil {
		// Events mode: a full socket dump only at keyframes, before the fd
		// walk so that it knows which socket inodes are inet sockets.
		if keyframe = r.prepareKeyframe(ts); keyframe {
			nsock = len(r.tcp.pendingDump)
		}
	} else {
		nsock = r.sampleSockets(ts, &b)
		if !fdWalk {
			r.walkFDs(ts, false, &b) // socket-owning and new processes only
		}
	}
	durSock := time.Since(t0)

	t0 = time.Now()
	var nfd int
	if fdWalk {
		nfd = r.walkFDs(ts, true, &b)
	}
	durFD := time.Since(t0)
	if r.tcp != nil {
		t1 := time.Now()
		r.applyTCP(&b)
		if keyframe {
			r.keyframe(&b)
		}
		r.flushTCP(ts, &b)
		b.Stats = append(b.Stats, r.tcp.stats(ts)...)
		durSock += time.Since(t1)
	}
	r.sweepOwners(ts, &b)
	r.dropClosedProcs()

	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	cpuUS := ru.Utime.Sec*1e6 + int64(ru.Utime.Usec) + ru.Stime.Sec*1e6 + int64(ru.Stime.Usec)
	r.fdWalkUS += durFD.Microseconds()
	r.checkBudget(now, cpuUS, r.fdWalkUS, &b)

	b.Sample = store.Sample{
		TS: ts, FDWalk: fdWalk,
		DurProcUS: durProc.Microseconds(),
		DurSockUS: durSock.Microseconds(),
		DurFDUS:   durFD.Microseconds(),
		DurDBUS:   r.lastDBDur.Microseconds(),
		NProc:     nproc, NSock: nsock, NFD: nfd, NEvents: nev,
		Rows:  b.Rows(),
		CPUUS: cpuUS, RSSKB: selfRSSKB(), DBBytes: r.db.Bytes(),
		FDIntervalS: int64(r.fdInterval.Seconds()),
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
		r.log.Errorf("list processes: %v", err)
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
			// ended is only set when an exit event gave the exact time;
			// otherwise the process ended between last_seen and this sample.
			var ended *int64
			if e.exit != 0 {
				ended = &e.exit
			}
			b.ProcCloses = append(b.ProcCloses, store.Close{ID: e.id, LastSeen: e.last, Ended: ended})
			e.closed = true // removed by dropClosedProcs after owners are swept
			r.closeFiles(e, b)
		}
	}
	return n
}

func (r *Recorder) dropClosedProcs() {
	for k, e := range r.procs {
		if e.closed {
			delete(r.procs, k)
			if r.byPID[k.pid] == e {
				delete(r.byPID, k.pid)
			}
		}
	}
}

func (r *Recorder) newProc(key procKey, st procfs.Stat, ts int64, b *store.Batch) *procEntry {
	status, err := r.fs.ReadStatus(key.pid)
	if err != nil {
		return nil
	}
	cmd, argv0, err := r.fs.ReadCmdline(key.pid)
	if err != nil {
		return nil
	}
	e := &procEntry{id: r.nextID("processes"), key: key, first: ts,
		upd: store.ProcUpdate{UID: status.UID, PPID: st.PPID, Comm: st.Comm, Cmdline: cmd, Argv0Len: argv0, Source: "sample"}}
	e.upd.ID = e.id
	// Adopt a process first seen through a fork/exec event: it existed
	// since its start time, not just since this sample.
	row := store.ProcRow{ID: e.id, PID: key.pid, StartTime: key.start,
		PPID: st.PPID, UID: status.UID, Comm: st.Comm, Cmdline: cmd, Argv0Len: argv0, TTY: st.TTY, SID: st.Session,
		PGRP: st.PGRP, Locked: status.VmLckK > 0, Source: "sample"}
	if ep := r.evProcs[key]; ep != nil {
		if cmd == "" && ep.ev.attrs.Cmdline != "" {
			// Seen first as a zombie: its exec event has the command line.
			cmd, argv0 = ep.ev.attrs.Cmdline, ep.ev.attrs.Argv0Len
			e.upd.Cmdline, row.Cmdline = cmd, cmd
			e.upd.Argv0Len, row.Argv0Len = argv0, argv0
		}
		e.first, e.exit = key.start, ep.exit
		e.upd.Exe, e.upd.ExecTS = ep.ev.attrs.Exe, ep.ev.attrs.ExecTS
		row.Exe, row.ExitCode, row.Signal, row.OOMKilled = ep.ev.attrs.Exe, ep.exitCode, ep.signal, ep.oom
		if ep.ev.attrs.ExecTS != 0 {
			row.ExecTS = &ep.ev.attrs.ExecTS
		}
		if ep.exitCode != nil || ep.signal != nil {
			row.ExitTS = &e.exit
		}
		delete(r.evProcs, key)
	}
	row.FirstSeen = e.first
	e.born = r.gen
	r.procs[key] = e
	r.byPID[key.pid] = e
	b.ProcInserts = append(b.ProcInserts, row)
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
	// A zombie's cmdline reads as empty; keep the command line it had (ps
	// shows zombies as "[comm] <defunct>" from the state anyway).
	if cmd, argv0, err := r.fs.ReadCmdline(e.key.pid); err == nil && cmd != "" {
		u.Cmdline, u.Argv0Len = cmd, argv0
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

// machineID is the host's systemd machine id (the same one sosreports carry),
// or "".
func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id
			}
		}
	}
	return ""
}

// timeZone is the host's time zone name (e.g. Australia/Adelaide): $TZ, the
// target of /etc/localtime, or /etc/timezone; "" if none says.
func timeZone() string {
	if tz := strings.TrimPrefix(os.Getenv("TZ"), ":"); tz != "" && !strings.HasPrefix(tz, "/") {
		return tz
	}
	if l, err := os.Readlink("/etc/localtime"); err == nil {
		if _, name, ok := strings.Cut(l, "zoneinfo/"); ok {
			return name
		}
	}
	if b, err := os.ReadFile("/etc/timezone"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}
