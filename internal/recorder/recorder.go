// Package recorder runs the sampling loop: each sample reads processes (and,
// in later phases, sockets and open files), updates the in-memory interval
// trackers and writes the resulting changes as one batch to the storage
// backend (Parquet: buffered, flushed periodically).
package recorder

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/bpfproc"
	"clifr/internal/bpftcp"
	"clifr/internal/metrics"
	"clifr/internal/pqstore"
	"clifr/internal/procfs"
	"clifr/internal/sockdiag"
	"clifr/internal/store"
)

type Config struct {
	Version string // clifrd's version, stored in meta
	DataDir string // Parquet data directory
	Parquet pqstore.Options
	// Events: "auto" (eBPF, else the proc connector), "ebpf",
	// "proc_connector" or "none".
	Events string
	EBPF   bpfproc.Options
	// Budget bounds the process and TCP events recorded in full during a
	// flood (budget.go; zero values: no limit).
	Budget EventBudget
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
	SysInterval      time.Duration // system-wide counters; 0 or >= Interval: with every sample
	ProcIO           bool          // read /proc/<pid>/io
	Redact           []string      // regular expressions masked in command lines before they are stored
	MaxCmdline       int           // bytes of a command line stored (0: all)
	// MaxFilesPerProcess: a process holding more open files is not tracked
	// (0: no limit).
	MaxFilesPerProcess int
	MemoryGuard        int64 // live heap above which the memory guard sheds data (0: off)
	Metrics            bool  // publish a metrics.Snapshot after each sample (clifrd --metrics)
	FDInterval         time.Duration
	Duration           time.Duration // 0 = until signalled
	ProcRoot           string
	CPUBudget          float64 // fraction of one core, e.g. 0.02; 0 disables the guard
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
	noFiles bool   // its open files are no longer tracked (memory guard)
	exit    int64  // exit time from a proc connector event, 0 if unknown
	born    uint64 // generation of the sample that first saw it
	closed  bool   // closed in the current sample
	sample  store.ProcSample
	hasSamp bool
	upd     store.ProcUpdate // current slow attributes
}

type Recorder struct {
	cfg Config
	fs  procfs.FS
	// ioprioGet and schedGet read a task's I/O priority and scheduling
	// policy (system calls: nil with --proc-root fixtures).
	ioprioGet, schedGet func(tid int) (int, error)
	db                  store.Backend
	log                 *Logger
	boot                int64 // boot time, unix ms
	sys                 *sysSampler
	gen                 uint64
	procs               map[procKey]*procEntry
	ids                 map[string]int64 // next id per table

	verifySkipped map[string]bool // verify commands already reported skipped (verifycap.go)
	// cgroups: when each systemd cgroup path was last written (cgroups.go).
	cgroups map[string]cgroupSeen
	// ctrSeen: the containers seen in processes' cgroups; ctrNew: one was
	// new since the names were read (ctrnames.go).
	ctrSeen    map[string]bool
	ctrCgroups map[string]bool // cgroup texts already checked for a container
	ctrNew     bool

	listSockets func() ([]sockdiag.Socket, error)
	// hostNetNS: the host's network namespace (init's), written as 0;
	// connections and processes elsewhere (containers, pods) keep their
	// namespace's number (schema 10).
	hostNetNS  uint32
	sockSource string // "sock_diag" or "proc_net"
	socks      map[sockKey]*sockEntry
	byInode    map[uint64]*sockEntry
	owners     map[ownKey]*ownEntry

	events  *eventQueue // nil if the proc connector is unavailable
	tcp     *tcpTracker // nil: v1 socket sampling
	fdWalks uint64      // full fd walks so far
	// walkNewHeld, walkHeldDeferred: new held files recorded in this walk,
	// and those left for the next walk (maxNewHeldPerWalk).
	walkNewHeld, walkHeldDeferred int
	redact                        Redactor
	mounts                        *mountWatch
	net                           *netWatch // interface addresses
	kmsg                          *kmsgWatch
	sessions                      *sessWatch
	units                         *unitWatch
	fsUsage                       fsUsage
	lostReported                  int
	procBudget, tcpBudget         *budget
	overflowReported              int64           // process events refused by the full queue, reported
	flooded                       map[string]bool // per kind: events above the budget in its last report
	flooding                      atomic.Bool     // either kind in flooded (read by the store's maintenance)
	tcpOverflowReported           int64
	evProcs                       map[procKey]*evProc // known from events, not (yet) sampled
	evByPID                       map[int]procKey
	byPID                         map[int]*procEntry
	// pending holds rows produced outside a sample (skips, guard events);
	// they are written with the next sample's transaction.
	pending   store.Batch
	lastDBDur time.Duration
	lastTS    int64

	fdInterval      time.Duration // current; the CPU guard may lengthen it
	cpuHist         []cpuPoint
	fdWalkUS        int64 // time spent in fd walks since the start
	budgetExhausted bool
	lastMaintUS     int64        // the store's maintenance CPU already reported
	cmdlineCut      atomic.Int64 // command lines cut at MaxCmdline (read by events too)
	cmdlineShed     atomic.Bool  // the memory guard cuts command lines at shedCmdline
	memShed         bool         // the memory guard is shedding
	memShedAt       time.Time    // when it last shed
	heapLive        func() uint64
	heapNow         func() uint64 // the heap with its uncollected garbage (heapObjects)
	lastCmdlineCut  int64         // of those, already reported
	afterSample     func()        // test hook
	// With cfg.Metrics: the next snapshot, built by the sampling loop, and
	// the published one, read by /metrics (never changed once published).
	live metrics.Snapshot
	snap atomic.Pointer[metrics.Snapshot]
}

// Metrics returns the newest published snapshot (nil before the first
// sample, or without cfg.Metrics). Safe from any goroutine.
func (r *Recorder) Metrics() *metrics.Snapshot { return r.snap.Load() }

// publishMetrics publishes a copy of r.live: the maps are copied, as the
// sampling loop goes on adding to them.
func (r *Recorder) publishMetrics() {
	s := r.live
	s.Stats = make(map[string][2]int64, len(r.live.Stats))
	for k, v := range r.live.Stats {
		s.Stats[k] = v
	}
	s.Guard = make(map[string]int64, len(r.live.Guard))
	for k, v := range r.live.Guard {
		s.Guard[k] = v
	}
	r.snap.Store(&s)
}

// metricsSample adds a full sample's batch to the running totals (its stats
// rows are deltas since the previous sample) and publishes.
func (r *Recorder) metricsSample(b *store.Batch) {
	if r.live.Stats == nil {
		r.live.Stats, r.live.Guard = map[string][2]int64{}, map[string]int64{}
	}
	for _, s := range b.Stats {
		t := r.live.Stats[s.Source]
		t[0] += s.Events
		t[1] += s.Dropped
		r.live.Stats[s.Source] = t
	}
	for _, g := range b.Guard {
		r.live.Guard[g.Kind]++
	}
	r.live.Version, r.live.BootMS = r.cfg.Version, r.boot
	r.live.Sample = b.Sample
	r.live.Samples++
	if r.mounts != nil {
		r.live.FS = r.fsUsage.current(r.mounts.table())
	}
	r.publishMetrics()
}

func New(cfg Config, logger *Logger) (*Recorder, error) {
	redact, err := NewRedactor(cfg.Redact)
	if err != nil {
		return nil, err
	}
	fs := procfs.New(cfg.ProcRoot)
	btime, err := fs.BootTime()
	if err != nil {
		return nil, err
	}
	// Compaction waits while events are above the budget or memory is high
	// (an hour of a flood, compacted at the end of a flood, took the
	// recorder past its MemoryMax).
	var rp *Recorder
	cfg.Parquet.Busy = func() bool { return rp != nil && rp.storeBusy() }
	db, err := openBackend(cfg, logger)
	if err != nil {
		return nil, err
	}
	r := &Recorder{cfg: cfg, fs: fs, db: db, log: logger, redact: redact, heapLive: liveHeap, heapNow: heapObjects, boot: preciseBootMS(fs, btime), sys: newSysSampler(cfg.ProcRoot),
		procs: map[procKey]*procEntry{}, ids: map[string]int64{},
		socks: map[sockKey]*sockEntry{}, byInode: map[uint64]*sockEntry{}, owners: map[ownKey]*ownEntry{},
		evProcs: map[procKey]*evProc{}, evByPID: map[int]procKey{}, byPID: map[int]*procEntry{}, cgroups: map[string]cgroupSeen{}}
	rp = r
	r.flooded = map[string]bool{}
	r.procBudget = newBudget("process events (fork, exec)", cfg.Budget.Processes, cfg.Budget.ProcessesMax, cfg.Budget.CmdlineBytes)
	r.tcpBudget = newBudget("new TCP connections", cfg.Budget.Connections, 0, 0)
	r.tcpBudget.noLite = true
	if cfg.MemoryGuard > 0 {
		over := func() bool { return r.heapNow() > uint64(cfg.MemoryGuard) }
		r.procBudget.pressure, r.tcpBudget.pressure = over, over
	}
	r.initSockets()
	r.hostNetNS = r.readHostNetNS()
	if r.cfg.FDFullEvery == 0 {
		r.cfg.FDFullEvery = 5
	}
	r.fdInterval = cfg.FDInterval
	if r.cfg.BudgetWindow == 0 {
		r.cfg.BudgetWindow = 5 * time.Minute
	}
	// Every entity table: ids must not repeat across runs (readers keep one
	// row per id). fds_held was left out of a hand-written list until
	// 2026-11-07, so its ids began at 1 in every run and collided.
	for _, t := range pqstore.EntityTables {
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
	sysname, release, version, machine := uname()
	osID, osVersion, osLike, osPretty := osRelease()
	for k, v := range map[string]string{
		"os_id": osID, "os_version_id": osVersion, "os_id_like": osLike, "os_pretty_name": osPretty,
		"uname_sysname": sysname, "uname_release": release, "uname_version": version, "uname_machine": machine,
		"schema_version": strconv.Itoa(store.SchemaVersion), "clifrd_version": cfg.Version,
		"machine_id": machineID(), "boot_id": bootID, "timezone": timeZone(), "tz_offset_s": strconv.Itoa(offset),
		"hostname": host, "mem_total_kb": strconv.FormatInt(memKB, 10),
		"boot_time": strconv.FormatInt(btime, 10), "boot_ms": strconv.FormatInt(r.boot, 10), "clk_tck": strconv.Itoa(procfs.ClockTicks), "page_kb": strconv.Itoa(os.Getpagesize() / 1024),
		"interval_s": fmt.Sprint(cfg.Interval.Seconds()), "fd_interval_s": fmt.Sprint(cfg.FDInterval.Seconds()),
		"flush_interval_s": fmt.Sprint(cfg.Parquet.FlushInterval.Seconds()),
		"sys_interval_s":   fmt.Sprint(min(cfg.SysInterval, cfg.Interval).Seconds()), "redact_patterns": strconv.Itoa(len(redact)),
		"proc_io": strconv.FormatBool(cfg.ProcIO),
	} {
		if err := db.SetMeta(k, v); err != nil {
			return nil, err
		}
	}
	if g, ok := uncleanStop(db, bootID, cfg.Parquet.FlushInterval); ok {
		logger.Warnf("unclean stop: %s", g.Detail)
		r.pending.Guard = append(r.pending.Guard, g)
	}
	if cfg.ProcRoot == "/proc" || cfg.ProcRoot == "" { // not with fixtures
		r.ioprioGet, r.schedGet = sysIOPrioGet, sysSchedGet
		if rows, g, ok := r.pstoreAtStart(db, bootID, defaultPstore); ok {
			logger.Warnf("%s", g.Detail)
			r.pending.Kmsg = append(r.pending.Kmsg, rows...)
			r.pending.Guard = append(r.pending.Guard, g)
		}
	}
	return r, nil
}

// pstoreAtStart: the previous boot's crash records, at the first run of a
// boot (pstore.go).
func (r *Recorder) pstoreAtStart(db any, bootID string, d pstoreDirs) ([]store.KmsgRow, store.GuardEvent, bool) {
	var prevBoot string
	var prevRunMS int64
	if s, ok := db.(interface {
		PrevRun() (pqstore.PrevRun, bool)
	}); ok {
		if p, ok := s.PrevRun(); ok {
			if p.BootID == bootID {
				return nil, store.GuardEvent{}, false // not the first run of this boot
			}
			prevBoot, prevRunMS = p.BootID, p.Run*1000
		}
	}
	return pstoreAtStart(d, prevBoot, prevRunMS, r.boot, time.Now())
}

// uncleanStop is an unclean_stop guard event when the run before this one
// ended without a clean stop: the machine went down (a crash, a power loss,
// a reset) when the boot changed, else clifrd itself was killed or crashed.
func uncleanStop(db any, bootID string, flush time.Duration) (store.GuardEvent, bool) {
	s, ok := db.(interface {
		PrevRun() (pqstore.PrevRun, bool)
	})
	if !ok {
		return store.GuardEvent{}, false
	}
	p, ok := s.PrevRun()
	if !ok || !p.Known || p.Clean {
		return store.GuardEvent{}, false
	}
	why := "clifrd was killed or crashed while the system kept running"
	if p.BootID != "" && bootID != "" && p.BootID != bootID {
		why = "the system went down without a clean shutdown (a crash, a power loss or a reset)"
	}
	last := "no sample on disk"
	if p.LastSampleMS > 0 {
		last = "last sample on disk at " + time.UnixMilli(p.LastSampleMS).Format("2006-01-02 15:04:05 MST")
	}
	if flush <= 0 {
		flush = 5 * time.Minute
	}
	return store.GuardEvent{TS: time.Now().UnixMilli(), Kind: "unclean_stop", Detail: fmt.Sprintf(
		"the previous run (started %s) ended without a clean stop: %s; %s (what came after it, up to %s, was lost)",
		time.Unix(p.Run, 0).Format("2006-01-02 15:04:05 MST"), why, last, flush)}, true
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

// openBackend opens the Parquet data directory.
func openBackend(cfg Config, logger *Logger) (store.Backend, error) {
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("no storage: set a data directory")
	}
	opt := cfg.Parquet
	if opt.Logf == nil {
		opt.Logf = logger.Warnf
	}
	if opt.Infof == nil {
		opt.Infof = logger.Printf
	}
	return pqstore.Open(cfg.DataDir, opt)
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
	netDone := make(chan struct{})
	if stop := r.startNet(netDone); stop != nil {
		defer stop()
		defer close(netDone)
	}
	kmsgDone := make(chan struct{})
	if stop := r.startKmsg(kmsgDone); stop != nil {
		defer stop()
		defer close(kmsgDone)
	}
	sessDone := make(chan struct{})
	if stop := r.startSessions(sessDone); stop != nil {
		defer stop()
		defer close(sessDone)
	}
	ueventsDone := make(chan struct{})
	if stop := r.startUevents(ueventsDone); stop != nil {
		defer stop()
		defer close(ueventsDone)
	}
	unitsDone := make(chan struct{})
	if stop := r.startUnits(unitsDone); stop != nil {
		defer stop()
		defer close(unitsDone)
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
	// System counters between samples when their interval is shorter; each
	// sample takes them too.
	sysEvery := r.cfg.SysInterval
	if sysEvery <= 0 || sysEvery >= r.cfg.Interval {
		sysEvery = 0
	}
	var nextSys time.Time
	for {
		if r.cfg.Duration > 0 && time.Since(start) >= r.cfg.Duration {
			break
		}
		for {
			d := time.Until(next)
			if d <= 0 {
				break
			}
			if r.tcp != nil || r.events != nil {
				d = min(d, tcpDrainEvery)
			}
			if sysEvery > 0 {
				d = max(min(d, time.Until(nextSys)), 0)
			}
			select {
			case <-ctx.Done():
				return r.shutdown()
			case <-time.After(d):
			}
			if r.tcp != nil && time.Until(next) > 0 {
				r.drainTCP()
			}
			if time.Until(next) > 0 {
				r.drainEvents()
			}
			// Not right before a sample, which reads them anyway.
			if sysEvery > 0 && !time.Now().Before(nextSys) && time.Until(next) > sysEvery/2 {
				r.sampleSystem(time.Now().UnixMilli(), &r.pending)
				for nextSys = nextSys.Add(sysEvery); !time.Now().Before(nextSys); nextSys = nextSys.Add(sysEvery) {
				}
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
		nextSys = now.Add(sysEvery)
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
		// Before flushTCP, which forgets what closed in the sample: a
		// deferred keyframe row would not find such a connection and be
		// adopted from the dump as a second one.
		r.resolveDeferred(b)
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

// RequestFlush asks the store to write what it holds at the next sample
// (clifrd on SIGUSR1). Safe from any goroutine.
func (r *Recorder) RequestFlush(reason string) {
	if f, ok := r.db.(interface{ RequestFlush(string) }); ok {
		f.RequestFlush(reason)
	}
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
	if r.net != nil {
		addrs, routing := r.net.take()
		b.Addrs, b.Routing = append(b.Addrs, addrs...), append(b.Routing, routing...)
	}
	if r.kmsg != nil {
		b.Kmsg = append(b.Kmsg, r.kmsg.take()...)
	}
	if r.units != nil {
		b.Units = append(b.Units, r.units.take()...)
	}
	if r.mounts != nil {
		// at ts, as the hourly usage rows: df takes a mount's usage only
		// from the time the table shows it
		r.mounts.refresh(ts)
		b.Mounts = append(b.Mounts, r.mounts.take()...)
		b.FSSamples = append(b.FSSamples, r.fsUsage.take()...)
		b.Guard = append(b.Guard, r.fsUsage.takeGuard()...)
		r.fsUsage.start(ts, r.mounts.table(), r.log)
	}
	if r.events != nil {
		b.Stats = append(b.Stats, r.events.stats(ts)...)
		b.Stats = append(b.Stats, r.procBudget.statRows(ts, "process_events")...)
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
		r.resolveDeferred(&b) // the last keyframe's rows the events had not explained yet
		if keyframe {
			r.keyframe(&b)
		}
		r.flushTCP(ts, &b)
		b.Stats = append(b.Stats, r.tcp.stats(ts)...)
		b.Stats = append(b.Stats, r.tcpBudget.statRows(ts, "tcp_conns")...)
		b.Guard = append(b.Guard, r.tcp.missedGuard(ts)...)
		r.afterFlood("tcp", r.tcpBudget.report(ts, "tcp"), &b)
		if n := r.tcp.overflowed(); n > r.tcpOverflowReported {
			b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "events_lost",
				Detail: fmt.Sprintf("TCP event queue full (%d events): %d TCP events dropped", tcpQueueCap, n-r.tcpOverflowReported)})
			r.tcpOverflowReported = n
		}
		durSock += time.Since(t1)
	}
	r.sweepOwners(ts, &b)
	r.dropClosedProcs()

	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	cpuUS := ru.Utime.Sec*1e6 + int64(ru.Utime.Usec) + ru.Stime.Sec*1e6 + int64(ru.Stime.Usec)
	r.fdWalkUS += durFD.Microseconds()
	// The store's compaction and retention run on a thread of their own at
	// the lowest priority, an hour's files at a time (1-3 s of CPU at once):
	// not what the guard rail can lower by walking fds less often.
	var maintUS int64
	if m, ok := r.db.(interface{ MaintenanceCPUUS() int64 }); ok {
		maintUS = m.MaintenanceCPUUS()
		if d := maintUS - r.lastMaintUS; d >= 1000 {
			b.Stats = append(b.Stats, store.StatRow{TS: ts, Source: "maintenance_cpu_ms", Events: d / 1000})
			r.lastMaintUS += d / 1000 * 1000
		}
	}
	if n := r.cmdlineCut.Load(); n > r.lastCmdlineCut {
		b.Stats = append(b.Stats, store.StatRow{TS: ts, Source: "cmdline_cut", Events: n - r.lastCmdlineCut})
		r.lastCmdlineCut = n
	}
	r.checkBudget(now, cpuUS-maintUS, r.fdWalkUS, &b)
	r.checkMemory(now, &b)

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
	if r.cfg.Metrics {
		r.metricsSample(&b)
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
		ticks := int64(st.Utime + st.Stime)
		e := r.procs[key]
		// What changes only while a process runs is re-read when it used
		// CPU since its last sample, when it is new and on fd-walk samples;
		// otherwise the previous values stand (cumulative counters: a
		// skipped read only delays an update).
		fresh := e == nil || refresh || !e.hasSamp || ticks != e.sample.CPUTicks
		var status procfs.Status
		haveStatus := false
		if fresh {
			var err error
			status, err = r.fs.ReadStatus(pid)
			haveStatus = err == nil
		}
		if e == nil {
			if !haveStatus {
				continue
			}
			e = r.newProc(key, st, status, ts, b)
			if e == nil {
				continue
			}
		} else if refresh {
			r.refreshProc(e, st, status, haveStatus, ts, b)
		} else if st.Comm != e.upd.Comm || st.PPID != e.upd.PPID {
			// A rename (prctl PR_SET_NAME, as browsers do for their
			// processes) or a reparenting: both are in stat, read anyway.
			u := e.upd
			u.Comm, u.PPID = st.Comm, st.PPID
			e.upd = u
			b.ProcUpdates = append(b.ProcUpdates, u)
		}
		e.gen = r.gen
		e.last = ts
		n++
		rss, shr := st.RSS, int64(0)
		if _, res, sh, err := r.fs.ReadStatm(pid); err == nil {
			rss, shr = res, sh
		}
		s := store.ProcSample{ProcID: e.id, TS: ts, State: string(st.State), Nice: st.Nice, TPGID: st.TPGID,
			CPUTicks: ticks, RSSKB: rss * int64(pageKB),
			VSZKB: int64(st.VSize / 1024), Threads: st.NumThreads,
			MinFlt: int64(st.MinFlt), MajFlt: int64(st.MajFlt), ShrKB: shr * int64(pageKB),
			Priority: st.Priority, Policy: st.Policy, RTPriority: st.RTPriority, CPU: st.Processor,
			PSFlags: int(st.Flags>>6) & 7, STimeTicks: int64(st.Stime), GuestTicks: int64(st.GuestTime),
			BlkioTicks: int64(st.BlkioTicks), RSSStatKB: st.RSS * int64(pageKB), IOPrio: r.ioprioOf(pid, st.Nice, st.Policy)}
		r.sampleRun(e, &s, fresh, status, haveStatus)
		// Unchanged values are written again in every UTC hour: retention
		// would otherwise delete an idle process's only row.
		if !e.hasSamp || !sameProcSample(e.sample, s) || store.OtherHour(e.sample.TS, ts) {
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

func (r *Recorder) newProc(key procKey, st procfs.Stat, status procfs.Status, ts int64, b *store.Batch) *procEntry {
	cmd, argv0, pad, err := r.readCmdlinePad(key.pid)
	if err != nil {
		return nil
	}
	label, cgroup, netns := r.readLabel(key.pid, ""), r.readCgroup(key.pid, ""), r.readNetNS(key.pid, 0)
	r.noteCgroup(cgroup, ts, b)
	e := &procEntry{id: r.nextID("processes"), key: key, first: ts,
		upd: store.ProcUpdate{UID: status.UID, RUID: status.RUID, RGID: status.RGID, CmdlinePad: pad, PPID: st.PPID, Comm: st.Comm, Cmdline: cmd, Argv0Len: argv0, Source: "sample",
			Label: label, Cgroup: cgroup, NetNS: netns}}
	e.upd.ID = e.id
	// Adopt a process first seen through a fork/exec event: it existed
	// since its start time, not just since this sample.
	row := store.ProcRow{ID: e.id, PID: key.pid, StartTime: key.start,
		PPID: st.PPID, UID: status.UID, RUID: status.RUID, RGID: status.RGID, CmdlinePad: pad, Comm: st.Comm, Cmdline: cmd, Argv0Len: argv0, TTY: st.TTY, SID: st.Session,
		PGRP: st.PGRP, Locked: status.VmLckK > 0, Source: "sample", Label: label, Cgroup: cgroup, NetNS: netns}
	if ep := r.evProcs[key]; ep != nil {
		if cmd == "" && ep.ev.attrs.Cmdline != "" {
			// Seen first as a zombie: its exec event has the command line.
			cmd, argv0 = ep.ev.attrs.Cmdline, ep.ev.attrs.Argv0Len
			e.upd.Cmdline, row.Cmdline = cmd, cmd
			e.upd.Argv0Len, row.Argv0Len = argv0, argv0
		}
		e.first, e.exit = key.start, ep.exit
		e.upd.Exe, e.upd.ExecTS = ep.ev.attrs.Exe, ep.ev.attrs.ExecTS
		row.Exe, row.ExitCode, row.Signal, row.Killer, row.OOMKilled = ep.ev.attrs.Exe, ep.exitCode, ep.signal, ep.killer, ep.oom
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
// setproctitle, uid via setuid, ppid via reparenting, the cgroup when a
// process is moved, the label). It runs on fd-walk samples only, to keep the
// per-interval cost low.
func (r *Recorder) refreshProc(e *procEntry, st procfs.Stat, status procfs.Status, haveStatus bool, ts int64, b *store.Batch) {
	u := e.upd
	u.PPID, u.Comm = st.PPID, st.Comm
	if haveStatus {
		u.UID, u.RUID, u.RGID = status.UID, status.RUID, status.RGID
	}
	// (The network namespace is read when first sampled and at an exec only:
	// a readlink per process per fd walk was 20-50 ms of every walk with
	// 2,000-10,000 processes, benchmark 20261109-0031.)
	u.Label, u.Cgroup = r.readLabel(e.key.pid, u.Label), r.readCgroup(e.key.pid, u.Cgroup)
	r.noteCgroup(u.Cgroup, ts, b)
	// A zombie's cmdline reads as empty; keep the command line it had (ps
	// shows zombies as "[comm] <defunct>" from the state anyway).
	if cmd, argv0, pad, err := r.readCmdlinePad(e.key.pid); err == nil && cmd != "" {
		u.Cmdline, u.Argv0Len, u.CmdlinePad = cmd, argv0, pad
	}
	if u != e.upd {
		e.upd = u
		b.ProcUpdates = append(b.ProcUpdates, u)
	}
}

// sampleRun fills what changes only while the process runs: context
// switches (from status), wchan, the run-queue wait and the I/O counters (/proc/<pid>/io), read
// when fresh, else the previous sample's.
func (r *Recorder) sampleRun(e *procEntry, s *store.ProcSample, fresh bool, status procfs.Status, haveStatus bool) {
	p := e.sample
	if !fresh {
		s.VolCtx, s.NonVolCtx, s.Wchan, s.WaitNS, s.RunDelayNS = p.VolCtx, p.NonVolCtx, p.Wchan, p.WaitNS, p.RunDelayNS
		s.VmStkKB, s.VmSwapKB, s.VmDataKB, s.VmExeKB, s.VmLibKB, s.VmLckKB = p.VmStkKB, p.VmSwapKB, p.VmDataKB, p.VmExeKB, p.VmLibKB, p.VmLckKB
		s.BlkioAllTicks, s.VolCtxAll, s.NonVolCtxAll = p.BlkioAllTicks, p.VolCtxAll, p.NonVolCtxAll
		s.ThrRun, s.ThrSleepI, s.ThrSleepU, s.ThrIdle = p.ThrRun, p.ThrSleepI, p.ThrSleepU, p.ThrIdle
		s.IOPrioDif = p.IOPrioDif
		s.RChar, s.WChar, s.ReadBytes, s.WriteBytes, s.CancelledWrite = p.RChar, p.WChar, p.ReadBytes, p.WriteBytes, p.CancelledWrite
		return
	}
	if haveStatus {
		s.VolCtx, s.NonVolCtx = status.VolCtx, status.NonVolCtx
		s.VmStkKB, s.VmSwapKB, s.VmDataKB, s.VmExeKB, s.VmLibKB, s.VmLckKB =
			status.VmStkK, status.VmSwapK, status.VmDataK, status.VmExeK, status.VmLibK, status.VmLckK
	}
	if w, err := r.fs.ReadWchan(e.key.pid); err == nil {
		s.Wchan = w
	}
	if ns, err := r.fs.ReadRunDelay(e.key.pid); err == nil {
		s.WaitNS, s.RunDelayNS = ns, ns
	}
	// atop's sums over all threads: a single-threaded process's own values;
	// a multi-threaded one's from each thread (the process's own schedstat,
	// stat delay and status switches are its main thread's).
	s.BlkioAllTicks, s.VolCtxAll, s.NonVolCtxAll = s.BlkioTicks, s.VolCtx, s.NonVolCtx
	s.ThrRun, s.ThrSleepI, s.ThrSleepU, s.ThrIdle = 0, 0, 0, 0
	s.IOPrioDif = 0
	switch s.State {
	case "R":
		s.ThrRun = 1
	case "S":
		s.ThrSleepI = 1
	case "D":
		s.ThrSleepU = 1
	case "I":
		s.ThrIdle = 1
	}
	if s.Threads > 1 {
		if th, err := r.fs.ReadThreads(e.key.pid); err == nil {
			s.RunDelayNS, s.BlkioAllTicks, s.VolCtxAll, s.NonVolCtxAll = th.RunDelayNS, th.BlkioTicks, th.VolCtx, th.NonVolCtx
			s.ThrRun, s.ThrSleepI, s.ThrSleepU, s.ThrIdle = th.Run, th.SleepI, th.SleepU, th.Idle
			s.IOPrioDif = r.ioprioDif(th.Prio)
		}
	}
	if !r.cfg.ProcIO {
		return
	}
	if io, err := r.fs.ReadIO(e.key.pid); err == nil {
		s.RChar, s.WChar, s.ReadBytes, s.WriteBytes, s.CancelledWrite = io.RChar, io.WChar, io.ReadBytes, io.WriteBytes, io.CancelledWrite
	}
}

// readLabel and readCgroup return the process's security label and cgroup,
// or old when they cannot be read (gone, or no security module).
func (r *Recorder) readLabel(pid int, old string) string {
	if l, err := r.fs.ReadLabel(pid); err == nil {
		return l
	}
	return old
}

// readNetNS returns the process's network namespace, 0 for the host's, or
// old when it cannot be read (one readlink: when the process is first
// sampled and at an exec).
func (r *Recorder) readNetNS(pid int, old uint32) uint32 {
	n, err := r.fs.ReadNetNS(pid)
	if err != nil {
		return old
	}
	return r.netnsID(n)
}

// netnsID is how a namespace is written: 0 for the host's.
func (r *Recorder) netnsID(n uint32) uint32 {
	if n == r.hostNetNS {
		return 0
	}
	return n
}

// readHostNetNS is init's network namespace (the host's), else clifrd's own.
func (r *Recorder) readHostNetNS() uint32 {
	if n, err := r.fs.ReadNetNS(1); err == nil {
		return n
	}
	if n, err := procfs.New("/proc").ReadNetNS(os.Getpid()); err == nil {
		return n
	}
	return 0
}

func (r *Recorder) readCgroup(pid int, old string) string {
	if c, err := r.fs.ReadCgroup(pid); err == nil {
		return c
	}
	return old
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

// osRelease is the distribution from /etc/os-release (or /usr/lib/os-release):
// ID, VERSION_ID, ID_LIKE and PRETTY_NAME, unquoted; "" if unknown. clifr
// prints the tools' output as that distribution's versions of them do.
func osRelease() (id, version, like, pretty string) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		if b, err = os.ReadFile("/usr/lib/os-release"); err != nil {
			return
		}
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		case "ID_LIKE":
			like = v
		case "PRETTY_NAME":
			pretty = v
		}
	}
	return
}

// uname is the kernel's identity as uname -s, -r, -v and -m print it.
func uname() (sysname, release, version, machine string) {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return
	}
	return unix.ByteSliceToString(u.Sysname[:]), unix.ByteSliceToString(u.Release[:]),
		unix.ByteSliceToString(u.Version[:]), unix.ByteSliceToString(u.Machine[:])
}

// timeZone is the host's time zone name (e.g. Europe/Berlin): $TZ, the
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
