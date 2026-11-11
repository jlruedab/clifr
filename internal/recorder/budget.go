package recorder

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"clifr/internal/store"
)

// The event budget bounds what a flood of events costs the recorder. Any
// user can start ten thousand processes or thirty thousand TCP connections a
// second (measured in a 4-CPU VM, 2026-11-11); recorded in full, each
// carries a /proc read and its command line, and before the budget such a
// flood took clifrd past its unit's MemoryMax within 20 seconds (OOM-killed,
// losing the minutes not yet written).
//
// Events are counted in windows of budgetWindow. Within a window:
//
//   - processes: the first Processes per second (fork and exec events),
//     while their command lines add up to at most CmdlineBytes per second,
//     are recorded in full; then, up to ProcessesMax per second, without
//     /proc reads and with the command line cut to liteCmdline bytes (the
//     part the eBPF event carries; the proc connector gives none); beyond,
//     only counted. A process is kept or dropped whole: one born while
//     events were only counted has its exec and exit dropped too.
//   - TCP: the first Connections new connections per second are recorded;
//     beyond, only counted, and every later event of such a connection is
//     dropped. Listening sockets are always recorded. A dropped connection
//     still open at a keyframe is adopted from it.
//
// Each sample with events above a budget writes an events_shed guard event
// with the counts and the users, commands and addresses that caused them,
// so the flood itself is recorded.
type EventBudget struct {
	Processes    int   // process events (fork, exec) a second recorded in full (0: no limit)
	ProcessesMax int   // process events a second recorded at all (0: no limit)
	CmdlineBytes int64 // command-line bytes a second recorded in full (0: no limit)
	Connections  int   // new TCP connections a second recorded (0: no limit)
}

// DefaultEventBudget (see README "Event budget" for the reasoning):
// processes: 4,000 events a second in full (2,000 commands, a fork and an
// exec each: 8 times the heaviest benchmark profile, "extreme", and above a
// parallel build's rate), 10,000 at most (the queue of one 30 s sample
// interval then stays near 170 MB in the worst case: a process is three
// queued events of 264 bytes, plus its command line); 1 MiB/s of command
// lines in full (any user can pass 64 KiB of arguments to every process);
// TCP: 5,000 new connections a second (twice "extreme").
var DefaultEventBudget = EventBudget{Processes: 4000, ProcessesMax: 10000, CmdlineBytes: 1 << 20, Connections: 5000}

const (
	budgetWindow = 10 * time.Second
	liteCmdline  = 256 // bytes of a command line kept above the full budget
	budgetTopMax = 10000
	// shedMemory: how long the times when processes were only counted are
	// remembered, to drop the exits of processes born then.
	shedMemory = time.Hour
	// pressureEvery: how often the readers look at the heap size (a
	// runtime/metrics read; events arrive tens of thousands a second).
	pressureEvery = 100 * time.Millisecond
)

type tier uint8

const (
	tierFull tier = iota
	tierLite
	tierShed
)

// budget counts one kind of event against its limits. Safe for the reader
// goroutine (decide, note) and the sampling one (report, shedBorn).
type budget struct {
	mu        sync.Mutex
	what      string // "process events (fork, exec)" or "new TCP connections"
	full, max int64  // events per window (0: no limit)
	bytesFull int64  // bytes per window (0: no limit)
	noLite    bool   // above full, only counted (TCP: no middle tier)
	// pressure reports the memory guard's state: while the heap is above
	// it, new processes and connections are only counted whatever the
	// rate (checked at most every pressureEvery).
	pressure            func() bool
	pressureAt          time.Time
	pressured           bool
	nPressure, totPress int64

	winStart time.Time
	n, bytes int64

	// Since the last report.
	since                  time.Time
	nFull, nLite, nShed    int64
	top                    map[string]int64
	totLite, totShed, drop int64 // cumulative (recorder_stats)
	reported               [3]int64

	ranges [][2]int64 // wall ms when events were only counted (processes)
}

func newBudget(what string, perSec, maxPerSec int, bytesPerSec int64) *budget {
	w := int64(budgetWindow / time.Second)
	return &budget{what: what, full: int64(perSec) * w, max: int64(maxPerSec) * w, bytesFull: bytesPerSec * w,
		top: map[string]int64{}}
}

// decide counts one event of size bytes arriving at now and returns its tier.
// whole: the event belongs to something already recorded (an exec of a
// process recorded at its fork), so it is at worst lite, never dropped.
func (b *budget) decide(now time.Time, bytes int64, whole ...bool) tier {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Sub(b.winStart) >= budgetWindow || now.Before(b.winStart) {
		b.winStart, b.n, b.bytes = now, 0, 0
	}
	if b.since.IsZero() {
		b.since = now
	}
	b.n++
	if b.pressure != nil && now.Sub(b.pressureAt) >= pressureEvery {
		b.pressureAt, b.pressured = now, b.pressure()
	}
	t := tierFull
	switch {
	case b.pressured:
		t = tierShed
	case b.max > 0 && b.n > b.max:
		t = tierShed
	case b.full > 0 && b.n > b.full, b.bytesFull > 0 && b.bytes+bytes > b.bytesFull:
		t = tierLite
		if b.noLite {
			t = tierShed
		}
	default:
		b.bytes += bytes
	}
	if t == tierShed && len(whole) > 0 && whole[0] {
		t = tierLite
	}
	if t == tierShed && b.pressured {
		b.nPressure++
		b.totPress++
	}
	switch t {
	case tierFull:
		b.nFull++
	case tierLite:
		b.nLite++
		b.totLite++
	case tierShed:
		b.nShed++
		b.totShed++
		ms := now.UnixMilli()
		if n := len(b.ranges); n > 0 && ms-b.ranges[n-1][1] <= budgetWindow.Milliseconds() {
			b.ranges[n-1][1] = ms
		} else {
			b.ranges = append(b.ranges, [2]int64{ms, ms})
		}
	}
	return t
}

// note adds an event above the full budget to the report's top list.
func (b *budget) note(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.top[key]; !ok && len(b.top) >= budgetTopMax {
		key = "others"
	}
	b.top[key]++
}

// dropped counts an event dropped because its connection or process was
// (a later event of it; or one a full queue could not take).
func (b *budget) dropped(n int64) {
	b.mu.Lock()
	b.drop += n
	b.mu.Unlock()
}

// shedBorn reports whether a process started at startMS (wall ms, from its
// start time in clock ticks) was born while process events were only
// counted: its fork was dropped, so its exec and exit are too.
func (b *budget) shedBorn(startMS int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, r := range b.ranges {
		if startMS >= r[0]-10 && startMS <= r[1] { // start times have 10 ms ticks
			return true
		}
	}
	return false
}

// report returns the guard event for the events above the budget since the
// last call (none if there were none) and forgets ranges older than
// shedMemory.
func (b *budget) report(ts int64, kind string) []store.GuardEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.ranges) > 0 && b.ranges[0][1] < ts-shedMemory.Milliseconds() {
		b.ranges = b.ranges[1:]
	}
	if b.nLite == 0 && b.nShed == 0 {
		b.since, b.nFull = time.Time{}, 0
		return nil
	}
	var parts []string
	if b.nShed > 0 {
		parts = append(parts, fmt.Sprintf("%d only counted", b.nShed))
	}
	if b.nLite > 0 {
		parts = append(parts, fmt.Sprintf("%d without /proc reads, command lines cut to %d bytes", b.nLite, liteCmdline))
	}
	d := fmt.Sprintf("%s: %s of %d %s since %s (budget: %s)", kind, strings.Join(parts, ", "),
		b.nFull+b.nLite+b.nShed, b.what, b.since.Format("15:04:05"), b.limits())
	if b.nPressure > 0 {
		d += fmt.Sprintf("; %d of those only counted because the recorder's heap was above the memory guard", b.nPressure)
	}
	type kv struct {
		k string
		n int64
	}
	var top []kv
	for k, n := range b.top {
		top = append(top, kv{k, n})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].n > top[j].n || top[i].n == top[j].n && top[i].k < top[j].k })
	if len(top) > 0 {
		var t []string
		for _, x := range top[:min(len(top), 5)] {
			t = append(t, fmt.Sprintf("%s %d", x.k, x.n))
		}
		d += "; most from: " + strings.Join(t, ", ")
	}
	b.since, b.nFull, b.nLite, b.nShed, b.nPressure, b.top = time.Time{}, 0, 0, 0, 0, map[string]int64{}
	return []store.GuardEvent{{TS: ts, Kind: "events_shed", Detail: d}}
}

func (b *budget) limits() string {
	w := int64(budgetWindow / time.Second)
	var l []string
	if b.full > 0 && b.noLite {
		l = append(l, fmt.Sprintf("%d/s recorded", b.full/w))
	} else if b.full > 0 {
		l = append(l, fmt.Sprintf("%d/s in full", b.full/w))
	}
	if b.bytesFull > 0 {
		l = append(l, fmt.Sprintf("%d KiB/s of command lines", b.bytesFull/w>>10))
	}
	if b.max > 0 {
		l = append(l, fmt.Sprintf("%d/s at most", b.max/w))
	}
	return strings.Join(l, ", ")
}

// statRows returns recorder_stats rows for the events above the budget since
// the last call: PREFIX_lite (recorded without detail), PREFIX_shed (only
// counted) and PREFIX_dropped (later events of those, dropped with them).
// Nothing while there were none.
func (b *budget) statRows(ts int64, prefix string) []store.StatRow {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := [3]int64{b.totLite, b.totShed, b.drop}
	var out []store.StatRow
	for i, name := range []string{"_lite", "_shed", "_dropped"} {
		if d := now[i] - b.reported[i]; d > 0 {
			out = append(out, store.StatRow{TS: ts, Source: prefix + name, Events: d})
		}
	}
	b.reported = now
	return out
}

// cutCmdline cuts a command line to liteCmdline bytes (argv0Len kept within).
// The cut is a copy: a substring would keep the whole original alive (the
// first flood with the budget held 214 MB of 1 KiB command lines that way).
// Redaction runs before it: a cut first could leave half a secret unmasked.
func cutCmdline(cmd string, argv0Len int) (string, int) {
	if len(cmd) <= liteCmdline {
		return cmd, argv0Len
	}
	return strings.Clone(cmd[:liteCmdline]), min(argv0Len, liteCmdline)
}

// afterFlood adds a budget report to b and, at the first sample without one
// after a flood, returns the freed memory to the system: Go keeps it
// otherwise (the recorder stayed at 536 MiB idle after a test flood).
func (r *Recorder) afterFlood(kind string, report []store.GuardEvent, b *store.Batch) {
	b.Guard = append(b.Guard, report...)
	was := r.flooded["processes"] || r.flooded["tcp"]
	r.flooded[kind] = len(report) > 0
	r.flooding.Store(r.flooded["processes"] || r.flooded["tcp"])
	if was && !r.flooded["processes"] && !r.flooded["tcp"] {
		freeOSMemory()
	}
}

// storeBusy tells the store's maintenance to put off compaction: during a
// flood, or while the heap is above half the memory guard.
func (r *Recorder) storeBusy() bool {
	return r.flooding.Load() || r.cfg.MemoryGuard > 0 && r.heapNow() > uint64(r.cfg.MemoryGuard)/2
}
