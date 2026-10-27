package recorder

import (
	"cmp"
	"fmt"
	"runtime/metrics"
	"slices"
	"time"

	"clifr/internal/store"
)

// maxFDInterval caps how far the CPU budget guard stretches --fd-interval.
const maxFDInterval = time.Hour

// minFDShare: the guard lengthens the fd-walk interval only while the walks
// are at least this share of the recorder's CPU. Below it, walking less often
// would cost open-file data without bringing the recorder near its budget.
const minFDShare = 0.25

type cpuPoint struct {
	t     time.Time
	cpuUS int64
	fdUS  int64
}

// checkBudget is the CPU guard rail. When the recorder's own CPU over the
// last budget window (without the store's maintenance, which runs on idle
// CPU) exceeds --cpu-budget of one core and the fd walks are a real share of
// it (minFDShare), it doubles the fd-walk interval and records
// a guard event; the window then restarts so the effect is measured before
// acting again. When the walks are not what costs the CPU, or the interval is
// at its cap, it leaves the interval alone and reports that once per period
// over budget. fdUS is the time spent in fd walks so far (wall time of the
// sampling goroutine, so an upper bound of their CPU). It runs once per sample.
func (r *Recorder) checkBudget(now time.Time, cpuUS, fdUS int64, b *store.Batch) {
	if r.cfg.CPUBudget <= 0 {
		return
	}
	r.cpuHist = append(r.cpuHist, cpuPoint{now, cpuUS, fdUS})
	window := r.cfg.BudgetWindow
	// Keep the newest point that is at least `window` old as the baseline.
	for len(r.cpuHist) > 1 && now.Sub(r.cpuHist[1].t) >= window {
		r.cpuHist = r.cpuHist[1:]
	}
	base := r.cpuHist[0]
	span := now.Sub(base.t)
	if span < window {
		return // not a full window of data yet
	}
	used := float64(cpuUS-base.cpuUS) / float64(span.Microseconds())
	if used <= r.cfg.CPUBudget {
		r.budgetExhausted = false
		return
	}
	fdShare := 0.0
	if cpuUS > base.cpuUS {
		fdShare = min(float64(fdUS-base.fdUS)/float64(cpuUS-base.cpuUS), 1)
	}
	ts := now.UnixMilli()
	switch {
	case fdShare >= minFDShare && r.fdInterval < maxFDInterval:
		old := r.fdInterval
		r.fdInterval = min(2*old, maxFDInterval)
		b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "fd_interval_up",
			Detail: fmt.Sprintf("recorder CPU %.2f%% of one core over the last %s exceeds the %.2f%% budget, fd walks are %.0f%% of it: fd-interval %s -> %s",
				100*used, window, 100*r.cfg.CPUBudget, 100*fdShare, old, r.fdInterval)})
		r.log.Warnf("cpu budget: %.2f%% > %.2f%%, fd walks %.0f%% of it, fd-interval %s -> %s",
			100*used, 100*r.cfg.CPUBudget, 100*fdShare, old, r.fdInterval)
		r.budgetExhausted = false
	case r.budgetExhausted:
		return // already reported; keep the window rolling
	case fdShare < minFDShare:
		r.budgetExhausted = true
		b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "budget_exceeded",
			Detail: fmt.Sprintf("recorder CPU %.2f%% of one core over the last %s exceeds the %.2f%% budget; fd walks are %.0f%% of it, "+
				"so fd-interval stays at %s (events, process sampling and storage cost more than the budget)",
				100*used, window, 100*r.cfg.CPUBudget, 100*fdShare, r.fdInterval)})
		r.log.Warnf("cpu budget exceeded: %.2f%% > %.2f%%, fd walks only %.0f%% of it, fd-interval stays at %s",
			100*used, 100*r.cfg.CPUBudget, 100*fdShare, r.fdInterval)
	default:
		r.budgetExhausted = true
		b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "budget_exceeded",
			Detail: fmt.Sprintf("recorder CPU %.2f%% of one core exceeds the %.2f%% budget with fd-interval already at %s",
				100*used, 100*r.cfg.CPUBudget, r.fdInterval)})
		r.log.Warnf("cpu budget exceeded with fd-interval at its maximum %s", r.fdInterval)
	}
	r.cpuHist = []cpuPoint{{now, cpuUS, fdUS}}
}

// shedCmdline: while the memory guard sheds, command lines read are cut
// to this many bytes (at most --max-cmdline).
const shedCmdline = 4096

// liveHeap is the Go heap still in use after the last collection.
func liveHeap() uint64 {
	s := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return s[0].Value.Uint64()
}

// checkMemory is the memory guard rail. Any user can make the recorder hold
// more: processes with long command lines, or many fds on long paths. When
// the live heap exceeds --memory-guard it records a guard event, cuts the
// command lines it reads to shedCmdline bytes and stops tracking the open
// files of the processes that hold the most, until half of all tracked
// entries are gone (their last walk is their last_seen); if the heap is still
// above the guard a budget window later, it drops half again. Below 3/4 of
// the guard command lines are read up to --max-cmdline again; processes
// whose files were dropped stay untracked until they exit. Without it the
// unit's MemoryMax kills the recorder, which restarts into the same state.
// It runs once per sample.
func (r *Recorder) checkMemory(now time.Time, b *store.Batch) {
	guard := uint64(r.cfg.MemoryGuard)
	if guard == 0 {
		return
	}
	live := r.heapLive()
	ts := now.UnixMilli()
	switch {
	case live > guard && (!r.memShed || now.Sub(r.memShedAt) >= r.cfg.BudgetWindow):
		first := !r.memShed
		r.memShed, r.memShedAt = true, now
		r.cmdlineShed.Store(true)
		procs, entries, top := r.shedFiles(b)
		detail := fmt.Sprintf("recorder live heap %d MiB exceeds the %d MiB memory guard: command lines cut at %d bytes; open files no longer tracked: %d processes, %d entries%s",
			live>>20, guard>>20, min(shedCmdline, r.maxCmdline()), procs, entries, top)
		if !first {
			detail = "still " + detail
		}
		b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "memory_shed", Detail: detail})
		r.log.Warnf("memory guard: %s", detail)
	case r.memShed && live < guard/4*3:
		r.memShed = false
		r.cmdlineShed.Store(false)
		detail := fmt.Sprintf("recorder live heap %d MiB below 3/4 of the %d MiB memory guard: command lines read up to --max-cmdline again",
			live>>20, guard>>20)
		b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "memory_ok", Detail: detail})
		r.log.Printf("memory guard: %s", detail)
	}
}

// maxCmdline is how many bytes of a command line are read now.
func (r *Recorder) maxCmdline() int {
	if r.cmdlineShed.Load() && (r.cfg.MaxCmdline == 0 || r.cfg.MaxCmdline > shedCmdline) {
		return shedCmdline
	}
	return r.cfg.MaxCmdline
}

// shedFiles stops tracking the open files of the processes with the most
// entries until at least half of all entries are dropped. It returns the
// processes and entries dropped, and the largest as " (most: pid N (comm)
// with M)".
func (r *Recorder) shedFiles(b *store.Batch) (procs, entries int, top string) {
	var list []*procEntry
	total := 0
	for _, p := range r.procs {
		if len(p.files) > 0 {
			list = append(list, p)
			total += len(p.files)
		}
	}
	slices.SortFunc(list, func(x, y *procEntry) int { return cmp.Compare(len(y.files), len(x.files)) })
	for _, p := range list {
		if 2*entries >= total {
			break
		}
		if procs == 0 {
			top = fmt.Sprintf(" (most: pid %d (%s) with %d)", p.key.pid, p.upd.Comm, len(p.files))
		}
		entries += len(p.files)
		procs++
		r.closeFiles(p, b)
		p.noFiles = true
	}
	return procs, entries, top
}
