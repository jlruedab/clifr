package recorder

import (
	"fmt"
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
