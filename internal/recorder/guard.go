package recorder

import (
	"fmt"
	"time"

	"sosv/internal/store"
)

// maxFDInterval caps how far the CPU budget guard stretches --fd-interval.
const maxFDInterval = time.Hour

type cpuPoint struct {
	t     time.Time
	cpuUS int64
}

// checkBudget is the CPU guard rail. When the recorder's own CPU over the
// last budget window exceeds --cpu-budget of one core, it doubles the
// fd-walk interval (the fd walk is the expensive part) and records a guard
// event. The window then restarts so the effect is measured before acting
// again. It runs once per sample.
func (r *Recorder) checkBudget(now time.Time, cpuUS int64, b *store.Batch) {
	if r.cfg.CPUBudget <= 0 {
		return
	}
	r.cpuHist = append(r.cpuHist, cpuPoint{now, cpuUS})
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
		return
	}
	ts := now.UnixMilli()
	switch {
	case r.fdInterval < maxFDInterval:
		old := r.fdInterval
		r.fdInterval = min(2*old, maxFDInterval)
		b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "fd_interval_up",
			Detail: fmt.Sprintf("recorder CPU %.2f%% of one core over the last %s exceeds the %.2f%% budget: fd-interval %s -> %s",
				100*used, window, 100*r.cfg.CPUBudget, old, r.fdInterval)})
		r.log.Printf("cpu budget: %.2f%% > %.2f%%, fd-interval %s -> %s", 100*used, 100*r.cfg.CPUBudget, old, r.fdInterval)
	case !r.budgetExhausted:
		r.budgetExhausted = true
		b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "budget_exceeded",
			Detail: fmt.Sprintf("recorder CPU %.2f%% of one core exceeds the %.2f%% budget with fd-interval already at %s; "+
				"process and socket sampling alone costs more than the budget (consider a longer --interval)",
				100*used, 100*r.cfg.CPUBudget, r.fdInterval)})
		r.log.Printf("cpu budget exceeded with fd-interval at its maximum %s", r.fdInterval)
	}
	r.cpuHist = []cpuPoint{{now, cpuUS}}
}
