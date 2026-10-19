package main

import (
	"fmt"
	"math"
	"path/filepath"
)

// validate lists metrics that are missing or implausible. A report built
// from such data would show blanks or nonsense (the 26.04 batch showed "—"
// for all recorder costs and 10 B/h for atop), so the report refuses to be
// written and the bench scripts stop at the first bad run.
func (r *Report) validate() []string {
	var p []string
	bad := func(where, format string, args ...any) {
		p = append(p, where+": "+fmt.Sprintf(format, args...))
	}
	// need: v must be a number within [lo, hi].
	need := func(where, name string, v, lo, hi float64) {
		switch {
		case math.IsNaN(v) || math.IsInf(v, 0):
			bad(where, "%s is missing", name)
		case v < lo || v > hi:
			bad(where, "%s = %g, outside the plausible range [%g, %g]", name, v, lo, hi)
		}
	}
	const kib = 1024.0
	for _, m := range r.Matrix {
		cpus := num(m.Env["cpus"])
		need(m.Dir, "machine.env cpus", cpus, 1, 4096)
		if len(m.Runs) == 0 {
			bad(m.Dir, "no successful runs")
		}
		for _, run := range m.Runs {
			w := filepath.Base(m.Dir) + "/" + run.ID
			if run.To-run.From < 10_000 {
				bad(w, "measured window is %d ms", run.To-run.From)
			}
			x := run.M
			need(w, "pgbench TPS", x["tps"], 1, math.Inf(1))
			need(w, "average latency (ms)", x["lat_avg_ms"], 1e-6, 60_000)
			need(w, "p99 latency (ms)", x["lat_p99_ms"], 1e-6, 60_000)
			need(w, "machine CPU busy (%)", x["sys_busy"], 0.01, 100)
			need(w, "CPU pressure (%)", x["sys_cpu_some"], 0, 100)
			need(w, "IO pressure (%)", x["sys_io_some"], 0, 100)
			if run.Config == "A" {
				continue
			}
			// Every other configuration runs a recorder (clifr or atop).
			need(w, "recorder CPU (% of one core)", x["rec_cpu"], 0.001, 100*cpus)
			need(w, "recorder memory", x["rec_mem_avg"], 64*kib, math.Inf(1))
			need(w, "recorder anonymous memory", x["rec_anon_avg"], 64*kib, math.Inf(1))
			need(w, "disk written per hour", x["write_per_h"], 0, math.Inf(1))
			// DB growth needs at least 5 samples (slopePerHour); a smoke run has fewer.
			// Node Exporter (N1) stores nothing.
			if run.Config != "N1" && (!run.HasClifr || x["samples"] >= 5) {
				need(w, "DB or log file growth per hour", x["store_per_h"], kib, math.Inf(1))
			}
			if run.HasClifr && len(run.Samples) < 2 {
				bad(w, "%d clifr samples in the measured window", len(run.Samples))
			}
		}
	}
	for _, s := range r.Scaling {
		for _, pt := range s.Points {
			if pt.Status != "ok" {
				continue
			}
			w := filepath.Base(s.Dir) + "/" + pt.ID
			need(w, "recorder CPU (% of one core)", pt.CPUPct, 0.001, math.Inf(1))
			need(w, "sample duration p50 (ms)", pt.TotalP50, 0.001, math.Inf(1))
			need(w, "DB growth per hour", pt.DBPerHour, kib, math.Inf(1))
			need(w, "disk written per hour", pt.WritePerH, 0, math.Inf(1))
			need(w, "anonymous memory", pt.AnonMax, 64*kib, math.Inf(1))
		}
	}
	for _, a := range r.Accuracy {
		w := filepath.Base(a.Dir)
		if a.Checkpoints == 0 {
			bad(w, "no verify checkpoints")
		}
		for _, cmd := range []string{"ps aux", "ss -tanp", "lsof -n -P"} {
			t, ok := a.Totals[cmd]
			if !ok || t.Real == 0 || t.Matched == 0 {
				bad(w, "%s: no rows compared", cmd)
			}
		}
	}
	for _, run := range r.Passive {
		w := filepath.Base(run.Dir)
		need(w, "recorder CPU (% of one core)", run.M["rec_cpu"], 0.001, math.Inf(1))
		need(w, "DB growth per hour", run.M["store_per_h"], kib, math.Inf(1))
	}
	return p
}
