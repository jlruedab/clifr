package main

import (
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// A report is a list of sections of blocks; html.go and md.go render them.
type section struct {
	Title  string
	Level  int // 2 or 3
	Blocks []block
}

type block struct {
	Para    string   // plain text paragraph
	Items   []string // bullet list
	Table   *table
	Chart   string // inline SVG (HTML only)
	Caption string // chart caption
}

type table struct {
	Head []string
	Rows [][]string
	Note string
	KV   bool // key/value table: no numeric alignment
}

var configDesc = map[string]string{
	"A":  "workload only (baseline)",
	"B":  "sosv-record --interval 30s --fd-interval 120s (v2 default)",
	"C":  "sosv-record --interval 10s --fd-interval 60s (v2 aggressive)",
	"D":  "sosv-record --interval 60s --fd-interval 300s (v2 conservative)",
	"V1": "v1 recorder (snapshots, SQLite) --interval 30s --fd-interval 120s",
	"R1": "atop -w FILE 30 (reference)",
}

var configColor = map[string]string{"A": "--base", "B": "--s1", "C": "--s2", "D": "--s3", "V1": "--s5", "R1": "--s4", "passive": "--s1"}

func color(cfg string) string {
	if c, ok := configColor[cfg]; ok {
		return c
	}
	return "--base"
}

// recorder configurations of a matrix, in run order (A excluded).
func recorders(m *Matrix) []string {
	var out []string
	for _, c := range m.Configs {
		if c != "A" {
			out = append(out, c)
		}
	}
	return out
}

func (r *Report) sections() []section {
	var out []section
	out = append(out, r.overview())
	for _, m := range r.Matrix {
		for _, p := range m.Profiles {
			out = append(out, costSection(m, p)...)
		}
	}
	for _, s := range r.Scaling {
		out = append(out, scalingSections(s)...)
	}
	for _, p := range r.Passive {
		out = append(out, passiveSection(p))
	}
	for _, a := range r.Accuracy {
		out = append(out, accuracySection(a))
	}
	out = append(out, r.method())
	return out
}

// --- overview ----------------------------------------------------------------

func (r *Report) overview() section {
	s := section{Title: "Summary", Level: 2}
	var items []string
	for _, m := range r.Matrix {
		for _, p := range m.Profiles {
			items = append(items, profileSummary(m, p)...)
		}
	}
	for _, sc := range r.Scaling {
		items = append(items, scalingSummary(sc)...)
	}
	for _, a := range r.Accuracy {
		items = append(items, accuracySummary(a))
	}
	for _, p := range r.Passive {
		items = append(items, fmt.Sprintf("Real-server run %s: sosv used %s of one core and wrote %s per day over %s.",
			p.ID, pct(p.M["rec_cpu"]), bytesFmt(p.M["write_per_h"]*24), dur(float64(p.To-p.From)/1000)))
	}
	if len(items) == 0 {
		items = append(items, "No results loaded.")
	}
	s.Blocks = append(s.Blocks, block{Items: items})
	mach := r.Machine
	if mach != nil {
		s.Blocks = append(s.Blocks, block{Table: &table{
			KV:   true,
			Head: []string{"Machine", ""},
			Rows: [][]string{
				{"CPU", fmt.Sprintf("%s, %s CPUs", mach["cpu_model"], mach["cpus"])},
				{"Memory", bytesFmt(num(mach["mem_total_kb"]) * 1024)},
				{"OS", fmt.Sprintf("%s, kernel %s", mach["distro"], mach["kernel"])},
				{"Virtualization", orNone(mach["virt"])},
				{"Disk", fmt.Sprintf("%s (%s), rotational=%s, filesystem %s", mach["disk"], orNone(mach["disk_model"]), mach["disk_rotational"], mach["fs"])},
				{"sosv commit", mach["sosv_commit"]},
			},
		}})
	}
	var dirs []string
	for _, d := range r.Dirs {
		dirs = append(dirs, filepath.Base(d))
	}
	s.Blocks = append(s.Blocks, block{Para: fmt.Sprintf("Generated %s from %s.",
		r.Generated.Format("2006-01-02 15:04"), strings.Join(dirs, ", "))})
	return s
}

func profileSummary(m *Matrix, p string) []string {
	var out []string
	g := m.Groups[p+"/B"]
	atop := m.Groups[p+"/R1"]
	if g != nil {
		line := fmt.Sprintf("Profile %s, default settings (B): sosv used %s of one core (%s of the machine), "+
			"anonymous memory %s, and wrote %s to disk per day",
			p, statPct(g.Stat["rec_cpu"]), pct(g.Stat["rec_cpu_machine"].Mean),
			bytesFmt(g.Stat["rec_anon_avg"].Mean), bytesFmt(g.Stat["write_per_h"].Mean*24))
		if atop != nil {
			line += fmt.Sprintf("; atop at 30 s used %s of one core and wrote %s per day",
				statPct(atop.Stat["rec_cpu"]), bytesFmt(atop.Stat["write_per_h"].Mean*24))
		}
		out = append(out, line+".")
	}
	for _, c := range recorders(m) {
		x := m.Groups[p+"/"+c]
		if x == nil || x.Diff == nil {
			continue
		}
		d := x.Diff["lat_p99_ms"]
		da := x.Diff["lat_avg_ms"]
		out = append(out, fmt.Sprintf("Profile %s, %s vs no recorder: pgbench p99 latency %s ms (%s), average %s ms (%s).",
			p, c, signed(d.D, 3), verdict(d), signed(da.D, 3), verdict(da)))
	}
	return out
}

func verdict(d Diff) string {
	switch {
	case !d.OK:
		return "too few repeats for an interval"
	case d.Significant():
		return fmt.Sprintf("95%% CI %s..%s, a measurable change", signed(d.Lo, 3), signed(d.Hi, 3))
	}
	return fmt.Sprintf("95%% CI %s..%s, within noise", signed(d.Lo, 3), signed(d.Hi, 3))
}

// --- recorder cost and workload impact ----------------------------------------

type metricDef struct {
	Key, Label string
	Fmt        func(float64) string
}

var costMetrics = []metricDef{
	{"rec_cpu", "CPU, % of one core", pct},
	{"rec_cpu_p95", "CPU p95 over 5 s intervals, % of one core", pct},
	{"rec_cpu_machine", "CPU, % of the whole machine", pct},
	{"rec_anon_avg", "Anonymous memory (about RSS), average", bytesFmt},
	{"rec_anon_max", "Anonymous memory, max", bytesFmt},
	{"rec_mem_avg", "cgroup memory incl. page cache, average", bytesFmt},
	{"rec_mem_peak", "cgroup memory.peak", bytesFmt},
	{"rss_growth_per_h", "RSS trend per hour (leak check)", signedBytes},
	{"write_per_h", "Disk written per hour", bytesFmt},
	{"write_per_day", "Disk written per day (extrapolated)", bytesFmt},
	{"wiops", "Write IOPS", func(v float64) string { return numFmt(v, 1) }},
	{"store_per_h", "DB (or atop file) growth per hour", bytesFmt},
	{"store_per_day", "DB growth per day (extrapolated)", bytesFmt},
	{"day_per_1k_procs", "DB per day per 1,000 processes", bytesFmt},
	{"day_per_10k_socks", "DB per day per 10,000 sockets", bytesFmt},
	{"rows_per_sample", "Rows written per sample", func(v float64) string { return numFmt(v, 0) }},
	{"nproc", "Processes per sample", func(v float64) string { return numFmt(v, 0) }},
	{"nsock", "Sockets per sample", func(v float64) string { return numFmt(v, 0) }},
	{"skipped", "Skipped samples", func(v float64) string { return numFmt(v, 0) }},
	{"fd_interval_end", "fd interval at the end, s (guard rail)", func(v float64) string { return numFmt(v, 0) }},
}

var impactMetrics = []metricDef{
	{"tps", "pgbench TPS", func(v float64) string { return numFmt(v, 0) }},
	{"lat_avg_ms", "Latency average, ms", ms3},
	{"lat_p50_ms", "Latency p50, ms", ms3},
	{"lat_p95_ms", "Latency p95, ms", ms3},
	{"lat_p99_ms", "Latency p99, ms", ms3},
	{"lat_p999_ms", "Latency p99.9, ms", ms3},
	{"sys_busy", "Machine CPU busy, %", func(v float64) string { return numFmt(v, 1) }},
	{"sys_cpu_some", "CPU pressure (some), %", func(v float64) string { return numFmt(v, 2) }},
	{"sys_io_some", "IO pressure (some), %", func(v float64) string { return numFmt(v, 2) }},
}

func costSection(m *Matrix, p string) []section {
	recs := recorders(m)
	var groups []*Group
	for _, c := range recs {
		if g := m.Groups[p+"/"+c]; g != nil {
			groups = append(groups, g)
		}
	}
	reps := 0
	for _, g := range m.Groups {
		if g.Profile == p && len(g.Runs) > reps {
			reps = len(g.Runs)
		}
	}
	intro := fmt.Sprintf("Load profile %s; %d repeat(s) per configuration, %s s warm-up (discarded) and %s s measured per run; "+
		"pgbench %s at %s TPS target. Values are means over repeats with 95%% confidence intervals (±) where there are at least two repeats.",
		p, reps, m.Env["warmup_s"], m.Env["measure_s"], orNone(m.Env["pgbench_mode"]), orNone(m.Env["pgbench_rate"]))
	cost := section{Title: "Profile " + p + ": recorder cost", Level: 2}
	cost.Blocks = append(cost.Blocks, block{Para: intro})

	// cost table: metrics x configurations
	t := &table{Head: []string{"Metric"}}
	for _, g := range groups {
		t.Head = append(t.Head, g.Config)
	}
	for _, md := range costMetrics {
		row := []string{md.Label}
		any := false
		for _, g := range groups {
			s := g.Stat[md.Key]
			if s.N > 0 && !math.IsNaN(s.Mean) {
				any = true
			}
			row = append(row, statFmt(s, md.Fmt))
		}
		if any {
			t.Rows = append(t.Rows, row)
		}
	}
	t.Note = "Memory: the cgroup figure includes page cache of the files the recorder writes; anonymous memory is the recorder's own heap and stacks. " +
		"For atop (R1) the DB rows show the size of its raw log file."
	cost.Blocks = append(cost.Blocks, block{Table: t})
	var guard []string
	for _, g := range groups {
		for _, r := range g.Runs {
			for k, n := range r.Guard {
				guard = append(guard, fmt.Sprintf("%s repeat %d: %s ×%d", g.Config, r.Repeat, k, n))
			}
		}
	}
	if len(guard) > 0 {
		sort.Strings(guard)
		cost.Blocks = append(cost.Blocks, block{Para: "Guard-rail events during the runs: " + strings.Join(guard, "; ") + "."})
	}

	// disk per day in MiB, or GiB when large
	unit, unitName := float64(1<<20), "MiB"
	for _, g := range groups {
		if g.Stat["write_per_h"].Mean*24 >= 10<<30 {
			unit, unitName = 1<<30, "GiB"
		}
	}
	var bars, disk []barRow
	for _, g := range groups {
		s := g.Stat["rec_cpu"]
		bars = append(bars, barRow{Label: g.Config, Color: color(g.Config), Value: s.Mean,
			Lo: s.Mean - s.CI, Hi: s.Mean + s.CI, ValueText: pct(s.Mean),
			Tip: fmt.Sprintf("%s: %s of one core\n%s", g.Config, statPct(s), configDesc[g.Config])})
		w := g.Stat["write_per_h"]
		disk = append(disk, barRow{Label: g.Config, Color: color(g.Config), Value: w.Mean * 24 / unit,
			Lo: (w.Mean - w.CI) * 24 / unit, Hi: (w.Mean + w.CI) * 24 / unit, ValueText: bytesFmt(w.Mean * 24),
			Tip: fmt.Sprintf("%s: %s written per day", g.Config, bytesFmt(w.Mean*24))})
	}
	cost.Blocks = append(cost.Blocks,
		block{Chart: hbars("Recorder CPU by configuration", "% of one core (bar: mean, whisker: 95% CI)", bars, 2, "2% budget"),
			Caption: "Recorder CPU, % of one core, profile " + p},
		block{Chart: hbars("Disk written per day by configuration", unitName+" per day (extrapolated from the measured window)", disk, 0, ""),
			Caption: "Disk written per day, profile " + p})

	// sample durations
	dur := section{Title: "Profile " + p + ": sample duration", Level: 3}
	dt := &table{Head: []string{"Config", "Samples", "Phase", "p50 ms", "p95 ms", "p99 ms", "max ms"}}
	var rr []rangeRow
	for _, g := range groups {
		var ss []Sample
		for _, r := range g.Runs {
			ss = append(ss, r.Samples...)
		}
		if len(ss) == 0 {
			continue
		}
		phases := []struct {
			name string
			f    func(Sample) (float64, bool)
		}{
			{"processes", func(s Sample) (float64, bool) { return s.Proc, true }},
			{"sockets", func(s Sample) (float64, bool) { return s.Sock, true }},
			{"fds (fd-walk samples)", func(s Sample) (float64, bool) { return s.FD, s.FDWalk }},
			{"db write", func(s Sample) (float64, bool) { return s.DB, true }},
			{"total, no fd walk", func(s Sample) (float64, bool) { return s.Total(), !s.FDWalk }},
			{"total, fd walk", func(s Sample) (float64, bool) { return s.Total(), s.FDWalk }},
		}
		for _, ph := range phases {
			var v []float64
			for _, s := range ss {
				if x, ok := ph.f(s); ok && !s.Skipped {
					v = append(v, x)
				}
			}
			if len(v) == 0 {
				continue
			}
			p50, p95, p99, mx := percentile(v, .5), percentile(v, .95), percentile(v, .99), maxOf(v)
			dt.Rows = append(dt.Rows, []string{g.Config, fmt.Sprint(len(v)), ph.name, ms1(p50), ms1(p95), ms1(p99), ms1(mx)})
			if strings.HasPrefix(ph.name, "total") {
				lbl := g.Config + ", " + strings.TrimPrefix(ph.name, "total, ")
				rr = append(rr, rangeRow{Label: lbl, Color: color(g.Config), P50: p50, P95: p95, P99: p99, Max: mx,
					Tip: fmt.Sprintf("%s\np50 %s ms, p95 %s ms, p99 %s ms, max %s ms (%d samples)", lbl, ms1(p50), ms1(p95), ms1(p99), ms1(mx), len(v))})
			}
		}
	}
	dt.Note = "Total = processes + sockets + fds; the DB write is the previous sample's transaction. Samples from all repeats, measured window only."
	if len(dt.Rows) > 0 {
		dur.Blocks = append(dur.Blocks, block{Table: dt},
			block{Chart: ranges("Sample duration", "ms, log scale (dot: p50, bar: p50 to p95, whisker: to p99, tick: max)", rr),
				Caption: "Total sample duration, profile " + p})
	}

	// timeline of recorder CPU, first repeat of each recorder config
	var series []lineSeries
	for _, g := range groups {
		r := g.Runs[0]
		var tips []string
		for _, pt := range r.Timeline {
			tips = append(tips, fmt.Sprintf("%s, minute %.1f: %s of one core", g.Config, pt.X, pct(pt.Y)))
		}
		series = append(series, lineSeries{Name: g.Config, Color: color(g.Config), Pts: r.Timeline, Tips: tips})
	}
	if len(series) > 0 {
		dur.Blocks = append(dur.Blocks, block{Chart: lines("Recorder CPU over time", "minutes into the measured period",
			"% of one core", series, 0, "", 640, 260),
			Caption: "Recorder CPU per 5 s interval, first repeat of each configuration, profile " + p})
	}

	// workload impact
	imp := section{Title: "Profile " + p + ": impact on the workload", Level: 2}
	base := m.Groups[p+"/A"]
	if base == nil {
		imp.Blocks = append(imp.Blocks, block{Para: "No baseline (configuration A) runs for this profile."})
		return []section{cost, dur, imp}
	}
	it := &table{Head: []string{"Metric", "A"}}
	for _, g := range groups {
		it.Head = append(it.Head, g.Config, g.Config+" − A")
	}
	for _, md := range impactMetrics {
		row := []string{md.Label, statFmt(base.Stat[md.Key], md.Fmt)}
		for _, g := range groups {
			row = append(row, statFmt(g.Stat[md.Key], md.Fmt), diffFmt(g.Diff[md.Key], md.Fmt))
		}
		it.Rows = append(it.Rows, row)
	}
	it.Note = "X − A: difference of means with a Welch 95% confidence interval and the change in %; * marks an interval that excludes zero (a measurable change). Without * the difference is within run-to-run noise."
	imp.Blocks = append(imp.Blocks, block{Table: it})
	for _, k := range []struct{ key, title string }{{"lat_p99_ms", "p99 latency"}, {"lat_p999_ms", "p99.9 latency"}, {"lat_avg_ms", "average latency"}} {
		var fr []forestRow
		for _, g := range groups {
			d := g.Diff[k.key]
			fr = append(fr, forestRow{Label: g.Config, D: d.D, Lo: d.Lo, Hi: d.Hi,
				ValueText: signed(d.D, 3) + " ms" + star(d),
				Tip:       fmt.Sprintf("%s − A, %s: %s ms\n%s", g.Config, k.title, signed(d.D, 3), verdict(d))})
		}
		imp.Blocks = append(imp.Blocks, block{Chart: forest("Change in "+k.title, "ms vs. no recorder (dot: difference of means, whisker: 95% CI)", fr),
			Caption: "Change in pgbench " + k.title + " vs. configuration A, profile " + p})
	}
	return []section{cost, dur, imp}
}

// --- scaling -------------------------------------------------------------------

var dimInfo = map[string]struct{ Label, Unit string }{
	"procs": {"long-lived processes", "processes"},
	"fds":   {"open files", "fds"},
	"conns": {"TCP connections", "connections"},
	"spawn": {"short-lived processes per second", "spawns/s"},
	"churn": {"new TCP connections per second", "conns/s"},
}

func dimPoints(s *Scaling, dim string) []*Point {
	var ps []*Point
	for _, p := range s.Points {
		if p.Dim == dim && p.Status == "ok" {
			ps = append(ps, p)
		}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].Value < ps[j].Value })
	return ps
}

func fits(s *Scaling, p *Point) bool { return p.CPUPct <= 2 && p.TotalMax < s.Interval*1000 }

func scalingSummary(s *Scaling) []string {
	var over []string
	n := 0
	for _, p := range s.Points {
		if p.Status != "ok" {
			continue
		}
		n++
		if !fits(s, p) {
			over = append(over, fmt.Sprintf("%s=%s (%s of one core, longest sample %s ms)", p.Dim, tickText(p.Value), pct(p.CPUPct), ms1(p.TotalMax)))
		}
	}
	if n == 0 {
		return nil
	}
	if len(over) == 0 {
		return []string{fmt.Sprintf("Scaling: at %s / %s every one of the %d load points stayed within the 2%% CPU budget and the interval.",
			s.Env["interval"], s.Env["fd_interval"], n)}
	}
	return []string{fmt.Sprintf("Scaling: at %s / %s, %d of %d load points exceed the 2%% CPU budget or the interval: %s.",
		s.Env["interval"], s.Env["fd_interval"], len(over), n, strings.Join(over, "; "))}
}

func scalingSections(s *Scaling) []section {
	sec := section{Title: "Scaling", Level: 2}
	sec.Blocks = append(sec.Blocks, block{Para: fmt.Sprintf("No workload; one load dimension varies while the others stay at the baseline (%s). "+
		"Recorder at --interval %s --fd-interval %s with the CPU guard rail off, %s s per point; the first sample (initial full insert) is excluded. "+
		"A point fits when CPU ≤ 2%% of one core and the longest sample is shorter than the interval.",
		s.Env["baseline"], s.Env["interval"], s.Env["fd_interval"], s.Env["record_s"])})
	t := &table{Head: []string{"Dimension", "Value", "CPU % of one core", "Fits", "Sample p50 ms (no walk)", "fd-walk sample ms", "Longest ms", "Rows/sample", "DB growth/h", "Written/h", "Anon max"}}
	gt := &table{Head: []string{"Dimension", "CPU per unit", "CPU growth", "fd-walk time growth", "DB growth per unit/h", "DB growth"}}
	for _, dim := range s.Dims {
		ps := dimPoints(s, dim)
		var xs, cpu, walk, db []float64
		for _, p := range ps {
			fit := "yes"
			if !fits(s, p) {
				fit = "NO"
			}
			t.Rows = append(t.Rows, []string{dim, tickText(p.Value), pct(p.CPUPct), fit, ms1(p.TotalP50), ms1(p.FDWalkMean),
				ms1(p.TotalMax), numFmt(p.RowsPerS, 0), bytesFmt(p.DBPerHour), bytesFmt(p.WritePerH), bytesFmt(p.AnonMax)})
			xs, cpu, walk, db = append(xs, p.Value), append(cpu, p.CPUPct), append(walk, p.FDWalkMean), append(db, p.DBPerHour)
		}
		if len(ps) < 2 {
			continue
		}
		unit, per := 1000.0, "per 1,000 "+dimInfo[dim].Unit
		if dim == "spawn" || dim == "churn" {
			unit, per = 100, "per 100 "+dimInfo[dim].Unit
		}
		gc, gw, gd := growthOf(xs, cpu), growthOf(xs, walk), growthOf(xs, db)
		gt.Rows = append(gt.Rows, []string{dim, signed(gc.PerUnit*unit, 3) + "% " + per, gc.label() + ratioText(gc),
			gw.label() + ratioText(gw), signedBytes(gd.PerUnit*unit) + " " + per, gd.label() + ratioText(gd)})
	}
	sec.Blocks = append(sec.Blocks, block{Table: t}, block{Table: gt})
	gt.Note = "Growth compares the marginal cost on the upper segment (middle to highest value) with the lower one (lowest to middle): " +
		"a ratio near 1 is linear, above 1.4 faster than linear. Costs include the fixed baseline load, so only the marginal figures isolate one dimension."
	for _, dim := range s.Dims {
		ps := dimPoints(s, dim)
		if len(ps) == 0 {
			continue
		}
		var cpu, p50, walk []XY
		var tc, tp, tw []string
		for _, p := range ps {
			cpu = append(cpu, XY{p.Value, p.CPUPct})
			tc = append(tc, fmt.Sprintf("%s %s: %s of one core", tickText(p.Value), dimInfo[dim].Unit, pct(p.CPUPct)))
			p50 = append(p50, XY{p.Value, p.TotalP50})
			tp = append(tp, fmt.Sprintf("%s %s: p50 sample %s ms", tickText(p.Value), dimInfo[dim].Unit, ms1(p.TotalP50)))
			walk = append(walk, XY{p.Value, p.FDWalkMean})
			tw = append(tw, fmt.Sprintf("%s %s: fd-walk sample %s ms", tickText(p.Value), dimInfo[dim].Unit, ms1(p.FDWalkMean)))
		}
		sub := section{Title: "Scaling: " + dimInfo[dim].Label, Level: 3}
		sub.Blocks = append(sub.Blocks,
			block{Chart: lines("Recorder CPU vs "+dimInfo[dim].Label, dimInfo[dim].Unit, "% of one core",
				[]lineSeries{{Name: "CPU", Color: "--s1", Pts: cpu, Tips: tc}}, 2, "2% budget", 400, 220),
				Caption: "Recorder CPU vs " + dimInfo[dim].Label},
			block{Chart: lines("Sample duration vs "+dimInfo[dim].Label, dimInfo[dim].Unit, "ms",
				[]lineSeries{{Name: "no fd walk, p50", Color: "--s1", Pts: p50, Tips: tp},
					{Name: "fd walk, mean", Color: "--s2", Pts: walk, Tips: tw}}, 0, "", 400, 220),
				Caption: "Sample duration vs " + dimInfo[dim].Label})
		sec.Blocks = append(sec.Blocks, sub.Blocks...)
	}
	return []section{sec}
}

func ratioText(g growth) string {
	if g.Flat || math.IsNaN(g.Ratio) {
		return ""
	}
	return fmt.Sprintf(" (ratio %.2f)", g.Ratio)
}

// --- passive and accuracy -----------------------------------------------------------

func passiveSection(p *Run) section {
	s := section{Title: "Real server: " + p.ID, Level: 2}
	s.Blocks = append(s.Blocks, block{Para: fmt.Sprintf("Recorder under the shipped unit's limits (CPUQuota=5%%, MemoryMax=256M), no generated load; %s measured.",
		dur(float64(p.To-p.From)/1000))})
	t := &table{KV: true, Head: []string{"Metric", "Value"}}
	for _, md := range append(costMetrics, metricDef{"throttled_pct", "Time throttled by CPUQuota, %", func(v float64) string { return numFmt(v, 1) }}) {
		if v, ok := p.M[md.Key]; ok && !math.IsNaN(v) {
			t.Rows = append(t.Rows, []string{md.Label, md.Fmt(v)})
		}
	}
	s.Blocks = append(s.Blocks, block{Table: t})
	if len(p.Timeline) > 0 {
		s.Blocks = append(s.Blocks, block{Chart: lines("Recorder CPU over time", "minutes", "% of one core",
			[]lineSeries{{Name: "sosv", Color: "--s1", Pts: p.Timeline}}, 2, "2% budget", 640, 240),
			Caption: "Recorder CPU per 5 s interval"})
	}
	return s
}

func accuracySummary(a *Accuracy) string {
	var parts []string
	for _, cmd := range []string{"ps aux", "ss -tanp", "lsof -n -P"} {
		if t, ok := a.Totals[cmd]; ok {
			parts = append(parts, fmt.Sprintf("%s %s of rows matched (%s exactly)", cmd, pct(matchPct(t)), pct(exactPct(t))))
		}
	}
	return fmt.Sprintf("Accuracy (%d checkpoints, profile %s): %s.", a.Checkpoints, orNone(a.Env["profile"]), strings.Join(parts, "; "))
}

// matchPct: rows matched out of the real rows that existed at the sample
// (rows that started or ended between the sample and the real command are
// counted separately as churn).
func matchPct(t VerifyResult) float64 {
	d := t.Real - t.ChurnMissing
	if d <= 0 {
		return nan
	}
	return float64(t.Matched) / float64(d) * 100
}

// exactPct: exact rows out of the same, minus the matched rows whose fields
// changed between the sample and the real command (churn-changed).
func exactPct(t VerifyResult) float64 {
	d := t.Real - t.ChurnMissing - t.ChurnChanged
	if d <= 0 {
		return nan
	}
	return float64(t.Exact) / float64(d) * 100
}

func accuracySection(a *Accuracy) section {
	s := section{Title: "Accuracy", Level: 2}
	s.Blocks = append(s.Blocks, block{Para: fmt.Sprintf("sosv record --verify-every %s under load profile %s for %s (interval %s, fd interval %s); "+
		"at each of the %d checkpoints the real ps aux, ss -tanp and lsof -n -P outputs were saved and compared with sosv's reconstruction for the same moment.",
		a.Env["verify_every"], a.Env["profile"], a.Env["duration"], a.Env["interval"], a.Env["fd_interval"], a.Checkpoints)})
	t := &table{Head: []string{"Command", "Real rows", "Matched", "Exact", "Missing", "Extra", "Churn (missing / extra / changed)", "Matched %", "Exact %", "Field mismatches"}}
	for _, cmd := range []string{"ps aux", "ss -tanp", "lsof -n -P"} {
		r, ok := a.Totals[cmd]
		if !ok {
			continue
		}
		var fd []string
		for k, n := range r.FieldDiffs {
			fd = append(fd, fmt.Sprintf("%s %d", k, n))
		}
		sort.Strings(fd)
		t.Rows = append(t.Rows, []string{cmd, commas(float64(r.Real)), commas(float64(r.Matched)), commas(float64(r.Exact)),
			commas(float64(r.Missing)), commas(float64(r.Extra)), fmt.Sprintf("%s / %s / %s", commas(float64(r.ChurnMissing)), commas(float64(r.ChurnExtra)), commas(float64(r.ChurnChanged))),
			pct(matchPct(r)), pct(exactPct(r)), orNone(strings.Join(fd, ", "))})
	}
	t.Note = "Missing/extra exclude churn: entities that started or ended between the sample and the moment the real command ran, counted separately. Changed: matched rows whose fields differ because the entity changed in that window (for example a connection that closed into TIME-WAIT, or an fd number reused by a new connection). Matched % is of the real rows minus churn; exact % also leaves out the changed rows."
	s.Blocks = append(s.Blocks, block{Table: t})
	var ign []string
	for _, cmd := range []string{"ps aux", "ss -tanp", "lsof -n -P"} {
		if v, ok := a.Ignored[cmd]; ok {
			ign = append(ign, cmd+": "+v)
		}
	}
	if len(ign) > 0 {
		s.Blocks = append(s.Blocks, block{Para: "Not compared: " + strings.Join(ign, ". ") + "."})
	}
	return s
}

func (r *Report) method() section {
	s := section{Title: "Method and caveats", Level: 2}
	items := []string{
		"Every process under test ran in its own systemd scope with CPU, memory and IO accounting; cgroup v2 counters and system-wide /proc counters were sampled every 5 s. Rates are counter differences over the measured window.",
		"The recorder (and atop) ran with nice 10 and the idle IO class, like the shipped unit, but without its CPUQuota/MemoryMax, so the true cost is measured, not the cap. The sosv CPU guard rail (2% budget) was active in the matrix runs and may lengthen the fd interval; its events are listed per profile.",
		"Workload: pgbench, by default read-only (-S) at a fixed transaction rate with the database cached in memory, and its output written to RAM. On the test VM the disk stalls for tens of seconds under write load, which made a read/write workload measure the host's flushing instead of the recorder. The impact on a disk-bound workload is therefore not measured here.",
		"Confidence intervals: t-distribution over the repeats (mean ± t·s/√n); differences vs. the baseline use Welch's interval. With fewer than two repeats no interval is given.",
		"Disk use is an upper bound: sosv writes one SQLite transaction per sample.",
		"Per-day figures extrapolate the measured window linearly.",
	}
	s.Blocks = append(s.Blocks, block{Items: items})
	return s
}

// --- formatting ----------------------------------------------------------------

func numFmt(v float64, dec int) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "—"
	}
	if math.Abs(v) >= 1000 {
		return commas(v)
	}
	return fmt.Sprintf("%.*f", dec, v)
}

func commas(v float64) string {
	s := fmt.Sprintf("%.0f", math.Abs(v))
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if v < 0 {
		return "-" + b.String()
	}
	return b.String()
}

func pct(v float64) string {
	if math.IsNaN(v) {
		return "—"
	}
	if math.Abs(v) < 10 {
		return fmt.Sprintf("%.2f%%", v)
	}
	return fmt.Sprintf("%.1f%%", v)
}

func ms1(v float64) string { return numFmt(v, 1) }
func ms3(v float64) string { return numFmt(v, 3) }

func bytesFmt(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "—"
	}
	a := math.Abs(v)
	switch {
	case a >= 1<<30:
		return fmt.Sprintf("%.2f GiB", v/(1<<30))
	case a >= 1<<20:
		return fmt.Sprintf("%.1f MiB", v/(1<<20))
	case a >= 1<<10:
		return fmt.Sprintf("%.0f KiB", v/(1<<10))
	}
	return fmt.Sprintf("%.0f B", v)
}

func signedBytes(v float64) string {
	if v > 0 {
		return "+" + bytesFmt(v)
	}
	return bytesFmt(v)
}

func signed(v float64, dec int) string {
	if math.IsNaN(v) {
		return "—"
	}
	return fmt.Sprintf("%+.*f", dec, v)
}

func statFmt(s Stat, f func(float64) string) string {
	if s.N == 0 || math.IsNaN(s.Mean) {
		return "—"
	}
	if math.IsNaN(s.CI) {
		return f(s.Mean)
	}
	return f(s.Mean) + " ± " + f(s.CI)
}

func statPct(s Stat) string { return statFmt(s, pct) }

func diffFmt(d Diff, f func(float64) string) string {
	if math.IsNaN(d.D) {
		return "—"
	}
	sign := ""
	if d.D > 0 {
		sign = "+"
	}
	out := sign + f(d.D)
	if d.OK {
		out += fmt.Sprintf(" [%s, %s]", f(d.Lo), f(d.Hi))
	}
	if !math.IsNaN(d.Pct) {
		out += fmt.Sprintf(" (%+.1f%%)", d.Pct)
	}
	return out + star(d)
}

func star(d Diff) string {
	if d.Significant() {
		return " *"
	}
	return ""
}

func dur(sec float64) string {
	return (time.Duration(sec) * time.Second).Round(time.Second).String()
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "n/a"
	}
	return s
}
