package main

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var nan = math.NaN()

// Report holds everything loaded from the result directories.
type Report struct {
	Generated time.Time
	Dirs      []string
	Machine   map[string]string // machine.env of the first directory
	Matrix    []*Matrix
	Scaling   []*Scaling
	Passive   []*Run
	Accuracy  []*Accuracy
}

// Matrix is one bench/run.sh results directory.
type Matrix struct {
	Dir      string
	Env      map[string]string
	Runs     []*Run
	Profiles []string          // in run order
	Configs  []string          // in run order
	Groups   map[string]*Group // key profile/config
	Failed   []string
}

// Run is one measured run (or a passive recording).
type Run struct {
	ID, Profile, Config string
	Repeat              int
	Dir                 string
	WarmStart           int64
	From, To            int64 // measured window, Unix ms
	HasSosv             bool  // samples.csv present
	M                   map[string]float64
	Samples             []Sample // within the measured window
	Guard               map[string]int
	FDIntervalEnd       float64
	Timeline            []XY // recorder CPU, % of one core, x = minutes since From
}

// Sample is one row of the sosv samples table.
type Sample struct {
	TS                         int64
	FDWalk, Skipped            bool
	Proc, Sock, FD, DB         float64 // phase durations, ms
	NProc, NSock, NFD, Rows    float64
	CPUUS, RSSKB, DBBytes, FDI float64
}

func (s Sample) Total() float64 { return s.Proc + s.Sock + s.FD }

// Group aggregates the repeats of one profile/config.
type Group struct {
	Profile, Config string
	Runs            []*Run
	Stat            map[string]Stat
	Diff            map[string]Diff // vs config A of the same profile
}

// Stat is a mean with its 95% confidence half-width (NaN when n < 2).
type Stat struct {
	Mean, CI float64
	N        int
	Vals     []float64
}

// Diff is mean(X) - mean(A) with a Welch 95% interval.
type Diff struct {
	D, Lo, Hi, Pct float64
	OK             bool // both sides have n >= 2
}

// Significant reports whether the interval excludes zero.
func (d Diff) Significant() bool { return d.OK && (d.Lo > 0 || d.Hi < 0) }

// Scaling is one bench/scaling.sh results directory.
type Scaling struct {
	Dir      string
	Env      map[string]string
	Interval float64 // seconds
	Dims     []string
	Points   []*Point
}

// Point is one scaling measurement.
type Point struct {
	ID, Dim    string
	Value      float64
	Status     string
	Load       map[string]float64
	CPUPct     float64 // % of one core, excluding the initial sample
	TotalP50   float64 // ms, samples without fd walk
	TotalMax   float64 // ms, any sample (excluding the first)
	FDWalkMean float64 // ms, total of fd-walk samples
	DBPerHour  float64 // logical bytes/h
	WritePerH  float64 // bytes written per hour (cgroup)
	RowsPerS   float64 // rows per sample
	MemPeak    float64 // bytes
	AnonMax    float64 // bytes
	NSock      float64
	Samples    int
	// The eBPF programs' own run time (sosv-stats.json; recorded with --bpf-stats).
	BPFPct    float64 // % of one core
	BPFRunsPS float64 // program runs per second
	BPFNSRun  float64 // mean ns per run
	BPFTop    string  // the program with the most run time
	BPFTopPct float64 // its share of the eBPF run time, %
}

// Accuracy is one bench/accuracy.sh results directory.
type Accuracy struct {
	Dir         string
	Env         map[string]string
	Checkpoints int
	Totals      map[string]VerifyResult
	Ignored     map[string]string
}

// VerifyResult mirrors verify.Result's JSON.
type VerifyResult struct {
	Cmd          string         `json:"cmd"`
	Real         int            `json:"real_rows"`
	Recon        int            `json:"reconstructed_rows"`
	Matched      int            `json:"matched"`
	Exact        int            `json:"exact"`
	Missing      int            `json:"missing"`
	Extra        int            `json:"extra"`
	ChurnMissing int            `json:"churn_missing"`
	ChurnExtra   int            `json:"churn_extra"`
	ChurnChanged int            `json:"churn_changed"`
	FieldDiffs   map[string]int `json:"field_mismatches"`
	GapMS        int64          `json:"gap_ms"`
}

type XY struct{ X, Y float64 }

// --- loading -----------------------------------------------------------------

func (r *Report) load(dir string) error {
	env, _ := readEnv(filepath.Join(dir, "machine.env"))
	if r.Machine == nil && env != nil {
		r.Machine = env
	}
	r.Dirs = append(r.Dirs, dir)
	switch {
	case exists(filepath.Join(dir, "matrix.csv")):
		m, err := loadMatrix(dir, env)
		if err != nil {
			return err
		}
		r.Matrix = append(r.Matrix, m)
	case exists(filepath.Join(dir, "points.csv")):
		s, err := loadScaling(dir, env)
		if err != nil {
			return err
		}
		r.Scaling = append(r.Scaling, s)
	case exists(filepath.Join(dir, "verify.json")):
		a, err := loadAccuracy(dir, env)
		if err != nil {
			return err
		}
		r.Accuracy = append(r.Accuracy, a)
	case env["mode"] == "passive":
		p, err := loadPassive(dir, env)
		if err != nil {
			return err
		}
		r.Passive = append(r.Passive, p)
	default:
		return fmt.Errorf("%s: no matrix.csv, points.csv, verify.json or passive machine.env", dir)
	}
	return nil
}

func loadMatrix(dir string, env map[string]string) (*Matrix, error) {
	rows, err := readCSV(filepath.Join(dir, "matrix.csv"))
	if err != nil {
		return nil, err
	}
	m := &Matrix{Dir: dir, Env: env, Groups: map[string]*Group{}}
	cpus := num(env["cpus"])
	for _, row := range rows {
		if row["status"] != "ok" {
			m.Failed = append(m.Failed, row["run_id"]+" ("+row["status"]+")")
			continue
		}
		run := &Run{
			ID: row["run_id"], Profile: row["profile"], Config: row["config"],
			Repeat: int(num(row["repeat"])), Dir: filepath.Join(dir, "runs", row["run_id"]),
			WarmStart: scriptMS(row["warm_start_ms"]),
			From:      scriptMS(row["meas_start_ms"]), To: scriptMS(row["meas_end_ms"]),
			M: map[string]float64{},
		}
		if err := run.analyse(cpus); err != nil {
			return nil, fmt.Errorf("%s: %w", run.Dir, err)
		}
		m.Runs = append(m.Runs, run)
		m.Profiles = appendNew(m.Profiles, run.Profile)
		m.Configs = appendNew(m.Configs, run.Config)
		k := run.Profile + "/" + run.Config
		if m.Groups[k] == nil {
			m.Groups[k] = &Group{Profile: run.Profile, Config: run.Config}
		}
		m.Groups[k].Runs = append(m.Groups[k].Runs, run)
	}
	for _, g := range m.Groups {
		g.Stat = map[string]Stat{}
		for _, r := range g.Runs {
			for k, v := range r.M {
				s := g.Stat[k]
				if !math.IsNaN(v) {
					s.Vals = append(s.Vals, v)
				}
				g.Stat[k] = s
			}
		}
		for k, s := range g.Stat {
			g.Stat[k] = meanCI(s.Vals)
		}
	}
	for _, g := range m.Groups {
		base := m.Groups[g.Profile+"/A"]
		if base == nil || g.Config == "A" {
			continue
		}
		g.Diff = map[string]Diff{}
		for k, s := range g.Stat {
			g.Diff[k] = welch(s, base.Stat[k])
		}
	}
	return m, nil
}

// analyse computes the run's metrics from its files.
func (run *Run) analyse(cpus float64) error {
	m := run.M
	if w, err := readCSV(filepath.Join(run.Dir, "workload", "workload.csv")); err == nil && len(w) > 0 {
		for _, k := range []string{"tps", "lat_avg_ms", "lat_p50_ms", "lat_p95_ms", "lat_p99_ms", "lat_p999_ms"} {
			m[k] = num(w[0][k])
		}
	}
	cg, err := readCSV(filepath.Join(run.Dir, "cgroup.csv.gz"))
	if err != nil {
		return err
	}
	rec := window(cg, "rec", run.From, run.To)
	run.recorderCost(rec, cpus)
	if sys, err := readCSV(filepath.Join(run.Dir, "system.csv.gz")); err == nil {
		w := window(sys, "", run.From, run.To)
		if len(w) < 2 && len(sys) >= 2 {
			return fmt.Errorf("no sampler rows between %d and %d (sampler has %s..%s): wrong run times?",
				run.From, run.To, sys[0]["ts_ms"], sys[len(sys)-1]["ts_ms"])
		}
		systemMetrics(m, w)
	}
	if exists(filepath.Join(run.Dir, "samples.csv.gz")) {
		if err := run.loadSamples(); err != nil {
			return err
		}
	}
	if b, err := os.ReadFile(filepath.Join(run.Dir, "atop_bytes")); err == nil {
		// atop writes from the start of the warm-up to the end of the run.
		if n := num(strings.TrimSpace(string(b))); n > 0 && run.To > run.WarmStart {
			m["store_per_h"] = n / float64(run.To-run.WarmStart) * 3.6e6
		}
	}
	return nil
}

// recorderCost fills CPU, memory and IO metrics from the "rec" cgroup rows.
func (run *Run) recorderCost(rec []map[string]string, cpus float64) {
	m := run.M
	for _, k := range []string{"rec_cpu", "rec_cpu_p95", "rec_cpu_machine", "rec_mem_avg", "rec_mem_peak",
		"rec_anon_avg", "rec_anon_max", "write_per_h", "write_per_day", "wiops", "throttled_pct"} {
		m[k] = nan
	}
	if len(rec) < 2 {
		return
	}
	first, last := rec[0], rec[len(rec)-1]
	dt := float64(int64(num(last["ts_ms"])) - int64(num(first["ts_ms"])))
	if dt <= 0 {
		return
	}
	cpu := (num(last["cpu_usage_us"]) - num(first["cpu_usage_us"])) / 1000 / dt * 100
	m["rec_cpu"] = cpu
	m["rec_cpu_machine"] = cpu / cpus
	var per []float64
	for i := 1; i < len(rec); i++ {
		d := num(rec[i]["ts_ms"]) - num(rec[i-1]["ts_ms"])
		if d > 0 {
			v := (num(rec[i]["cpu_usage_us"]) - num(rec[i-1]["cpu_usage_us"])) / 1000 / d * 100
			per = append(per, v)
			run.Timeline = append(run.Timeline, XY{(num(rec[i]["ts_ms"]) - float64(run.From)) / 60000, v})
		}
	}
	m["rec_cpu_p95"] = percentile(per, 0.95)
	var mem, anon []float64
	for _, r := range rec {
		mem = append(mem, num(r["mem_current"]))
		anon = append(anon, num(r["mem_anon"]))
	}
	m["rec_mem_avg"] = mean(mem)
	m["rec_anon_avg"] = mean(anon)
	m["rec_anon_max"] = maxOf(anon)
	m["rec_mem_peak"] = num(last["mem_peak"])
	if math.IsNaN(m["rec_mem_peak"]) {
		m["rec_mem_peak"] = maxOf(mem)
	}
	m["write_per_h"] = (num(last["io_wbytes"]) - num(first["io_wbytes"])) / dt * 3.6e6
	m["write_per_day"] = m["write_per_h"] * 24
	m["wiops"] = (num(last["io_wios"]) - num(first["io_wios"])) / dt * 1000
	if t := num(last["throttled_us"]); !math.IsNaN(t) {
		m["throttled_pct"] = (t - num(first["throttled_us"])) / 1000 / dt * 100
	}
}

// systemMetrics: machine-wide CPU busy % and CPU/IO pressure over the window.
func systemMetrics(m map[string]float64, sys []map[string]string) {
	m["sys_busy"], m["sys_io_some"], m["sys_cpu_some"] = nan, nan, nan
	if len(sys) < 2 {
		return
	}
	a, b := sys[0], sys[len(sys)-1]
	var all, idle float64
	for _, k := range []string{"cpu_user", "cpu_nice", "cpu_system", "cpu_idle", "cpu_iowait", "cpu_irq", "cpu_softirq", "cpu_steal"} {
		all += num(b[k]) - num(a[k])
	}
	idle = num(b["cpu_idle"]) - num(a["cpu_idle"]) + num(b["cpu_iowait"]) - num(a["cpu_iowait"])
	if all > 0 {
		m["sys_busy"] = (1 - idle/all) * 100
	}
	dt := (num(b["ts_ms"]) - num(a["ts_ms"])) * 1000 // µs
	if dt > 0 {
		m["sys_io_some"] = (num(b["psi_io_some_us"]) - num(a["psi_io_some_us"])) / dt * 100
		m["sys_cpu_some"] = (num(b["psi_cpu_some_us"]) - num(a["psi_cpu_some_us"])) / dt * 100
	}
}

func (run *Run) loadSamples() error {
	rows, err := readCSV(filepath.Join(run.Dir, "samples.csv.gz"))
	if err != nil {
		return err
	}
	run.HasSosv = true
	all := parseSamples(rows)
	for _, s := range all {
		if s.TS >= run.From && s.TS <= run.To {
			run.Samples = append(run.Samples, s)
		}
		run.FDIntervalEnd = s.FDI
	}
	m := run.M
	var ok []Sample
	skipped := 0
	for _, s := range run.Samples {
		if s.Skipped {
			skipped++
		} else {
			ok = append(ok, s)
		}
	}
	m["skipped"] = float64(skipped)
	m["samples"] = float64(len(ok))
	m["store_per_h"] = slopePerHour(ok, func(s Sample) float64 { return s.DBBytes })
	if v, isParquet := parquetPerHour(run.Dir, all); isParquet {
		m["store_per_h"] = v
	}
	m["rss_growth_per_h"] = nan
	if len(ok) > 0 && ok[len(ok)-1].TS-ok[0].TS >= 10*60*1000 { // shorter windows show GC noise, not a trend
		m["rss_growth_per_h"] = slopePerHour(ok, func(s Sample) float64 { return s.RSSKB * 1024 })
	}
	var np, ns, rowsN []float64
	for _, s := range ok {
		np = append(np, s.NProc)
		ns = append(ns, s.NSock)
		rowsN = append(rowsN, s.Rows)
	}
	m["nproc"], m["nsock"], m["rows_per_sample"] = mean(np), mean(ns), mean(rowsN)
	day := m["store_per_h"] * 24
	m["store_per_day"] = day
	m["day_per_1k_procs"] = day / (m["nproc"] / 1000)
	run.Guard = map[string]int{}
	if g, err := readCSV(filepath.Join(run.Dir, "guard_events.csv.gz")); err == nil {
		for _, e := range g {
			if t := int64(num(e["ts"])); t <= run.To {
				run.Guard[e["kind"]]++
			}
		}
	}
	m["fd_interval_end"] = run.FDIntervalEnd
	return nil
}

// parquetPerHour: a v2 recording (table_bytes.txt present) grows in steps,
// one per flush, which a slope over a short window misses or exaggerates.
// Its rate is the final size of the data directory over the recording time
// (the connections already open at the start are in it: an upper bound).
func parquetPerHour(dir string, all []Sample) (float64, bool) {
	if !exists(filepath.Join(dir, "table_bytes.txt")) {
		return 0, false
	}
	b, err := os.ReadFile(filepath.Join(dir, "db_bytes"))
	if err != nil || len(all) < 2 {
		return nan, true
	}
	dt := float64(all[len(all)-1].TS - all[0].TS)
	if dt <= 0 {
		return nan, true
	}
	return num(strings.TrimSpace(string(b))) / dt * 3.6e6, true
}

func parseSamples(rows []map[string]string) []Sample {
	var out []Sample
	for _, r := range rows {
		out = append(out, Sample{
			TS: int64(num(r["ts"])), FDWalk: r["fd_walk"] == "1", Skipped: r["skipped"] == "1",
			Proc: num(r["dur_proc_us"]) / 1000, Sock: num(r["dur_sock_us"]) / 1000,
			FD: num(r["dur_fd_us"]) / 1000, DB: num(r["dur_db_us"]) / 1000,
			NProc: num(r["nproc"]), NSock: num(r["nsock"]), NFD: num(r["nfd"]), Rows: num(r["rows"]),
			CPUUS: num(r["cpu_us"]), RSSKB: num(r["rss_kb"]), DBBytes: num(r["db_bytes"]), FDI: num(r["fd_interval_s"]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS < out[j].TS })
	return out
}

func loadScaling(dir string, env map[string]string) (*Scaling, error) {
	rows, err := readCSV(filepath.Join(dir, "points.csv"))
	if err != nil {
		return nil, err
	}
	s := &Scaling{Dir: dir, Env: env, Interval: 30}
	if d, err := time.ParseDuration(env["interval"]); err == nil {
		s.Interval = d.Seconds()
	}
	for _, row := range rows {
		p := &Point{ID: row["point_id"], Dim: row["dim"], Value: num(row["value"]), Status: row["status"], Load: map[string]float64{}}
		for _, k := range []string{"procs", "fds", "conns", "spawn", "churn"} {
			p.Load[k] = num(row[k])
		}
		s.Dims = appendNew(s.Dims, p.Dim)
		s.Points = append(s.Points, p)
		if p.Status != "ok" {
			continue
		}
		pdir := filepath.Join(dir, "points", p.ID)
		srows, err := readCSV(filepath.Join(pdir, "samples.csv.gz"))
		if err != nil {
			return nil, err
		}
		all := parseSamples(srows)
		if len(all) < 3 {
			p.Status = "too few samples"
			continue
		}
		ss := all[1:] // the first sample inserts everything: not steady state
		first, last := ss[0], ss[len(ss)-1]
		dt := float64(last.TS - first.TS)
		p.CPUPct = (last.CPUUS - first.CPUUS) / 1000 / dt * 100
		var normal, walk, totals, rowsN, nsock []float64
		for _, x := range ss {
			if x.Skipped {
				continue
			}
			totals = append(totals, x.Total())
			rowsN = append(rowsN, x.Rows)
			nsock = append(nsock, x.NSock)
			if x.FDWalk {
				walk = append(walk, x.Total())
			} else {
				normal = append(normal, x.Total())
			}
		}
		p.TotalP50 = percentile(normal, 0.5)
		p.TotalMax = maxOf(totals)
		p.FDWalkMean = mean(walk)
		p.RowsPerS = mean(rowsN)
		p.NSock = mean(nsock)
		p.Samples = len(totals)
		p.DBPerHour = slopePerHour(ss, func(s Sample) float64 { return s.DBBytes })
		if v, isParquet := parquetPerHour(pdir, all); isParquet {
			p.DBPerHour = v
		}
		if cg, err := readCSV(filepath.Join(pdir, "cgroup.csv.gz")); err == nil {
			rec := window(cg, "rec", first.TS, last.TS)
			if len(rec) >= 2 {
				a, b := rec[0], rec[len(rec)-1]
				p.WritePerH = (num(b["io_wbytes"]) - num(a["io_wbytes"])) / (num(b["ts_ms"]) - num(a["ts_ms"])) * 3.6e6
			}
			all := window(cg, "rec", 0, math.MaxInt64)
			var anon []float64
			for _, r := range all {
				anon = append(anon, num(r["mem_anon"]))
				p.MemPeak = math.Max(p.MemPeak, num(r["mem_peak"]))
			}
			p.AnonMax = maxOf(anon)
		}
		p.loadBPF(filepath.Join(pdir, "sosv-stats.json"))
	}
	return s, nil
}

// loadBPF reads the eBPF programs' run time from the point's sosv stats, if
// they were recorded.
func (p *Point) loadBPF(path string) {
	var st struct {
		Pct   float64 `json:"bpf_cpu_pct_one_core"`
		Progs map[string]struct {
			Runs int64 `json:"runs"`
			NS   int64 `json:"run_time_ns"`
		} `json:"bpf_programs"`
	}
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &st) != nil || st.Pct <= 0 {
		return
	}
	var runs, ns, top int64
	for name, pr := range st.Progs {
		runs, ns = runs+pr.Runs, ns+pr.NS
		if pr.NS > top || pr.NS == top && name < p.BPFTop {
			top, p.BPFTop = pr.NS, name
		}
	}
	if runs == 0 || ns == 0 {
		return
	}
	p.BPFPct, p.BPFNSRun, p.BPFTopPct = st.Pct, float64(ns)/float64(runs), float64(top)/float64(ns)*100
	p.BPFRunsPS = float64(runs) / (float64(ns) / 1e9 / (st.Pct / 100))
}

func loadPassive(dir string, env map[string]string) (*Run, error) {
	run := &Run{ID: filepath.Base(dir), Config: "passive", Dir: dir, M: map[string]float64{}}
	srows, err := readCSV(filepath.Join(dir, "samples.csv.gz"))
	if err != nil {
		return nil, err
	}
	all := parseSamples(srows)
	if len(all) < 3 {
		return nil, fmt.Errorf("%s: too few samples", dir)
	}
	run.From = all[1].TS // skip the initial full insert
	run.To = all[len(all)-1].TS
	if e := scriptMS(env["end_ms"]); e > run.To {
		run.To = e
	}
	if err := run.analyse(num(env["cpus"])); err != nil {
		return nil, err
	}
	return run, nil
}

func loadAccuracy(dir string, env map[string]string) (*Accuracy, error) {
	b, err := os.ReadFile(filepath.Join(dir, "verify.json"))
	if err != nil {
		return nil, err
	}
	var v struct {
		Checkpoints []json.RawMessage       `json:"checkpoints"`
		Totals      map[string]VerifyResult `json:"totals"`
		Ignored     map[string]string       `json:"ignored_fields"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	return &Accuracy{Dir: dir, Env: env, Checkpoints: len(v.Checkpoints), Totals: v.Totals, Ignored: v.Ignored}, nil
}

// --- file helpers ------------------------------------------------------------

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// readCSV reads a CSV file (gzip-compressed if it ends in .gz; if the plain
// name is missing, the .gz name is tried) into maps keyed by header.
func readCSV(path string) ([]map[string]string, error) {
	f, err := os.Open(path)
	if err != nil && !strings.HasSuffix(path, ".gz") {
		f, err = os.Open(path + ".gz")
		path += ".gz"
	} else if err != nil {
		f, err = os.Open(strings.TrimSuffix(path, ".gz"))
		path = strings.TrimSuffix(path, ".gz")
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rd io.Reader = bufio.NewReader(f)
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(rd)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		rd = gz
	}
	cr := csv.NewReader(rd)
	cr.FieldsPerRecord = -1
	recs, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(recs) == 0 {
		return nil, nil
	}
	var out []map[string]string
	for _, rec := range recs[1:] {
		m := make(map[string]string, len(recs[0]))
		for i, h := range recs[0] {
			if i < len(rec) {
				m[h] = rec[i]
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func readEnv(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			env[k] = v
		}
	}
	return env, nil
}

// window returns the rows of one cgroup group ("" = all rows) with
// from <= ts <= to. Ticks after the measured end are left out: they would
// include the recorder's shutdown work.
func window(rows []map[string]string, group string, from, to int64) []map[string]string {
	var out []map[string]string
	for _, r := range rows {
		if group != "" && r["group"] != group {
			continue
		}
		if ts := int64(num(r["ts_ms"])); ts >= from && ts <= to {
			out = append(out, r)
		}
	}
	return out
}

// scriptMS parses a Unix time in ms written by the bench scripts. Results from
// Ubuntu 26.04 hold `date +%s%3N` from uutils date, which ignored the width and
// printed the nanoseconds without zero padding: 10 digits of seconds, then the
// nanoseconds. Those are converted; a nanosecond part below 1000 would be read
// as ms (an error under one second).
func scriptMS(s string) int64 {
	s = strings.TrimSpace(s)
	if len(s) <= 13 {
		if v := num(s); !math.IsNaN(v) {
			return int64(v)
		}
		return 0
	}
	sec, err1 := strconv.ParseInt(s[:10], 10, 64)
	ns, err2 := strconv.ParseInt(s[10:], 10, 64)
	if err1 != nil || err2 != nil {
		return 0
	}
	return sec*1000 + ns/1e6
}

// num parses a number; empty or invalid gives NaN.
func num(s string) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return nan
	}
	return v
}

func appendNew(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
