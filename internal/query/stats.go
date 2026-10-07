package query

import (
	"fmt"
	"io"
	"sort"
	"time"

	"sosv/internal/store"
)

type Percentiles struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
	Max float64 `json:"max"`
}

type Stats struct {
	From, To        string                 `json:"-"`
	FromMS          int64                  `json:"from_ms"`
	ToMS            int64                  `json:"to_ms"`
	Samples         int                    `json:"samples"`
	FDWalks         int                    `json:"fd_walk_samples"`
	Skipped         int                    `json:"skipped_samples"`
	TableRows       map[string]int64       `json:"table_rows"`
	DBBytes         int64                  `json:"db_bytes"`
	CPUPctOneCore   float64                `json:"recorder_cpu_pct_one_core"`
	RSSAvgKB        int64                  `json:"recorder_rss_avg_kb"`
	RSSMaxKB        int64                  `json:"recorder_rss_max_kb"`
	PhaseMS         map[string]Percentiles `json:"sample_phase_ms"`
	GuardEvents     map[string]int         `json:"guard_events"`
	DiskPerDayBytes int64                  `json:"est_disk_per_day_bytes"`
	AvgProcs        float64                `json:"avg_processes"`
	AvgSockets      float64                `json:"avg_sockets"`
	AvgFDs          float64                `json:"avg_fds_per_walk"`
}

var statTables = []string{"processes", "proc_samples", "sockets", "sock_samples", "sock_owners",
	"open_files", "guard_events", "verify_snapshots", "samples"}

func percentiles(v []float64) Percentiles {
	if len(v) == 0 {
		return Percentiles{}
	}
	sort.Float64s(v)
	at := func(q float64) float64 { return v[int(q*float64(len(v)-1)+0.5)] }
	return Percentiles{P50: at(0.50), P95: at(0.95), P99: at(0.99), Max: v[len(v)-1]}
}

// ComputeStats summarises the recorder's own cost from the samples table.
func ComputeStats(db *store.DB) (*Stats, error) {
	st := &Stats{TableRows: map[string]int64{}, PhaseMS: map[string]Percentiles{}, GuardEvents: map[string]int{}}
	for _, t := range statTables {
		var n int64
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + t).Scan(&n); err != nil {
			return nil, err
		}
		st.TableRows[t] = n
	}
	st.DBBytes = db.SizeBytes()

	rows, err := db.Query(`SELECT ts, fd_walk, skipped, COALESCE(dur_proc_us,0), COALESCE(dur_sock_us,0),
		COALESCE(dur_fd_us,0), COALESCE(dur_db_us,0), COALESCE(nproc,0), COALESCE(nsock,0), COALESCE(nfd,0),
		COALESCE(cpu_us,0), COALESCE(rss_kb,0), COALESCE(db_bytes,0) FROM samples ORDER BY ts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	phases := map[string][]float64{}
	var prevTS, prevCPU, prevDB int64
	firstOfRun := true // the first interval of a run includes the initial inventory
	var cpuSum, wallSum, dbGrowth, dbWall, rssSum, fdSum float64
	var nprocSum, nsockSum float64
	for rows.Next() {
		var ts, fdw, skipped, dp, ds, df, dd, np, ns, nf, cpu, rss, dbb int64
		if err := rows.Scan(&ts, &fdw, &skipped, &dp, &ds, &df, &dd, &np, &ns, &nf, &cpu, &rss, &dbb); err != nil {
			return nil, err
		}
		if st.FromMS == 0 {
			st.FromMS = ts
		}
		st.ToMS = ts
		if skipped == 1 {
			st.Skipped++
			continue
		}
		st.Samples++
		phases["processes"] = append(phases["processes"], float64(dp)/1000)
		phases["sockets"] = append(phases["sockets"], float64(ds)/1000)
		if fdw == 1 {
			st.FDWalks++
			phases["fds"] = append(phases["fds"], float64(df)/1000)
			fdSum += float64(nf)
		}
		phases["db_write"] = append(phases["db_write"], float64(dd)/1000)
		phases["total"] = append(phases["total"], float64(dp+ds+df)/1000)
		nprocSum += float64(np)
		nsockSum += float64(ns)
		rssSum += float64(rss)
		if rss > st.RSSMaxKB {
			st.RSSMaxKB = rss
		}
		// cpu_us and db_bytes restart with each recorder run; only count
		// increasing pairs.
		if prevTS != 0 && cpu >= prevCPU {
			cpuSum += float64(cpu - prevCPU)
			wallSum += float64(ts-prevTS) * 1000
		}
		if prevTS != 0 && dbb >= prevDB && cpu >= prevCPU {
			if !firstOfRun {
				dbGrowth += float64(dbb - prevDB)
				dbWall += float64(ts - prevTS)
			}
			firstOfRun = false
		} else {
			firstOfRun = true
		}
		prevTS, prevCPU, prevDB = ts, cpu, dbb
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for k, v := range phases {
		st.PhaseMS[k] = percentiles(v)
	}
	if wallSum > 0 {
		st.CPUPctOneCore = 100 * cpuSum / wallSum
	}
	if st.Samples > 0 {
		st.RSSAvgKB = int64(rssSum / float64(st.Samples))
		st.AvgProcs = nprocSum / float64(st.Samples)
		st.AvgSockets = nsockSum / float64(st.Samples)
	}
	if st.FDWalks > 0 {
		st.AvgFDs = fdSum / float64(st.FDWalks)
	}
	if dbWall > 0 {
		st.DiskPerDayBytes = int64(dbGrowth / dbWall * 86400e3)
	}
	g, err := db.Query(`SELECT kind, COUNT(*) FROM guard_events GROUP BY kind`)
	if err != nil {
		return nil, err
	}
	defer g.Close()
	for g.Next() {
		var k string
		var n int
		g.Scan(&k, &n)
		st.GuardEvents[k] = n
	}
	return st, nil
}

func humanBytes(n int64) string {
	f := float64(n)
	for _, u := range []string{"B", "KiB", "MiB", "GiB"} {
		if f < 1024 || u == "GiB" {
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= 1024
	}
	return ""
}

func PrintStats(w io.Writer, s *Stats) {
	span := time.Duration(s.ToMS-s.FromMS) * time.Millisecond
	fmt.Fprintf(w, "Recording:        %s .. %s (%s)\n", FormatMS(s.FromMS), FormatMS(s.ToMS), span.Round(time.Second))
	fmt.Fprintf(w, "Samples:          %d (%d with full fd walk), skipped: %d\n", s.Samples, s.FDWalks, s.Skipped)
	fmt.Fprintf(w, "Seen per sample:  %.0f processes, %.0f sockets, %.0f fds per walk\n", s.AvgProcs, s.AvgSockets, s.AvgFDs)
	fmt.Fprintf(w, "DB size:          %s (est. %s/day from growth during recording)\n", humanBytes(s.DBBytes), humanBytes(s.DiskPerDayBytes))
	fmt.Fprintf(w, "Recorder CPU:     %.3f%% of one core (average)\n", s.CPUPctOneCore)
	fmt.Fprintf(w, "Recorder RSS:     avg %s, max %s\n", humanBytes(s.RSSAvgKB*1024), humanBytes(s.RSSMaxKB*1024))
	fmt.Fprintln(w, "Rows per table:")
	for _, t := range statTables {
		fmt.Fprintf(w, "  %-18s %d\n", t, s.TableRows[t])
	}
	fmt.Fprintln(w, "Sample duration by phase (ms):     p50      p95      p99      max")
	for _, k := range []string{"processes", "sockets", "fds", "db_write", "total"} {
		p, ok := s.PhaseMS[k]
		if !ok {
			continue
		}
		fmt.Fprintf(w, "  %-30s %8.1f %8.1f %8.1f %8.1f\n", k, p.P50, p.P95, p.P99, p.Max)
	}
	fmt.Fprintln(w, "  (fds: only samples with a full walk; db_write: transaction of the previous sample)")
	fmt.Fprintln(w, "Guard-rail events:")
	if len(s.GuardEvents) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for k, n := range s.GuardEvents {
		fmt.Fprintf(w, "  %-18s %d\n", k, n)
	}
}

func PrintStatsJSON(w io.Writer, s *Stats) error { return writeJSON(w, s) }
