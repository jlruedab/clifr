package query

import (
	"database/sql"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// lifeProc is one process row overlapping a time range.
type lifeProc struct {
	id, start, first int64
	last, ended      sql.NullInt64
	pid, ppid        int
	command, source  string
	exitCode, signal sql.NullInt64
	oom              bool
}

// processesInRange returns processes that existed at some point in [from, to].
func processesInRange(db *store.DB, from, to int64) ([]lifeProc, error) {
	rows, err := db.Query(`
		SELECT id, pid, ppid, start_time, first_seen, last_seen, ended, comm, cmdline, source,
		       exit_code, signal, COALESCE(oom_killed, 0)
		FROM processes
		WHERE first_seen <= ?2 AND COALESCE(ended, last_seen, ?3) >= ?1
		ORDER BY start_time, pid`, from, to, openEnd)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []lifeProc
	for rows.Next() {
		var p lifeProc
		var comm, cmdline string
		var oom int
		if err := rows.Scan(&p.id, &p.pid, &p.ppid, &p.start, &p.first, &p.last, &p.ended, &comm, &cmdline, &p.source,
			&p.exitCode, &p.signal, &oom); err != nil {
			return nil, err
		}
		p.oom = oom != 0
		p.command = commandOf(cmdline, comm, "")
		out = append(out, p)
	}
	return out, rows.Err()
}

// LifeRow is one process lifetime.
type LifeRow struct {
	Start    int64  `json:"start_ms"`
	End      int64  `json:"end_ms"`
	EndKind  string `json:"end_kind"` // exact (exit event), before-next-sample, running
	Duration int64  `json:"duration_ms"`
	PID      int    `json:"pid"`
	PPID     int    `json:"ppid"`
	Command  string `json:"command"`
	Source   string `json:"source"`
	// How it ended, from exit events (eBPF); nil when unknown.
	ExitCode  *int64 `json:"exit_code,omitempty"`
	Signal    *int64 `json:"signal,omitempty"`
	OOMKilled bool   `json:"oom_killed,omitempty"`
}

// Exit is the EXIT column: the exit code, the signal name, "OOM" or "-".
func (r LifeRow) Exit() string {
	switch {
	case r.OOMKilled:
		return "OOM"
	case r.Signal != nil:
		if n := unix.SignalName(syscall.Signal(*r.Signal)); n != "" {
			return n
		}
		return fmt.Sprintf("signal %d", *r.Signal)
	case r.ExitCode != nil:
		return fmt.Sprint(*r.ExitCode)
	}
	return "-"
}

// Life lists process lifetimes in [from, to], optionally filtered by a
// regular expression on the command line.
func Life(db *store.DB, from, to int64, re *regexp.Regexp) ([]LifeRow, error) {
	procs, err := processesInRange(db, from, to)
	if err != nil {
		return nil, err
	}
	latest, _ := SnapshotAt(db, to, false)
	var out []LifeRow
	for _, p := range procs {
		if re != nil && !re.MatchString(p.command) {
			continue
		}
		r := LifeRow{Start: p.start, PID: p.pid, PPID: p.ppid, Command: p.command, Source: p.source, OOMKilled: p.oom}
		if p.exitCode.Valid {
			r.ExitCode = &p.exitCode.Int64
		}
		if p.signal.Valid {
			r.Signal = &p.signal.Int64
		}
		switch {
		case p.ended.Valid:
			r.End, r.EndKind = p.ended.Int64, "exact"
		case p.last.Valid:
			r.End, r.EndKind = p.last.Int64, "after"
		default:
			r.End, r.EndKind = latest, "running"
		}
		r.Duration = max(r.End-r.Start, 0)
		out = append(out, r)
	}
	return out, nil
}

const msLayout = "2006-01-02 15:04:05.000"

// shortSource abbreviates the source column for the table output.
func shortSource(s string) string {
	if s == "proc_connector" {
		return "cnproc"
	}
	return s
}

func fmtDur(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", ms)
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return d.Round(time.Second).String()
}

func PrintLife(w io.Writer, rows []LifeRow) {
	fmt.Fprintf(w, "%-23s %-24s %10s %7s %7s %-7s %-6s %s\n", "START", "END", "DURATION", "PID", "PPID", "EXIT", "SOURCE", "COMMAND")
	for _, r := range rows {
		end := time.UnixMilli(r.End).Format(msLayout)
		dur := fmtDur(r.Duration)
		switch r.EndKind {
		case "after": // exited after last_seen, before the next sample
			end, dur = ">"+end, ">"+dur
		case "running":
			end, dur = "running", ">"+dur
		}
		fmt.Fprintf(w, "%-23s %-24s %10s %7d %7d %-7s %-6s %s\n", time.UnixMilli(r.Start).Format(msLayout),
			end, dur, r.PID, r.PPID, r.Exit(), shortSource(r.Source), r.Command)
	}
}

// PSRangeRow collapses processes with the same command over a time range.
type PSRangeRow struct {
	FirstSeen int64   `json:"first_seen_ms"`
	LastSeen  int64   `json:"last_seen_ms"`
	Runs      int     `json:"runs"`
	EventRuns int     `json:"event_only_runs"`
	PeakCPU   float64 `json:"peak_pcpu"`
	PeakRSSKB int64   `json:"peak_rss_kb"`
	Command   string  `json:"command"`
}

// PSRange reconstructs `ps aux` over [from, to]: one row per distinct
// command, with its run count, peak %CPU between samples and peak RSS.
func PSRange(db *store.DB, from, to int64) ([]PSRangeRow, error) {
	procs, err := processesInRange(db, from, to)
	if err != nil {
		return nil, err
	}
	latest, _ := SnapshotAt(db, to, false)
	peakCPU, peakRSS, err := peaks(db, from, to)
	if err != nil {
		return nil, err
	}
	groups := map[string]*PSRangeRow{}
	for _, p := range procs {
		g := groups[p.command]
		if g == nil {
			g = &PSRangeRow{FirstSeen: p.start, Command: p.command}
			groups[p.command] = g
		}
		end := latest
		if p.ended.Valid {
			end = p.ended.Int64
		} else if p.last.Valid {
			end = p.last.Int64
		}
		g.FirstSeen = min(g.FirstSeen, max(p.start, 0))
		g.LastSeen = max(g.LastSeen, end)
		g.Runs++
		if p.source != "sample" {
			g.EventRuns++
		}
		g.PeakCPU = max(g.PeakCPU, peakCPU[p.id])
		g.PeakRSSKB = max(g.PeakRSSKB, peakRSS[p.id])
	}
	out := make([]PSRangeRow, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FirstSeen != out[j].FirstSeen {
			return out[i].FirstSeen < out[j].FirstSeen
		}
		return out[i].Command < out[j].Command
	})
	return out, nil
}

// peaks computes per process the highest %CPU between consecutive stored
// samples and the highest RSS in effect during [from, to]. A process's
// first sample uses its lifetime average, like ps.
func peaks(db *store.DB, from, to int64) (map[int64]float64, map[int64]int64, error) {
	rows, err := db.Query(`
		SELECT x.proc_id, x.ts, x.cpu_ticks, x.rss_kb, p.start_time
		FROM proc_samples x JOIN processes p ON p.id = x.proc_id
		WHERE p.first_seen <= ?2 AND COALESCE(p.ended, p.last_seen, ?3) >= ?1 AND x.ts <= ?2
		ORDER BY x.proc_id, x.ts`, from, to, openEnd)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	cpu, rss := map[int64]float64{}, map[int64]int64{}
	var prevID, prevTS, prevCPU int64 = -1, 0, 0
	for rows.Next() {
		var id, ts, ticks, rssKB, start int64
		if err := rows.Scan(&id, &ts, &ticks, &rssKB, &start); err != nil {
			return nil, nil, err
		}
		var pct float64
		if id == prevID && ts > prevTS {
			pct = float64(ticks-prevCPU) / procfs.ClockTicks / (float64(ts-prevTS) / 1000) * 100
		} else if ts > start {
			pct = float64(ticks) / procfs.ClockTicks / (float64(ts-start) / 1000) * 100
		}
		if ts >= from {
			cpu[id] = max(cpu[id], pct)
			rss[id] = max(rss[id], rssKB)
		} else {
			rss[id] = rssKB // the value in effect when the range began
		}
		prevID, prevTS, prevCPU = id, ts, ticks
	}
	return cpu, rss, rows.Err()
}

func PrintPSRange(w io.Writer, rows []PSRangeRow) {
	fmt.Fprintf(w, "%-19s %-19s %5s %5s %8s %-3s %s\n", "FIRST_SEEN", "LAST_SEEN", "RUNS", "%CPU", "RSS", "SRC", "COMMAND")
	for _, r := range rows {
		src := ""
		switch {
		case r.EventRuns == r.Runs:
			src = "ev"
		case r.EventRuns > 0:
			src = "ev~" // some runs only seen through events
		}
		fmt.Fprintf(w, "%-19s %-19s %5d %5.1f %8d %-3s %s\n", FormatMS(r.FirstSeen), FormatMS(r.LastSeen),
			r.Runs, r.PeakCPU, r.PeakRSSKB, src, strings.TrimSpace(r.Command))
	}
}
