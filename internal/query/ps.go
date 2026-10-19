package query

import (
	"database/sql"
	"fmt"
	"io"
	"strings"
	"time"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// PSRow is one process as `ps aux` would show it at a point in time.
type PSRow struct {
	User    string  `json:"user"`
	PID     int     `json:"pid"`
	PPID    int     `json:"ppid"`
	CPU     string  `json:"pcpu"`
	Mem     string  `json:"pmem"`
	VSZ     int64   `json:"vsz_kb"`
	RSS     int64   `json:"rss_kb"`
	TTY     string  `json:"tty"`
	Stat    string  `json:"stat"`
	Start   string  `json:"start"`
	Time    string  `json:"time"`
	Command string  `json:"command"`
	StartMS int64   `json:"start_time_ms"`
	Source  string  `json:"source"`
	cpuPct  float64 // unrounded, for tests
	// For the other ps formats (psfmt.go).
	uid, nice, threads int
	comm, args         string
	ticks              int64  // CPU time in clock ticks; -1 when not sampled
	permille           uint64 // %CPU in tenths
	nowMS              int64  // the sample's time
	startDisp          int64  // start time as ps computes it (btime in whole seconds)
	atMS               int64  // the moment asked for: elapsed times are exact there
}

type procAt struct {
	id, startMS            int64
	pid, ppid, uid, tty    int
	sid, pgrp              int
	locked                 bool
	comm, cmdline, source  string
	state                  sql.NullString
	nice, tpgid, threads   sql.NullInt64
	cpuTicks, rssKB, vszKB sql.NullInt64
}

// processesAt returns processes alive at t: those alive at sample s (with
// their values at s), plus processes that events show started between s and
// t. Processes with an exit event at or before t are left out.
func processesAt(db *store.DB, s, t int64) ([]procAt, error) {
	rows, err := db.Query(`
		SELECT p.id, p.pid, p.ppid, p.uid, p.start_time, p.tty, p.sid, p.pgrp, p.locked, p.comm,
		       p.cmdline, p.source, x.state, x.nice, x.tpgid, x.threads, x.cpu_ticks, x.rss_kb, x.vsz_kb
		FROM processes p
		LEFT JOIN proc_samples x ON x.proc_id = p.id
		     AND x.ts = (SELECT MAX(ts) FROM proc_samples WHERE proc_id = p.id AND ts <= ?1)
		WHERE ((p.first_seen <= ?1 AND COALESCE(p.last_seen, ?3) >= ?1)
		       OR (p.first_seen > ?1 AND p.first_seen <= ?2))
		  AND (p.ended IS NULL OR p.ended > ?2)
		ORDER BY p.pid`, s, t, openEnd)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []procAt
	for rows.Next() {
		var p procAt
		var locked int
		if err := rows.Scan(&p.id, &p.pid, &p.ppid, &p.uid, &p.startMS, &p.tty, &p.sid, &p.pgrp, &locked,
			&p.comm, &p.cmdline, &p.source, &p.state, &p.nice, &p.tpgid, &p.threads, &p.cpuTicks,
			&p.rssKB, &p.vszKB); err != nil {
			return nil, err
		}
		p.locked = locked == 1
		out = append(out, p)
	}
	return out, rows.Err()
}

// PSAt reconstructs `ps aux` at time t.
func PSAt(db *store.DB, t int64) ([]PSRow, int64, error) {
	s, err := SnapshotAt(db, t, false)
	if err != nil {
		return nil, 0, err
	}
	procs, err := processesAt(db, s, t)
	if err != nil {
		return nil, 0, err
	}
	memKB := metaInt(db, "mem_total_kb")
	// ps derives START from /proc/stat btime, which is truncated to whole
	// seconds; clifr stores precise start times. Shift back for display.
	skew := int64(0)
	if bms := metaInt(db, "boot_ms"); bms > 0 {
		skew = bms - metaInt(db, "boot_time")*1000
	}
	out := make([]PSRow, 0, len(procs))
	for _, p := range procs {
		r := psRow(p, s, memKB)
		r.Start = psStart(p.startMS-skew, s)
		r.startDisp, r.atMS = p.startMS-skew, t
		out = append(out, r)
	}
	return out, s, nil
}

func psRow(p procAt, now, memKB int64) PSRow {
	r := PSRow{User: UserName(p.uid, true), PID: p.pid, PPID: p.ppid, TTY: procfs.TTYName(p.tty),
		StartMS: p.startMS, Source: p.source, VSZ: p.vszKB.Int64, RSS: p.rssKB.Int64,
		uid: p.uid, comm: p.comm, nice: int(p.nice.Int64), threads: int(p.threads.Int64), ticks: -1, nowMS: now}
	r.Start = psStart(p.startMS, now)
	if !p.state.Valid { // event-only: no per-sample values were captured
		r.CPU, r.Mem, r.Stat, r.Time = "-", "-", "-", "-"
		r.Command = commandOf(p.cmdline, p.comm, "")
		r.args = r.Command
		return r
	}
	ticks := p.cpuTicks.Int64
	r.ticks = ticks
	// procps: pcpu = (cputime_ms) / elapsed_seconds, in tenths of a percent, truncated.
	if secs := (now - p.startMS) / 1000; secs > 0 {
		r.permille = uint64(ticks*1000/procfs.ClockTicks) / uint64(secs)
		r.CPU = tenths(r.permille)
		r.cpuPct = float64(ticks*1000/procfs.ClockTicks) / float64(secs) / 10
	} else {
		r.CPU = tenths(0)
	}
	if memKB > 0 {
		r.Mem = tenths(uint64(p.rssKB.Int64 * 1000 / memKB))
	} else {
		r.Mem = "-"
	}
	r.Stat = psStat(p)
	cpuSecs := ticks / procfs.ClockTicks
	r.Time = fmt.Sprintf("%d:%02d", cpuSecs/60, cpuSecs%60)
	r.Command = commandOf(p.cmdline, p.comm, p.state.String)
	r.args = r.Command
	return r
}

func tenths(permille uint64) string {
	if permille > 999 {
		return fmt.Sprintf("%d", permille/10)
	}
	return fmt.Sprintf("%d.%d", permille/10, permille%10)
}

func commandOf(cmdline, comm, state string) string {
	if state == "Z" {
		return "[" + comm + "] <defunct>"
	}
	if cmdline == "" {
		return "[" + comm + "]"
	}
	// ps shows control characters (e.g. newlines in bash -c scripts) as '?'.
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, cmdline)
}

// psStat builds the BSD STAT column: state, then <N L s l + flags.
func psStat(p procAt) string {
	var b strings.Builder
	b.WriteString(p.state.String)
	switch {
	case p.nice.Int64 < 0:
		b.WriteByte('<')
	case p.nice.Int64 > 0:
		b.WriteByte('N')
	}
	if p.locked {
		b.WriteByte('L')
	}
	if p.sid == p.pid {
		b.WriteByte('s')
	}
	if p.threads.Int64 > 1 {
		b.WriteByte('l')
	}
	if int64(p.pgrp) == p.tpgid.Int64 {
		b.WriteByte('+')
	}
	return b.String()
}

// psStart formats START like procps: HH:MM within 24h, MonDD within a year,
// otherwise the year.
func psStart(startMS, nowMS int64) string {
	t := time.UnixMilli(startMS)
	ago := time.Duration(nowMS-startMS) * time.Millisecond
	switch {
	case ago > 365*24*time.Hour:
		return t.Format(" 2006")
	case ago > 24*time.Hour:
		return t.Format("Jan02")
	}
	return t.Format("15:04")
}

func PrintPS(w io.Writer, rows []PSRow) {
	fmt.Fprintf(w, "%-8s %7s %4s %4s %6s %5s %-8s %-4s %5s %6s %s\n",
		"USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY", "STAT", "START", "TIME", "COMMAND")
	for _, r := range rows {
		fmt.Fprintf(w, "%-8s %7d %4s %4s %6d %5d %-8s %-4s %5s %6s %s\n",
			r.User, r.PID, r.CPU, r.Mem, r.VSZ, r.RSS, r.TTY, r.Stat, r.Start, r.Time, r.Command)
	}
}

func PrintPSJSON(w io.Writer, rows []PSRow) error { return writeJSON(w, rows) }
