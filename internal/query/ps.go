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
	User     string  `json:"user"`
	PID      int     `json:"pid"`
	PPID     int     `json:"ppid"`
	CPU      string  `json:"pcpu"`
	Mem      string  `json:"pmem"`
	VSZ      int64   `json:"vsz_kb"`
	RSS      int64   `json:"rss_kb"`
	TTY      string  `json:"tty"`
	Stat     string  `json:"stat"`
	Start    string  `json:"start"`
	Time     string  `json:"time"`
	Command  string  `json:"command"`
	StartMS  int64   `json:"start_time_ms"`
	Source   string  `json:"source"`
	cpuPct   float64 // unrounded, for tests
	UIDNum   int     `json:"uid"`
	CommName string  `json:"comm"`
	Nice     int     `json:"nice"`
	Threads  int     `json:"threads"`
	CPUTicks int64   `json:"cpu_ticks"` // -1 when not sampled
	ElapsedS int64   `json:"elapsed_s"` // at the moment asked for (exact)
	// Cumulative I/O at the sample (schema 2; 0 when not recorded).
	IORChar      int64 `json:"io_rchar"`
	IOWChar      int64 `json:"io_wchar"`
	IOReadBytes  int64 `json:"io_read_bytes"`
	IOWriteBytes int64 `json:"io_write_bytes"`
	// Schema 8 (Known false in older recordings: printed as "-", PRI as
	// 20 + NI).
	Known      bool   `json:"-"`
	Flags      int    `json:"flags"`    // ps's F
	Priority   int    `json:"priority"` // the kernel's (top's PR)
	Policy     int    `json:"policy"`   // SCHED_*
	RTPriority int    `json:"rt_priority"`
	Processor  int    `json:"processor"`
	MinFlt     int64  `json:"min_flt"`
	MajFlt     int64  `json:"maj_flt"`
	VolCtx     int64  `json:"vol_ctx"`
	NonVolCtx  int64  `json:"nonvol_ctx"`
	Wchan      string `json:"wchan"` // as ps prints it: "-" while running
	Label      string `json:"label"`
	Cgroup     string `json:"cgroup"`
	// For the other ps formats (psfmt.go).
	args      string
	permille  uint64 // %CPU in tenths
	nowMS     int64  // the sample's time
	startDisp int64  // start time as ps computes it (btime in whole seconds)
	forest    string // ps f: the tree prefix of COMMAND (PSForest)
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
	rchar, wchar, rbytes   sql.NullInt64
	wbytes                 sql.NullInt64
	// Schema 8 (NULL in older recordings).
	minFlt, majFlt, shrKB, psFlags sql.NullInt64
	prio, policy, rtPrio, psr      sql.NullInt64
	volCtx, nonVolCtx              sql.NullInt64
	wchan, label, cgroup           sql.NullString
}

// processesAt returns processes alive at t: those alive at sample s (with
// their values at s), plus processes that events show started between s and
// t. Processes with an exit event at or before t are left out.
func processesAt(db *store.DB, s, t int64) ([]procAt, error) {
	rows, err := db.Query(`
		SELECT p.id, p.pid, p.ppid, p.uid, p.start_time, p.tty, p.sid, p.pgrp, p.locked, p.comm,
		       p.cmdline, p.source, x.state, x.nice, x.tpgid, x.threads, x.cpu_ticks, x.rss_kb, x.vsz_kb,
		       x.rchar, x.wchar, x.read_bytes, x.write_bytes,
		       x.min_flt, x.maj_flt, x.shr_kb, x.ps_flags, x.priority, x.policy, x.rt_priority, x.processor,
		       x.vol_ctx, x.nonvol_ctx, x.wchan, p.label, p.cgroup
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
			&p.rssKB, &p.vszKB, &p.rchar, &p.wchar, &p.rbytes, &p.wbytes,
			&p.minFlt, &p.majFlt, &p.shrKB, &p.psFlags, &p.prio, &p.policy, &p.rtPrio, &p.psr,
			&p.volCtx, &p.nonVolCtx, &p.wchan, &p.label, &p.cgroup); err != nil {
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
	strip := StyleAt(db, s).PsWchanStrip
	out := make([]PSRow, 0, len(procs))
	for _, p := range procs {
		r := psRow(p, s, memKB)
		r.Wchan = psWchan(r.Wchan, strip)
		r.Start = psStart(p.startMS-skew, s)
		r.startDisp = p.startMS - skew
		r.ElapsedS = max(t-p.startMS, 0) / 1000
		out = append(out, r)
	}
	return out, s, nil
}

func psRow(p procAt, now, memKB int64) PSRow {
	r := PSRow{User: UserName(p.uid, true), PID: p.pid, PPID: p.ppid, TTY: procfs.TTYName(p.tty),
		StartMS: p.startMS, Source: p.source, VSZ: p.vszKB.Int64, RSS: p.rssKB.Int64,
		UIDNum: p.uid, CommName: p.comm, Nice: int(p.nice.Int64), Threads: int(p.threads.Int64), CPUTicks: -1, nowMS: now,
		IORChar: p.rchar.Int64, IOWChar: p.wchar.Int64, IOReadBytes: p.rbytes.Int64, IOWriteBytes: p.wbytes.Int64}
	r.Start = psStart(p.startMS, now)
	if !p.state.Valid { // event-only: no per-sample values were captured
		r.CPU, r.Mem, r.Stat, r.Time = "-", "-", "-", "-"
		r.Command = commandOf(p.cmdline, p.comm, "")
		r.args = r.Command
		return r
	}
	ticks := p.cpuTicks.Int64
	r.CPUTicks = ticks
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
	r.Label, r.Cgroup = p.label.String, p.cgroup.String
	if p.prio.Valid {
		r.Known = true
		r.Flags, r.Priority, r.Policy, r.RTPriority = int(p.psFlags.Int64), int(p.prio.Int64), int(p.policy.Int64), int(p.rtPrio.Int64)
		r.Processor, r.MinFlt, r.MajFlt = int(p.psr.Int64), p.minFlt.Int64, p.majFlt.Int64
		r.VolCtx, r.NonVolCtx, r.Wchan = p.volCtx.Int64, p.nonVolCtx.Int64, p.wchan.String
	}
	return r
}

// psWchan is WCHAN as ps prints it: "-" while running or unknown, without
// leading underscores; procps 3.3 strips a leading "do_" or "sys_" instead
// when there is one.
func psWchan(w string, strip bool) string {
	if w == "" || w == "0" {
		return "-"
	}
	switch {
	case strip && strings.HasPrefix(w, "sys_"):
		return w[4:]
	case strip && strings.HasPrefix(w, "do_"):
		return w[3:]
	}
	return strings.TrimLeft(w, "_")
}

// niceClass: SCHED_OTHER and SCHED_BATCH, the policies whose nice value ps
// prints as NI; for the others (FIFO, RR, IDLE, DEADLINE) NI is "-" and
// RTPRIO the real-time priority.
func niceClass(policy int) bool { return policy == 0 || policy == 3 }

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

// psStart formats START (STIME) like procps: HH:MM on the same day, MonDD
// in the same year, otherwise the year.
func psStart(startMS, nowMS int64) string {
	// procps's pr_stime: by local calendar day, not by age.
	t, now := time.UnixMilli(startMS), time.UnixMilli(nowMS)
	switch {
	case t.Year() != now.Year():
		return t.Format(" 2006")
	case t.YearDay() != now.YearDay():
		return t.Format("Jan02")
	}
	return t.Format("15:04")
}

func PrintPS(w io.Writer, rows []PSRow) {
	fmt.Fprintf(w, "%-8s %7s %4s %4s %6s %5s %-8s %-4s %5s %6s %s\n",
		"USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY", "STAT", "START", "TIME", "COMMAND")
	for _, r := range rows {
		fmt.Fprintf(w, "%-8s %7d %4s %4s %6d %5d %-8s %-4s %5s %6s %s\n",
			r.User, r.PID, r.CPU, r.Mem, r.VSZ, r.RSS, r.TTY, r.Stat, r.Start, r.Time, r.forest+r.Command)
	}
}

func PrintPSJSON(w io.Writer, rows []PSRow) error { return writeJSON(w, rows) }
