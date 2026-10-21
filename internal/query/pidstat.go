package query

import (
	"database/sql"
	"fmt"
	"io"
	"regexp"
	"strings"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// PidstatRow is one process in a pidstat report: the values of every
// report (-u, -r, -d, -w) over the span; the printer picks the columns.
type PidstatRow struct {
	TS      int64   `json:"ts_ms"`
	UID     int     `json:"uid"`
	PID     int     `json:"pid"`
	Usr     float64 `json:"pct_usr"`
	System  float64 `json:"pct_system"`
	Guest   float64 `json:"pct_guest"`
	Wait    float64 `json:"pct_wait"`
	CPU     float64 `json:"pct_cpu"`
	Proc    int     `json:"cpu"`
	MinFlt  float64 `json:"minflt_s"`
	MajFlt  float64 `json:"majflt_s"`
	VSZ     int64   `json:"vsz_kb"`
	RSS     int64   `json:"rss_kb"`
	Mem     float64 `json:"pct_mem"`
	KBRd    float64 `json:"kb_rd_s"` // -1: not recorded (clifrd --proc-io=false)
	KBWr    float64 `json:"kb_wr_s"`
	KBCcwr  float64 `json:"kb_ccwr_s"`
	IODelay int64   `json:"iodelay"` // block I/O delay in clock ticks
	Cswch   float64 `json:"cswch_s"`
	Nvcswch float64 `json:"nvcswch_s"`
	Command string  `json:"command"`
	Comm    string  `json:"comm"`
	// Which reports it has activity in (pidstat lists only those without -p).
	active [4]bool
	listed bool // named with -p: in every report
}

// Pidstat activities, in the order of pidstat's reports and -h columns.
const (
	PidCPU = iota // -u
	PidMem        // -r
	PidIO         // -d
	PidCtx        // -w
)

// PidstatSelect: -p (PIDs: every one listed, active or not), -C (a regular
// expression on the command name), -l (the command line as COMMAND).
type PidstatSelect struct {
	All     bool // -p ALL: every process, active or not
	PIDs    []int
	Comm    *regexp.Regexp
	CmdLine bool
}

// Pidstat computes one report per span. A span from 0 is since boot (what
// pidstat prints without an interval): values over the uptime at the span's
// end. Spans end at process samples; processes only seen through events
// have no values and are left out, as are processes without activity in the
// reports asked for (unless listed with -p).
func Pidstat(db *store.DB, spans []Span, acts []int, sel PidstatSelect) ([]PidstatRow, error) {
	memKB := metaInt(db, "mem_total_kb")
	procIO := MetaAt(db, "proc_io", spans[0].To) != "false"
	var out []PidstatRow
	for _, sp := range spans {
		cur, err := processesAt(db, sp.To, sp.To)
		if err != nil {
			return nil, err
		}
		var upTo, upFrom sql.NullInt64
		db.QueryRow(`SELECT uptime_ms FROM sys_samples WHERE ts = ?`, sp.To).Scan(&upTo)
		prev := map[int64]procAt{}
		secs := float64(upTo.Int64) / 1000
		if sp.From != 0 {
			db.QueryRow(`SELECT uptime_ms FROM sys_samples WHERE ts = ?`, sp.From).Scan(&upFrom)
			secs = float64(upTo.Int64-upFrom.Int64) / 1000
			ps, err := processesAt(db, sp.From, sp.From)
			if err != nil {
				return nil, err
			}
			for _, p := range ps {
				prev[p.id] = p
			}
		}
		if !upTo.Valid || secs <= 0 {
			return nil, fmt.Errorf("pidstat: no system uptime recorded at %s", FormatMS(sp.To))
		}
		for _, c := range cur {
			if !c.state.Valid {
				continue
			}
			if !c.prio.Valid {
				return nil, fmt.Errorf("pidstat: needs a recording made since 2026-10-22 (schema 8); this one has no user/system split")
			}
			if sel.Comm != nil && !sel.Comm.MatchString(c.comm) {
				continue
			}
			listed := sel.All
			for _, pid := range sel.PIDs {
				listed = listed || pid == c.pid
			}
			if len(sel.PIDs) > 0 && !listed {
				continue
			}
			p := prev[c.id] // zero values: since boot, or started within the span
			d := func(f func(procAt) sql.NullInt64) int64 { return max(f(c).Int64-f(p).Int64, 0) }
			ticks := float64(procfs.ClockTicks) * secs
			utime := func(x procAt) sql.NullInt64 {
				return sql.NullInt64{Int64: x.cpuTicks.Int64 - x.stime.Int64 - x.guest.Int64, Valid: true}
			}
			stime := d(func(x procAt) sql.NullInt64 { return x.stime })
			guest := d(func(x procAt) sql.NullInt64 { return x.guest })
			usr := d(utime)
			// pidstat converts the run-queue wait to clock ticks first.
			waitTicks := func(x procAt) sql.NullInt64 {
				return sql.NullInt64{Int64: x.waitNS.Int64 * procfs.ClockTicks / 1e9, Valid: true}
			}
			r := PidstatRow{TS: sp.To, UID: int(c.ruid.Int64), PID: c.pid, Proc: int(c.psr.Int64), Comm: c.comm, Command: c.comm,
				Usr: float64(usr) / ticks * 100, System: float64(stime) / ticks * 100, Guest: float64(guest) / ticks * 100,
				Wait: float64(d(waitTicks)) / ticks * 100, CPU: float64(usr+stime+guest) / ticks * 100,
				MinFlt: float64(d(func(x procAt) sql.NullInt64 { return x.minFlt })) / secs,
				MajFlt: float64(d(func(x procAt) sql.NullInt64 { return x.majFlt })) / secs,
				VSZ:    c.vszKB.Int64, RSS: c.rssStat.Int64,
				IODelay: d(func(x procAt) sql.NullInt64 { return x.blkio }),
				Cswch:   float64(d(func(x procAt) sql.NullInt64 { return x.volCtx })) / secs,
				Nvcswch: float64(d(func(x procAt) sql.NullInt64 { return x.nonVolCtx })) / secs}
			if sel.CmdLine && c.cmdline != "" {
				r.Command = c.cmdline
			}
			if memKB > 0 {
				r.Mem = float64(r.RSS) * 100 / float64(memKB)
			}
			rd, wr := d(func(x procAt) sql.NullInt64 { return x.rbytes }), d(func(x procAt) sql.NullInt64 { return x.wbytes })
			cc := max(c.cancelled.Int64-p.cancelled.Int64, 0)
			r.KBRd, r.KBWr, r.KBCcwr = float64(rd)/1024/secs, float64(wr)/1024/secs, float64(cc)/1024/secs
			if !procIO {
				r.KBRd, r.KBWr, r.KBCcwr = -1, -1, -1
			}
			r.active = [4]bool{
				PidCPU: usr+stime+guest != 0,
				PidMem: r.MinFlt != 0 || r.MajFlt != 0,
				PidIO:  rd != 0 || wr != 0 || cc != 0 || r.IODelay != 0,
				PidCtx: r.Cswch != 0 || r.Nvcswch != 0,
			}
			show := listed
			for _, a := range acts {
				show = show || r.active[a]
			}
			r.listed = listed
			if show {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

// PrintPidstat prints the reports in pidstat's layout (sysstat 12, C
// locale), without its first line (kernel, host, date): one section per
// activity per span, or with -h (oneLine) every activity on one line.
func PrintPidstat(w io.Writer, rows []PidstatRow, acts []int, oneLine bool) {
	heads := [4]string{
		PidCPU: "    %usr %system  %guest   %wait    %CPU   CPU",
		PidMem: "  minflt/s  majflt/s     VSZ     RSS   %MEM",
		PidIO:  "   kB_rd/s   kB_wr/s kB_ccwr/s iodelay",
		PidCtx: "   cswch/s nvcswch/s",
	}
	vals := func(r PidstatRow, a int) string {
		switch a {
		case PidCPU:
			return fmt.Sprintf(" %7.2f %7.2f %7.2f %7.2f %7.2f %5d", r.Usr, r.System, r.Guest, r.Wait, r.CPU, r.Proc)
		case PidMem:
			return fmt.Sprintf(" %9.2f %9.2f %7d %7d %6.2f", r.MinFlt, r.MajFlt, r.VSZ, r.RSS, r.Mem)
		case PidIO:
			return fmt.Sprintf(" %9.2f %9.2f %9.2f %7d", r.KBRd, r.KBWr, r.KBCcwr, r.IODelay)
		}
		return fmt.Sprintf(" %9.2f %9.2f", r.Cswch, r.Nvcswch)
	}
	shown := func(r PidstatRow, as []int) bool {
		for _, a := range as {
			if r.active[a] {
				return true
			}
		}
		return false
	}
	first := true
	section := func(ts int64, as []int, label string) {
		var b strings.Builder
		if !first {
			b.WriteString("\n")
		}
		first = false
		fmt.Fprintf(&b, "%-11s %5s %9s", label, "UID", "PID")
		for _, a := range as {
			b.WriteString(heads[a])
		}
		b.WriteString("  Command\n")
		for _, r := range rows {
			// A listed (-p) process is in every report; the others only in
			// those they had activity in.
			if r.TS != ts || !shown(r, as) && !r.listed {
				continue
			}
			fmt.Fprintf(&b, "%-11s %5d %9d", clock(r.TS), r.UID, r.PID)
			for _, a := range as {
				b.WriteString(vals(r, a))
			}
			b.WriteString("  " + r.Command + "\n")
		}
		io.WriteString(w, b.String())
	}
	var stamps []int64
	for _, r := range rows {
		if len(stamps) == 0 || stamps[len(stamps)-1] != r.TS {
			stamps = append(stamps, r.TS)
		}
	}
	for _, ts := range stamps {
		if oneLine {
			section(ts, acts, "# Time")
			continue
		}
		for _, a := range acts {
			section(ts, []int{a}, clock(ts))
		}
	}
}
