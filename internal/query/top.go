package query

import (
	"database/sql"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// TopReport is `top -b -n 1` at a moment: the summary from the system sample
// at or before it, and every process with its %CPU over the interval from
// the process sample before to the one at or before it (top's own first
// screen covers a fraction of a second; clifr's resolution is the sample
// interval).
type TopReport struct {
	SampleTS int64     `json:"sample_ts_ms"` // the process sample
	PrevTS   int64     `json:"prev_ts_ms"`   // the sample %CPU is measured from (0: since each process started)
	Uptime   UptimeRow `json:"uptime"`
	Tasks    TopTasks  `json:"tasks"`
	CPU      TopCPU    `json:"cpu"`
	Mem      TopMem    `json:"mem"`
	Procs    []TopRow  `json:"procs"`
}

type TopTasks struct {
	Total    int `json:"total"`
	Running  int `json:"running"`
	Sleeping int `json:"sleeping"` // S, D and I, and processes without a sample
	Stopped  int `json:"stopped"`
	Zombie   int `json:"zombie"`
}

// TopCPU is the time split of all CPUs, in %, over FromTS..ToTS (FromTS 0:
// since boot).
type TopCPU struct {
	FromTS int64   `json:"from_ts_ms"`
	ToTS   int64   `json:"to_ts_ms"`
	Us     float64 `json:"us"`
	Sy     float64 `json:"sy"`
	Ni     float64 `json:"ni"`
	Id     float64 `json:"id"`
	Wa     float64 `json:"wa"`
	Hi     float64 `json:"hi"`
	Si     float64 `json:"si"`
	St     float64 `json:"st"`
}

// TopMem is in KiB; used = total - available (procps-ng 4).
type TopMem struct {
	Total     int64 `json:"mem_total_kb"`
	Free      int64 `json:"mem_free_kb"`
	Used      int64 `json:"mem_used_kb"`
	BuffCache int64 `json:"buff_cache_kb"`
	SwapTotal int64 `json:"swap_total_kb"`
	SwapFree  int64 `json:"swap_free_kb"`
	SwapUsed  int64 `json:"swap_used_kb"`
	Available int64 `json:"available_kb"`
}

// TopRow is one process line. PR is 20 + NI: the scheduling policy is not
// recorded, so a real-time process shows its nice-based priority, not "rt".
// SHR is not recorded. Sampled false: only seen through exec/exit events,
// no values.
type TopRow struct {
	PID     int     `json:"pid"`
	User    string  `json:"user"`
	PR      int     `json:"pr"`
	NI      int     `json:"ni"`
	VirtKB  int64   `json:"virt_kb"`
	ResKB   int64   `json:"res_kb"`
	S       string  `json:"s"`
	CPU     float64 `json:"pcpu"`
	Mem     float64 `json:"pmem"`
	TimeCS  int64   `json:"time_cs"` // CPU time in hundredths of a second
	Comm    string  `json:"comm"`
	Command string  `json:"command"` // the command line, as top -c shows it
	UID     int     `json:"uid"`
	StartMS int64   `json:"start_time_ms"`
	Sampled bool    `json:"sampled"`
}

// TopAt reconstructs top at t, the processes sorted by %CPU (then PID).
func TopAt(db *store.DB, t int64) (TopReport, error) {
	var rep TopReport
	s, err := SnapshotAt(db, t, false)
	if err != nil {
		return rep, err
	}
	rep.SampleTS = s
	var prev sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM samples WHERE skipped = 0 AND ts < ?`, s).Scan(&prev); err != nil {
		return rep, err
	}
	rep.PrevTS = prev.Int64
	procs, err := processesAt(db, s, t)
	if err != nil {
		return rep, err
	}
	before := map[int64]int64{} // CPU ticks at the previous sample, by process id
	if prev.Valid {
		rows, err := db.Query(`SELECT proc_id, arg_max(cpu_ticks, ts) FROM proc_samples WHERE ts <= ? GROUP BY proc_id`, prev.Int64)
		if err != nil {
			return rep, err
		}
		for rows.Next() {
			var id, ticks int64
			if err := rows.Scan(&id, &ticks); err != nil {
				rows.Close()
				return rep, err
			}
			before[id] = ticks
		}
		rows.Close()
	}

	spans, err := SysSpans(db, Window{At: t}, 0)
	if err != nil {
		return rep, err
	}
	sys, err := loadSys(db, spans[0].To)
	if err != nil {
		return rep, err
	}
	up, err := Uptime(db, spans)
	if err != nil {
		return rep, err
	}
	rep.Uptime = up[0]
	rep.Mem = TopMem{Total: sys.MemTotal, Free: sys.MemFree, BuffCache: sys.Buffers + sys.Cached + sys.SReclaimable,
		SwapTotal: sys.SwapTotal, SwapFree: sys.SwapFree, SwapUsed: sys.SwapTotal - sys.SwapFree, Available: sys.MemAvailable}
	rep.Mem.Used = rep.Mem.Total - rep.Mem.Available
	if rep.Mem.Available > rep.Mem.Total {
		rep.Mem.Used = rep.Mem.Total - rep.Mem.Free
	}
	if rep.CPU, err = topCPU(db, spans[0].To); err != nil {
		return rep, err
	}

	for _, p := range procs {
		r := TopRow{PID: p.pid, User: UserName(p.uid, false), NI: int(p.nice.Int64), PR: 20 + int(p.nice.Int64),
			VirtKB: p.vszKB.Int64, ResKB: p.rssKB.Int64, Comm: p.comm, UID: p.uid, StartMS: p.startMS, S: "-",
			Command: commandOf(p.cmdline, p.comm, p.state.String), Sampled: p.state.Valid}
		rep.Tasks.Total++
		if !p.state.Valid {
			rep.Tasks.Sleeping++
			rep.Procs = append(rep.Procs, r)
			continue
		}
		r.S = p.state.String
		switch r.S {
		case "R":
			rep.Tasks.Running++
		case "T", "t":
			rep.Tasks.Stopped++
		case "Z":
			rep.Tasks.Zombie++
		default: // S, D, I
			rep.Tasks.Sleeping++
		}
		ticks := p.cpuTicks.Int64
		r.TimeCS = ticks * 100 / procfs.ClockTicks
		from, base := p.startMS, int64(0)
		if prev.Valid && prev.Int64 > p.startMS {
			from, base = prev.Int64, before[p.id]
		}
		if secs := float64(s-from) / 1000; secs > 0 {
			r.CPU = float64(max(ticks-base, 0)) / float64(procfs.ClockTicks) / secs * 100
		}
		if sys.MemTotal > 0 {
			r.Mem = float64(r.ResKB) * 100 / float64(sys.MemTotal)
		}
		rep.Procs = append(rep.Procs, r)
	}
	SortTop(rep.Procs, "%CPU")
	return rep, nil
}

// topCPU is the CPU split from the system sample before ts to ts (since
// boot when there is none, or the machine rebooted in between).
func topCPU(db *store.DB, ts int64) (TopCPU, error) {
	sp := Span{To: ts}
	var prev, prevUp, up sql.NullInt64
	db.QueryRow(`SELECT MAX(ts) FROM sys_samples WHERE ts < ?`, ts).Scan(&prev)
	if prev.Valid {
		db.QueryRow(`SELECT uptime_ms FROM sys_samples WHERE ts = ?`, prev.Int64).Scan(&prevUp)
		db.QueryRow(`SELECT uptime_ms FROM sys_samples WHERE ts = ?`, ts).Scan(&up)
		if up.Int64 >= prevUp.Int64 {
			sp.From = prev.Int64
		}
	}
	cpus, err := cpuDelta(db, sp)
	if err != nil {
		return TopCPU{}, err
	}
	c := cpus[-1]
	total := float64(cpuTotal(c))
	p := func(v int64) float64 {
		if total == 0 {
			return 0
		}
		return 100 * float64(v) / total
	}
	out := TopCPU{FromTS: sp.From, ToTS: ts, Us: p(c[cUser]), Sy: p(c[cSystem]), Ni: p(c[cNice]), Id: p(c[cIdle]),
		Wa: p(c[cIOWait]), Hi: p(c[cIRQ]), Si: p(c[cSoftIRQ]), St: p(c[cSteal])}
	if total == 0 {
		out.Id = 100
	}
	return out, nil
}

// TopFields are the sort fields of top -o, by their column names.
var TopFields = []string{"PID", "USER", "PR", "NI", "VIRT", "RES", "S", "%CPU", "%MEM", "TIME+", "COMMAND"}

// SortTop sorts the rows by field, largest first (as top does; PID, USER and
// COMMAND too), then by PID; rows without values go last.
func SortTop(rows []TopRow, field string) {
	less := func(a, b *TopRow) int { // > 0: a first
		switch field {
		case "PID":
			return b.PID - a.PID
		case "USER":
			return strings.Compare(b.User, a.User)
		case "PR", "NI":
			return a.NI - b.NI
		case "VIRT":
			return cmp64(a.VirtKB, b.VirtKB)
		case "RES", "%MEM":
			return cmp64(a.ResKB, b.ResKB)
		case "S":
			return strings.Compare(b.S, a.S)
		case "TIME+":
			return cmp64(a.TimeCS, b.TimeCS)
		case "COMMAND":
			return strings.Compare(b.Comm, a.Comm)
		}
		switch {
		case a.CPU > b.CPU:
			return 1
		case a.CPU < b.CPU:
			return -1
		}
		return 0
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := &rows[i], &rows[j]
		if a.Sampled != b.Sampled {
			return a.Sampled
		}
		if c := less(a, b); c != 0 {
			return c > 0
		}
		return a.PID < b.PID
	})
}

func cmp64(a, b int64) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	}
	return 0
}

// TopFormat holds top's output options.
type TopFormat struct {
	Width   int  // line width; longer lines end in "+" (80, as top -b without -w)
	CmdLine bool // -c: the command line instead of the name
}

// PrintTop prints the report like procps-ng 4 top -b -n 1 (without the
// number of users, which is not recorded; SHR as "-").
func PrintTop(w io.Writer, r TopReport, f TopFormat) {
	min := r.Uptime.UptimeS / 60
	days, hours, min := min/1440, min/60%24, min%60
	up := ""
	if days > 0 {
		up = fmt.Sprintf("%d day", days)
		if days > 1 {
			up += "s"
		}
		up += ", "
	}
	if hours > 0 {
		up += fmt.Sprintf("%2d:%02d, ", hours, min)
	} else {
		up += fmt.Sprintf("%d min, ", min)
	}
	fmt.Fprintf(w, "top - %s up %s load average: %.2f, %.2f, %.2f\n", clock(r.Uptime.TS), up,
		r.Uptime.Load1, r.Uptime.Load5, r.Uptime.Load15)
	t := r.Tasks
	fmt.Fprintf(w, "Tasks: %3d total, %3d running, %3d sleeping, %3d stopped, %3d zombie\n",
		t.Total, t.Running, t.Sleeping, t.Stopped, t.Zombie)
	c := r.CPU
	fmt.Fprintf(w, "%%Cpu(s): %4.1f us, %4.1f sy, %4.1f ni, %4.1f id, %4.1f wa, %4.1f hi, %4.1f si, %4.1f st\n",
		c.Us, c.Sy, c.Ni, c.Id, c.Wa, c.Hi, c.Si, c.St)
	mib := func(kb int64) float64 { return float64(kb) / 1024 }
	m := r.Mem
	fmt.Fprintf(w, "MiB Mem : %8.1f total, %8.1f free, %8.1f used, %8.1f buff/cache\n",
		mib(m.Total), mib(m.Free), mib(m.Used), mib(m.BuffCache))
	fmt.Fprintf(w, "MiB Swap: %8.1f total, %8.1f free, %8.1f used. %8.1f avail Mem\n",
		mib(m.SwapTotal), mib(m.SwapFree), mib(m.SwapUsed), mib(m.Available))
	fmt.Fprintln(w)
	line := func(s string) { // top -b uses width - 1 columns, the last a "+" when cut
		if f.Width > 1 && len(s) > f.Width-1 {
			s = s[:f.Width-2] + "+"
		}
		fmt.Fprintln(w, s)
	}
	line("    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND")
	for _, p := range r.Procs {
		cmd := p.Comm
		if f.CmdLine {
			cmd = p.Command
		}
		user := p.User
		if len(user) > 8 {
			user = user[:7] + "+"
		}
		if !p.Sampled {
			line(fmt.Sprintf("%7d %-8s %3s %3s %7s %6s %6s %s %5s %5s %9s %s", p.PID, user, "-", "-", "-", "-", "-", "-", "-", "-", "-", cmd))
			continue
		}
		line(fmt.Sprintf("%7d %-8s %3d %3d %7s %6s %6s %s %5.1f %5.1f %9s %s", p.PID, user, p.PR, p.NI,
			topMem(p.VirtKB, 7), topMem(p.ResKB, 6), "-", p.S, p.CPU, p.Mem, topTime(p.TimeCS), cmd))
	}
}

// topMem is a KiB value in a column of width w: the number if it fits, else
// the first of m, g, t, ... in which it fits with one decimal (top's "53.5g").
func topMem(kb int64, w int) string {
	if s := strconv.FormatInt(kb, 10); len(s) <= w {
		return s
	}
	v := float64(kb)
	for _, u := range "mgtpe" {
		v /= 1024
		if s := fmt.Sprintf("%.1f%c", v, u); len(s) <= w {
			return s
		}
	}
	return strconv.FormatInt(kb, 10)
}

// topTime is TIME+: minutes:seconds.hundredths, or minutes:seconds when that
// does not fit 9 characters.
func topTime(cs int64) string {
	secs := cs / 100
	if s := fmt.Sprintf("%d:%02d.%02d", secs/60, secs%60, cs%100); len(s) <= 9 {
		return s
	}
	return fmt.Sprintf("%d:%02d", secs/60, secs%60)
}
