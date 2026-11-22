// Reconstruction of htop's screen (htop 3.2.1, 3.3.0 and 3.4.1 for Linux).
//
// The layout, the meters and the process columns follow htop's code
// (Meter.c, CPUMeter.c, MemoryMeter.c, SwapMeter.c, TasksMeter.c,
// LoadAverageMeter.c, UptimeMeter.c, Header.c, Settings.c, Row.c, Process.c,
// Table.c, ScreenManager.c, linux/Platform.c, linux/LinuxMachine.c,
// linux/LinuxProcessTable.c), Copyright (C) 2004-2011 Hisham H. Muhammad and
// the htop dev team, GPL-2.0-or-later (htop 3.1.1 and later; see
// packaging/notices/htop.txt). htop 3.0.5 is GPL-2.0-only: its screen
// (htop30.go) is written from its output only, never from its code.

package query

import (
	"database/sql"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"unicode/utf8"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// HtopProc is one process line.
type HtopProc struct {
	PID     int     `json:"pid"`
	PPID    int     `json:"ppid"`
	UID     int     `json:"uid"`
	User    string  `json:"user"`
	Pri     int     `json:"pri"` // the kernel's priority (stat field 18); <= -100: RT
	Nice    int     `json:"ni"`
	VirtKB  int64   `json:"virt_kb"`
	ResKB   int64   `json:"res_kb"`
	ShrKB   int64   `json:"shr_kb"` // -1: not recorded (before schema 8)
	State   string  `json:"s"`
	CPU     float32 `json:"pcpu"`
	Mem     float32 `json:"pmem"`
	TimeCS  int64   `json:"time_cs"`
	Command string  `json:"command"`
	Kernel  bool    `json:"kernel_thread"`
	Threads int     `json:"threads"`
	Sampled bool    `json:"sampled"` // false: only seen through exec/exit events (no values)
}

// HtopCPU is one CPU's split over the interval, in %, as htop's CPU meter
// without detailed CPU time: nice, normal (user without guest), kernel
// (system, irq, softirq) and virtualisation (steal and guest).
type HtopCPU struct {
	Nice, Normal, Kernel, Virt float64
}

// HtopScreen is what htop shows at one refresh: the header's values and
// every process (kernel threads too: htop hides them by default).
type HtopScreen struct {
	SampleTS int64     `json:"sample_ts_ms"`
	PrevTS   int64     `json:"prev_ts_ms"` // the interval's start (0: since boot)
	CPUs     []HtopCPU `json:"cpus"`
	// Memory in KiB, from /proc/meminfo (htop's partition).
	MemTotal, MemFree, MemAvailable, Buffers, Cached, SReclaimable, Shmem int64
	SwapTotal, SwapFree, SwapCached, Zswap, Zswapped                      int64
	ProcsRunning                                                          int
	Load                                                                  [3]float64
	UptimeS                                                               int64
	PIDDigits                                                             int
	Procs                                                                 []HtopProc `json:"procs"`
}

// HtopAt is htop's screen at t: the processes alive at t with their values
// from the process sample at or before it, %CPU and the CPU meters over the
// interval since the process sample before (htop's refresh interval).
func HtopAt(db *store.DB, t int64) (HtopScreen, error) {
	var sc HtopScreen
	s, err := SnapshotAt(db, t, false)
	if err != nil {
		return sc, err
	}
	sc.SampleTS = s
	var prev sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM samples WHERE skipped = 0 AND ts < ?`, s).Scan(&prev); err != nil {
		return sc, err
	}
	var sysTS sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM sys_samples WHERE ts <= ?`, s).Scan(&sysTS); err != nil {
		return sc, err
	}
	if !sysTS.Valid {
		return sc, fmt.Errorf("no system counters recorded at or before %s", FormatMS(s))
	}
	sys, err := loadSys(db, sysTS.Int64)
	if err != nil {
		return sc, err
	}
	sp := Span{To: sysTS.Int64}
	if prev.Valid {
		var up sql.NullInt64
		db.QueryRow(`SELECT uptime_ms FROM sys_samples WHERE ts = ?`, prev.Int64).Scan(&up)
		if up.Valid && up.Int64 <= sys.UptimeMS {
			sp.From = prev.Int64
			sc.PrevTS = prev.Int64
		}
	}
	var zs, zd sql.NullInt64
	db.QueryRow(`SELECT zswap, zswapped FROM sys_samples WHERE ts = ?`, sysTS.Int64).Scan(&zs, &zd)
	sc.MemTotal, sc.MemFree, sc.MemAvailable, sc.Buffers, sc.Cached = sys.MemTotal, sys.MemFree, sys.MemAvailable, sys.Buffers, sys.Cached
	sc.SReclaimable, sc.Shmem, sc.SwapTotal, sc.SwapFree, sc.SwapCached = sys.SReclaimable, sys.Shmem, sys.SwapTotal, sys.SwapFree, sys.SwapCached
	sc.Zswap, sc.Zswapped = zs.Int64, zd.Int64
	sc.ProcsRunning = sys.ProcsRunning
	sc.Load = [3]float64{float64(sys.Load1) / 100, float64(sys.Load5) / 100, float64(sys.Load15) / 100}
	spans, err := SysSpans(db, Window{At: t}, 0)
	if err != nil {
		return sc, err
	}
	up, err := Uptime(db, spans)
	if err != nil {
		return sc, err
	}
	u := up[0]
	u.At(t)
	sc.UptimeS = u.UptimeS
	sc.PIDDigits = max(IotopPIDWidth(db, t), 5)

	cpus, err := cpuDelta(db, sp)
	if err != nil {
		return sc, err
	}
	n := 0
	for c := range cpus {
		n = max(n, c+1)
	}
	sc.CPUs = make([]HtopCPU, n)
	var period float64 // all CPUs' ticks in the interval per CPU (htop's period)
	for c, v := range cpus {
		user, nice := v[cUser]-v[cGuest], v[cNice]-v[cGuestNice]
		sysAll := v[cSystem] + v[cIRQ] + v[cSoftIRQ]
		virt := v[cGuest] + v[cGuestNice]
		total := float64(max(user, 0) + max(nice, 0) + sysAll + v[cIdle] + v[cIOWait] + v[cSteal] + virt)
		if c < 0 {
			if n > 0 {
				period = total / float64(n)
			}
			continue
		}
		if total == 0 {
			total = 1
		}
		sc.CPUs[c] = HtopCPU{Nice: float64(max(nice, 0)) / total * 100, Normal: float64(max(user, 0)) / total * 100,
			Kernel: float64(sysAll) / total * 100, Virt: float64(v[cSteal]+virt) / total * 100}
	}

	procs, err := processesAt(db, s, t)
	if err != nil {
		return sc, err
	}
	before := map[int64]int64{}
	if sc.PrevTS != 0 {
		rows, err := db.Query(`SELECT proc_id, arg_max(cpu_ticks, ts) FROM proc_samples WHERE ts <= ? GROUP BY proc_id`, sc.PrevTS)
		if err != nil {
			return sc, err
		}
		for rows.Next() {
			var id, ticks int64
			if err := rows.Scan(&id, &ticks); err != nil {
				rows.Close()
				return sc, err
			}
			before[id] = ticks
		}
		rows.Close()
	}
	for _, p := range procs {
		r := HtopProc{PID: p.pid, PPID: p.ppid, UID: p.uid, User: UserName(p.uid, false), Nice: int(p.nice.Int64),
			Pri: 20 + int(p.nice.Int64), VirtKB: p.vszKB.Int64, ResKB: p.rssKB.Int64, ShrKB: -1, State: p.state.String,
			Kernel: p.cmdline == "" && (p.pid == 2 || p.ppid == 2), Threads: max(int(p.threads.Int64), 1), Sampled: p.state.Valid}
		if p.prio.Valid {
			r.Pri, r.ShrKB = int(p.prio.Int64), p.shrKB.Int64
		}
		// htop reads at most 4096 bytes of /proc/PID/cmdline; a process
		// without one (a zombie) shows its name.
		r.Command = p.cmdline
		if len(r.Command) > 4096 {
			r.Command = strings.TrimRight(r.Command[:4096], " ")
		}
		if r.Command == "" {
			r.Command = p.comm
		}
		ticks := p.cpuTicks.Int64
		r.TimeCS = ticks * 100 / procfs.ClockTicks
		base := int64(0) // a process started in the interval: all its time (htop: first seen)
		if sc.PrevTS != 0 && sc.PrevTS > p.startMS {
			base = before[p.id]
		}
		if period > 0 && r.Sampled {
			r.CPU = min(float32(float64(max(ticks-base, 0))/period*100), float32(n)*100)
		}
		if sys.MemTotal > 0 {
			r.Mem = float32(float64(r.ResKB) / float64(sys.MemTotal) * 100)
		}
		sc.Procs = append(sc.Procs, r)
	}
	return sc, nil
}

// HtopOpts are htop's options clifr takes.
type HtopOpts struct {
	Tree    bool
	SortKey string // a column name of HtopSortKeys ("" PERCENT_CPU)
	PIDs    []int
	UIDs    []int
	NoColor bool   // -C: monochrome bars ("|#*@$%&." per item)
	Width   int    // screen columns
	Version string // ToolStyle.Htop: "" 3.4.1, "3.3" 3.3.0, "3.2" 3.2.1, "3.0" 3.0.5
}

// HtopSortKeys: the columns of the default screen htop -s takes.
var HtopSortKeys = []string{"PID", "USER", "PRIORITY", "NICE", "M_VIRT", "M_RESIDENT", "M_SHARE", "STATE", "PERCENT_CPU", "PERCENT_MEM", "TIME", "COMM"}

// htopSortDesc: the keys htop sorts largest first.
var htopSortDesc = map[string]bool{"M_VIRT": true, "M_RESIDENT": true, "M_SHARE": true, "PERCENT_CPU": true, "PERCENT_MEM": true, "TIME": true}

// htopStateOrder: htop's ProcessState values (sort by STATE), from stat's letter.
func htopStateOrder(s string) int {
	switch s {
	case "S":
		return 14
	case "X":
		return 12
	case "Z":
		return 11
	case "t":
		return 10
	case "T":
		return 9
	case "D":
		return 6
	case "R":
		return 3
	case "P":
		return 7
	case "I":
		return 13
	}
	return 1
}

// htopStateChar is the S column: stat's letter, P (parked) as B.
func htopStateChar(s string) string {
	switch s {
	case "":
		return "?"
	case "P":
		return "B"
	}
	return s[:1]
}

func htopCompare(a, b *HtopProc, key string) int {
	switch key {
	case "PID":
		return cmpInt(a.PID, b.PID)
	case "USER":
		return strings.Compare(a.User, b.User)
	case "PRIORITY":
		return cmpInt(a.Pri, b.Pri)
	case "NICE":
		return cmpInt(a.Nice, b.Nice)
	case "M_VIRT":
		return cmp64(a.VirtKB, b.VirtKB)
	case "M_RESIDENT", "PERCENT_MEM":
		return cmp64(a.ResKB, b.ResKB)
	case "M_SHARE":
		return cmp64(a.ShrKB, b.ShrKB)
	case "STATE":
		return cmpInt(htopStateOrder(a.State), htopStateOrder(b.State))
	case "TIME":
		return cmp64(a.TimeCS, b.TimeCS)
	case "COMM":
		return strings.Compare(a.Command, b.Command)
	}
	switch { // PERCENT_CPU
	case a.CPU < b.CPU:
		return -1
	case a.CPU > b.CPU:
		return 1
	}
	return 0
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// htopSort sorts as htop's Process_compare: by the key in its direction,
// ties by PID (ascending in either direction).
func htopSort(rows []*HtopProc, key string, desc bool) {
	slices.SortStableFunc(rows, func(a, b *HtopProc) int {
		r := htopCompare(a, b, key)
		if r == 0 {
			return cmpInt(a.PID, b.PID)
		}
		if desc {
			return -r
		}
		return r
	})
}

// htopLine is one line of the screen, written into by column.
type htopLine []rune

func (l *htopLine) put(x int, s string, width int) {
	for _, r := range s {
		if x >= width {
			return
		}
		for len(*l) <= x {
			*l = append(*l, ' ')
		}
		(*l)[x] = r
		x++
	}
}

// htopHumanUnit is htop's Meter_humanUnit (KiB in).
func htopHumanUnit(v float64, old bool) string {
	const prefixes = "KMGTPEZYRQ"
	if old { // 3.2.1: integer arithmetic on KiB
		value := uint64(max(v, 0))
		prefix := 0
		powi := uint64(1)
		for value/1024 >= powi && prefix < 7 {
			powi *= 1024
			prefix++
		}
		precision := 2
		if prefix == 0 {
			precision = 0
		}
		powj := uint64(1)
		for ; precision > 0; precision-- {
			powj *= 10
			if value/powi < powj {
				break
			}
		}
		return fmt.Sprintf("%.*f%c", precision, float64(value)/float64(powi), prefixes[prefix])
	}
	i := 0
	for v >= 1024 {
		if i >= len(prefixes)-1 {
			if v > 9999 {
				return "inf"
			}
			break
		}
		v /= 1024
		i++
	}
	precision := 0
	if i > 0 {
		switch {
		case v <= 9.99:
			precision = 2
		case v <= 99.9:
			precision = 1
		}
		if precision < 2 {
			limit := 100.0
			if precision == 1 {
				limit = 10
			}
			v = max(v, limit)
		}
	}
	return fmt.Sprintf("%.*f%c", precision, v, prefixes[i])
}

// htopBar draws a bar meter (caption, [, bar with the text right-aligned, ])
// at x with total width w.
func htopBar(l *htopLine, x, w, width int, caption string, values []float64, total float64, text string, o HtopOpts) {
	if len(caption) > 3 {
		caption = caption[:3]
	}
	l.put(x, caption, width)
	x += 3
	w -= 3
	l.put(x, "[", width)
	w--
	l.put(x+max(w, 0), "]", width)
	w--
	x++
	if w < 1 {
		return
	}
	bar := []rune(strings.Repeat(" ", w) + text)
	start := len(bar) - w
	if start > w { // the text is too long: cut it at a space
		for pos := 2 * w; pos > w; pos-- {
			if bar[pos] == ' ' {
				for pos > w && bar[pos-1] == ' ' {
					pos--
				}
				start = pos - w
				break
			}
		}
		start = min(start, w)
	}
	offset := 0
	for i, v := range values {
		size := 0
		if v > 0 && total > 0 && !math.IsNaN(v) {
			size = int(math.Ceil(min(v, total) / total * float64(w)))
		}
		next := min(max(offset+size, 0), w)
		for j := offset; j < next; j++ {
			if bar[start+j] == ' ' {
				c := '|'
				if o.NoColor {
					c = rune("|#*@$%&."[i])
				}
				bar[start+j] = c
			}
		}
		offset = next
	}
	l.put(x, string(bar[start:start+w]), width)
}

// htopCPUText is the CPU meter's text: the sum of its values, at most 100.
func htopCPUText(c HtopCPU) (float64, string) {
	p := 0.0
	for _, v := range []float64{c.Nice, c.Normal, c.Kernel, c.Virt} {
		if v > 0 {
			p += v
		}
	}
	p = min(p, 100)
	return p, fmt.Sprintf("%.1f%%", p)
}

// htopUptime is the Uptime meter's text.
func htopUptime(secs int64) string {
	if secs <= 0 {
		return "(unknown)"
	}
	d := secs / 86400
	days := ""
	switch {
	case d > 100:
		days = fmt.Sprintf("%d days(!), ", d)
	case d > 1:
		days = fmt.Sprintf("%d days, ", d)
	case d == 1:
		days = "1 day, "
	}
	return fmt.Sprintf("%s%02d:%02d:%02d", days, secs/3600%24, secs/60%60, secs%60)
}

// htopKBytes is htop's Row_printKBytes (3.3.0 and later).
func htopKBytes(n int64) string {
	if n < 0 {
		return "  N/A "
	}
	if n < 1000 {
		return fmt.Sprintf("%5d ", n)
	}
	if n < 100000 {
		return fmt.Sprintf("%2d%03d ", n/1000, n%1000)
	}
	const prefixes = "KMGTPEZYRQ"
	u := uint64(n)
	i := 1
	hundredths := (u/256)*25 + (u%256)*25/256 // KiB to 1/100 MiB
	for hundredths >= 1000000 {
		hundredths /= 1024
		i++
	}
	num, h := hundredths/100, hundredths%100
	switch {
	case num < 10:
		return fmt.Sprintf("%1d.%02d%c ", num, h, prefixes[i])
	case num < 100:
		return fmt.Sprintf("%2d.%1d%c ", num, h/10, prefixes[i])
	case num < 1000:
		return fmt.Sprintf("%4d%c ", num, prefixes[i])
	}
	return fmt.Sprintf("%1d%03d%c ", num/1000, num%1000, prefixes[i])
}

// htopKBytes32 is htop 3.2.1's Process_printBytes (KiB in).
func htopKBytes32(n int64) string {
	if n < 0 {
		return "  N/A "
	}
	const k, m, g = 1024, 1024 * 1024, 1024 * 1024 * 1024
	u := uint64(n)
	switch {
	case u < 1000:
		return fmt.Sprintf("%5d ", u)
	case u < 100000:
		return fmt.Sprintf("%2d%03d ", u/1000, u%1000)
	case u < 1000*k:
		return fmt.Sprintf("%4dM ", u/k)
	case u < 10000*k:
		u /= k
		return fmt.Sprintf("%1d%03dM ", u/1000, u%1000)
	case u < 100000*k:
		u /= 100 * k
		return fmt.Sprintf("%2d.%1dG ", u/10, u%10)
	case u < 1000*m:
		return fmt.Sprintf("%4dG ", u/m)
	case u < 10000*m:
		u /= m
		return fmt.Sprintf("%1d%03dG ", u/1000, u%1000)
	case u < 100000*m:
		u /= 100 * m
		return fmt.Sprintf("%2d.%1dT ", u/10, u%10)
	case u < 10000*g:
		return fmt.Sprintf("%4dT ", u/g)
	}
	return fmt.Sprintf("%4.1fP ", float64(u)/(1024*float64(g)))
}

// htopTime is htop's Row_printTime (3.3.0 and later), hundredths in.
func htopTime(cs int64) string {
	if cs <= 0 {
		return " 0:00.00 "
	}
	secs := cs / 100
	mins := secs / 60
	hours := mins / 60
	if mins < 60 {
		return fmt.Sprintf("%2d:%02d.%02d ", mins, secs%60, cs%100)
	}
	if hours < 24 {
		return fmt.Sprintf("%2dh%02d:%02d ", hours, mins%60, secs%60)
	}
	days := hours / 24
	switch {
	case days < 10:
		return fmt.Sprintf("%1dd%02dh%02dm ", days, hours%24, mins%60)
	case days < 365:
		return fmt.Sprintf("%4dd%02dh ", days, hours%24)
	}
	years := days / 365
	switch {
	case years < 1000:
		return fmt.Sprintf("%3dy%03dd ", years, days%365)
	case years < 10000000:
		return fmt.Sprintf("%7dy ", years)
	}
	return "eternity "
}

// htopTime32 is htop 3.2.1's Process_printTime.
func htopTime32(cs int64) string {
	secs := cs / 100
	hours := secs / 3600
	days := secs / 86400
	mins, s, h := secs/60%60, secs%60, cs-secs*100
	switch {
	case days >= 365:
		years, left := days/365, days%365
		switch {
		case years >= 10000000:
			return "eternity "
		case years >= 1000:
			return fmt.Sprintf("%7dy ", years)
		case left >= 100:
			return fmt.Sprintf("%3dy%3dd ", years, left)
		case left >= 10:
			return fmt.Sprintf("%4dy%2dd ", years, left)
		}
		return fmt.Sprintf("%5dy%1dd ", years, left)
	case days >= 100:
		left := hours - days*24
		if left >= 10 {
			return fmt.Sprintf("%4dd%2dh ", days, left)
		}
		return fmt.Sprintf("%5dd%1dh ", days, left)
	case hours >= 100:
		left := secs/60 - hours*60
		if left >= 10 {
			return fmt.Sprintf("%4dh%2dm ", hours, left)
		}
		return fmt.Sprintf("%5dh%1dm ", hours, left)
	case hours > 0:
		return fmt.Sprintf("%2dh%02d:%02d ", hours, mins, s)
	}
	return fmt.Sprintf("%2d:%02d.%02d ", mins, s, h)
}

// htopPercent is htop's Row_printPercentage.
func htopPercent(v float32, width int) string {
	if v < 0 || math.IsNaN(float64(v)) {
		return fmt.Sprintf("%*.*s ", width, width, "N/A")
	}
	precision := 1
	if width == 4 && v > 99.9 {
		precision, v = 0, 100
	}
	return fmt.Sprintf("%*.*f ", width, precision, v)
}

// htopLeft is htop's Row_printLeftAlignedField: cut to width columns, then
// padded to width + 1.
func htopLeft(s string, width int) string {
	if utf8.RuneCountInString(s) > width {
		s = string([]rune(s)[:width])
	}
	return s + strings.Repeat(" ", width+1-utf8.RuneCountInString(s))
}

// PrintHtop draws the screen: the header (meters), the screen tabs, the
// column titles and every process line (not cut at the screen's height;
// no function key bar), lines without trailing spaces.
func PrintHtop(w io.Writer, sc HtopScreen, o HtopOpts) {
	v30 := o.Version == "3.0" // htop 3.0.5: from its output only (htop30.go)
	old := o.Version == "3.2" || v30
	width := o.Width
	ncpu := len(sc.CPUs)

	// Settings_defaultMeters: the CPU meters by the number of CPUs; the left
	// column then Memory and Swap, the right one Tasks, Load average, Uptime.
	type meter struct {
		kind       string
		start, cnt int
		ncol       int
	}
	var left, right []meter
	ncol := 1
	switch {
	case ncpu > 32:
		ncol = 8
	case ncpu > 16:
		ncol = 4
	case ncpu > 8:
		ncol = 2
	}
	if ncpu > 4 && ncpu <= 128 {
		half := (ncpu + 1) / 2
		left = append(left, meter{kind: "cpus", start: 0, cnt: half, ncol: ncol})
		right = append(right, meter{kind: "cpus", start: half, cnt: ncpu - half, ncol: ncol})
	} else if ncpu > 128 {
		left = append(left, meter{kind: "avg"})
	} else {
		left = append(left, meter{kind: "cpus", start: 0, cnt: ncpu, ncol: 1})
	}
	left = append(left, meter{kind: "mem"}, meter{kind: "swap"})
	right = append(right, meter{kind: "tasks"}, meter{kind: "load"}, meter{kind: "uptime"})
	height := func(m meter) int {
		if m.kind == "cpus" {
			return (m.cnt + m.ncol - 1) / m.ncol
		}
		return 1
	}
	colHeight := func(ms []meter) int {
		h := 0
		for _, m := range ms {
			h += height(m)
		}
		return h
	}
	const pad = 2
	hh := pad + max(colHeight(left), colHeight(right))
	lines := make([]htopLine, hh)

	// Tasks: user processes, their other threads, kernel threads, running.
	var tasks, thr, kthr int
	for _, p := range sc.Procs {
		if p.Kernel {
			kthr++
			continue
		}
		tasks++
		thr += p.Threads - 1
	}
	running := min(sc.ProcsRunning, ncpu)

	cpuMeter := func(l *htopLine, x, w, cpu int) {
		caption := "CPU"
		if ncpu > 1 {
			caption = fmt.Sprintf("%3d", cpu)
		}
		c := sc.CPUs[cpu]
		_, text := htopCPUText(c)
		htopBar(l, x, w, width, caption, []float64{c.Nice, c.Normal, c.Kernel, c.Virt}, 100, text, o)
	}
	draw := func(m meter, x, y, w int) {
		l := &lines[y]
		if v30 && m.kind != "cpus" {
			w = htop30Draw(w)
		}
		switch m.kind {
		case "cpus":
			cw := (w-m.ncol)/m.ncol + 1
			diff := w - cw*m.ncol
			nrows := (m.cnt + m.ncol - 1) / m.ncol
			for i := 0; i < m.cnt; i++ {
				col := i / nrows
				d := min(col, diff)
				dw := cw
				if v30 {
					dw = htop30Draw(cw)
				}
				cpuMeter(&lines[y+i%nrows], x+col*cw+d, dw, m.start+i)
			}
		case "avg":
			var a HtopCPU
			for _, c := range sc.CPUs {
				a.Nice += c.Nice / float64(ncpu)
				a.Normal += c.Normal / float64(ncpu)
				a.Kernel += c.Kernel / float64(ncpu)
				a.Virt += c.Virt / float64(ncpu)
			}
			_, text := htopCPUText(a)
			htopBar(l, x, w, width, "Avg", []float64{a.Nice, a.Normal, a.Kernel, a.Virt}, 100, text, o)
		case "mem":
			total := float64(sc.MemTotal)
			shared := float64(sc.Shmem)
			cache := float64(sc.Cached + sc.SReclaimable - sc.Shmem)
			usedDiff := sc.MemFree + sc.Cached + sc.SReclaimable + sc.Buffers
			used := float64(sc.MemTotal - sc.MemFree)
			if sc.MemTotal >= usedDiff {
				used = float64(sc.MemTotal - usedDiff)
			}
			if v30 {
				used30, cache30 := htop30Mem(sc)
				htopBar(l, x, w, width, "Mem", []float64{used30, float64(sc.Buffers), cache30}, total,
					htopHumanUnit(used30, true)+"/"+htopHumanUnit(total, true), o)
				return
			}
			if old {
				htopBar(l, x, w, width, "Mem", []float64{used, float64(sc.Buffers), shared, cache}, total,
					htopHumanUnit(used, true)+"/"+htopHumanUnit(total, true), o)
				return
			}
			compressed := 0.0
			if sc.Zswap > 0 || sc.Zswapped > 0 {
				used -= float64(sc.Zswap)
				compressed = float64(sc.Zswap)
			}
			shown := used + max(shared, 0) + max(compressed, 0)
			htopBar(l, x, w, width, "Mem", []float64{used, shared, compressed, float64(sc.Buffers), cache}, total,
				htopHumanUnit(shown, false)+"/"+htopHumanUnit(total, false), o)
		case "swap":
			total := float64(sc.SwapTotal)
			used := float64(sc.SwapTotal - sc.SwapFree - sc.SwapCached)
			cache := float64(sc.SwapCached)
			if old {
				htopBar(l, x, w, width, "Swp", []float64{used, cache}, total,
					htopHumanUnit(used, true)+"/"+htopHumanUnit(total, true), o)
				return
			}
			front := 0.0
			if sc.Zswap > 0 || sc.Zswapped > 0 {
				used -= float64(sc.Zswapped)
				if used < 0 {
					cache += used
					used = 0
				}
				front = float64(sc.Zswapped)
			}
			htopBar(l, x, w, width, "Swp", []float64{used, cache, front}, total,
				htopHumanUnit(used, false)+"/"+htopHumanUnit(total, false), o)
		case "tasks":
			text := fmt.Sprintf("%d, %d thr, %d kthr; %d running", tasks, thr, kthr, running)
			if v30 {
				text = htop30Tasks(tasks, running)
			}
			l.put(x, htopCut("Tasks: "+text, w), width)
		case "load":
			l.put(x, htopCut(fmt.Sprintf("Load average: %.2f %.2f %.2f ", sc.Load[0], sc.Load[1], sc.Load[2]), w), width)
		case "uptime":
			l.put(x, htopCut("Uptime: "+htopUptime(sc.UptimeS), w), width)
		}
	}
	// Header_draw: two columns of 50%, the rounding loss carried right.
	avail := width - 2*pad - 1
	x := pad
	loss := float32(0)
	for c, col := range [][]meter{left, right} {
		cw := float32(avail) * 50 / 100
		loss += cw - float32(math.Floor(float64(cw)))
		if loss >= 1 {
			cw++
			loss--
		}
		icw := int(math.Floor(float64(cw)))
		if v30 {
			x, icw = htop30Column(width, c)
		}
		y := pad / 2
		for _, m := range col {
			draw(m, x, y, icw)
			y += height(m)
		}
		x += icw + 1
	}
	var out strings.Builder
	for _, l := range lines {
		out.WriteString(strings.TrimRight(string(l), " ") + "\n")
	}
	// The screen tabs (not in 3.0.5).
	if !v30 {
		var tabs htopLine
		tx := 2
		for _, name := range []string{"Main", "I/O"} {
			if tx >= width {
				break
			}
			tabs.put(tx, "["+name+"]", width)
			tx += len(name) + 3
		}
		out.WriteString(strings.TrimRight(string(tabs), " ") + "\n")
	}

	// The process list.
	key, desc := htopSortOf(o)
	cpuW := 5
	for _, p := range sc.Procs {
		if p.CPU >= 99.9 {
			cpuW = max(cpuW, int(math.Ceil(math.Log10(float64(p.CPU)+0.1)))+2)
		}
	}
	pidW := sc.PIDDigits
	titles := []struct{ key, title string }{
		{"PID", fmt.Sprintf("%*s ", pidW, "PID")}, {"USER", "USER       "}, {"PRIORITY", "PRI "}, {"NICE", " NI "},
		{"M_VIRT", " VIRT "}, {"M_RESIDENT", "  RES "}, {"M_SHARE", "  SHR "}, {"STATE", "S "},
		{"PERCENT_CPU", fmt.Sprintf("%*s ", cpuW, " CPU%")}, {"PERCENT_MEM", "MEM% "}, {"TIME", "  TIME+  "}, {"COMM", "Command "},
	}
	if o.Version != "" && cpuW > 5 { // before 3.4: the title left-aligned
		titles[8].title = fmt.Sprintf("%-*.*s ", cpuW, cpuW, " CPU%")
	}
	if v30 {
		titles[1].title, titles[8].title = htop30UserTitle, htop30CPUTitle
	}
	var head strings.Builder
	for _, t := range titles {
		s := t.title
		if t.key == key && strings.HasSuffix(s, " ") {
			arrow := "▽"
			if !desc {
				arrow = "△"
			}
			s = s[:len(s)-1] + arrow
		}
		head.WriteString(s)
	}
	out.WriteString(htopCutRight(head.String(), width) + "\n")

	for _, e := range htopVisible(sc, o) {
		p := e.p
		var b strings.Builder
		fmt.Fprintf(&b, "%*d ", pidW, p.PID)
		switch {
		case v30:
			b.WriteString(htop30User(p))
		case p.User != "":
			b.WriteString(htopLeft(p.User, 10))
		default:
			fmt.Fprintf(&b, "%-10d ", p.UID)
		}
		if p.Pri <= -100 {
			b.WriteString(" RT ")
		} else {
			fmt.Fprintf(&b, "%3d ", p.Pri)
		}
		fmt.Fprintf(&b, "%3d ", p.Nice)
		kb := htopKBytes
		tm := htopTime
		if old {
			kb, tm = htopKBytes32, htopTime32
		}
		b.WriteString(kb(p.VirtKB) + kb(p.ResKB) + kb(p.ShrKB))
		b.WriteString(htopStateChar(p.State) + " ")
		if v30 {
			b.WriteString(htop30CPU(p.CPU))
		} else {
			b.WriteString(htopPercent(p.CPU, cpuW))
		}
		b.WriteString(htopPercent(p.Mem, 4))
		b.WriteString(tm(p.TimeCS))
		if o.Tree {
			b.WriteString(htopTreePrefix(e))
		}
		b.WriteString(strings.ReplaceAll(p.Command, "\n", " "))
		out.WriteString(htopCutRight(b.String(), width) + "\n")
	}
	io.WriteString(w, out.String())
}

// htopEntry is a line of the process list: the tree view's indent bits
// (htop's Row.indent; last: the last shown child, drawn with └) and hidden
// (below a hidden row: a kernel thread's children).
type htopEntry struct {
	p      *HtopProc
	indent int32
	last   bool
	hidden bool
}

// htopTree is htop's Table_buildTree: roots (no parent, or a parent not in
// the table) and each process's children sorted by parent then the sort key,
// every row's indent bits as htop keeps them (the last shown child's
// negated). Kernel threads are rows too, hidden: kthreadd's children hide
// with it, and a hidden row is never the last shown.
func htopTree(all []*HtopProc, key string, desc bool) []htopEntry {
	type entry = htopEntry
	byPID := map[int]*HtopProc{}
	for _, p := range all {
		byPID[p.PID] = p
	}
	root := func(p *HtopProc) bool {
		return p.PPID == p.PID || p.PPID == 0 || byPID[p.PPID] == nil
	}
	children := map[int][]*HtopProc{}
	var roots []*HtopProc
	for _, p := range all {
		if root(p) {
			roots = append(roots, p)
		} else {
			children[p.PPID] = append(children[p.PPID], p)
		}
	}
	htopSort(roots, key, desc)
	shown := func(p *HtopProc) bool { return !p.Kernel && p.Sampled }
	var out []entry
	var branch func(pid int, level uint, indent int32, show bool)
	branch = func(pid int, level uint, indent int32, show bool) {
		kids := children[pid]
		htopSort(kids, key, desc)
		lastShown := -1
		for i, k := range kids {
			if show && shown(k) {
				lastShown = i
			}
		}
		for i, k := range kids {
			next := indent | int32(1)<<min(level, 30)
			idx := len(out)
			out = append(out, entry{p: k, hidden: !show})
			childIndent := indent
			if i < lastShown {
				childIndent = next
			}
			branch(k.PID, level+1, childIndent, show && shown(k))
			out[idx].indent = next
			if i == lastShown {
				out[idx].indent, out[idx].last = -next, true
			}
		}
	}
	for _, r := range roots {
		out = append(out, entry{p: r})
		branch(r.PID, 0, 0, shown(r))
	}
	return out
}

// htopCut cuts a meter's text to w columns.
func htopCut(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) > w {
		return string([]rune(s)[:w])
	}
	return s
}

// htopCutRight cuts a line to the screen's width, without trailing spaces.
func htopCutRight(s string, width int) string {
	return strings.TrimRight(htopCut(s, width), " ")
}

// HtopVersion names the htop release printed for a style.
func HtopVersion(st ToolStyle) string {
	switch st.Htop {
	case "3.0":
		return "3.0.5"
	case "3.2":
		return "3.2.1"
	case "3.3":
		return "3.3.0"
	}
	return "3.4.1"
}

// htopSortOf: the sort key and direction (the tree view sorts by PID, ascending).
func htopSortOf(o HtopOpts) (string, bool) {
	key := o.SortKey
	if key == "" {
		key = "PERCENT_CPU"
	}
	desc := htopSortDesc[key]
	if o.Tree {
		key, desc = "PID", false
	}
	return key, desc
}

// htopVisible: the process lines in screen order: sorted or as a tree,
// without kernel threads, processes without values, those -u and -p leave
// out, and those below a hidden row.
func htopVisible(sc HtopScreen, o HtopOpts) []htopEntry {
	key, desc := htopSortOf(o)
	pids := map[int]bool{}
	for _, p := range o.PIDs {
		pids[p] = true
	}
	uids := map[int]bool{}
	for _, u := range o.UIDs {
		uids[u] = true
	}
	all := make([]*HtopProc, 0, len(sc.Procs))
	for i := range sc.Procs {
		all = append(all, &sc.Procs[i])
	}
	var list []htopEntry
	if !o.Tree {
		htopSort(all, key, desc)
		for _, p := range all {
			list = append(list, htopEntry{p: p})
		}
	} else {
		list = htopTree(all, key, desc)
	}
	out := list[:0]
	for _, e := range list {
		p := e.p
		if e.hidden || p.Kernel || !p.Sampled || len(uids) > 0 && !uids[p.UID] || len(pids) > 0 && !pids[p.PID] {
			continue
		}
		out = append(out, e)
	}
	return out
}

// htopTreePrefix is the tree view's drawing before a command.
func htopTreePrefix(e htopEntry) string {
	if e.indent == 0 {
		return ""
	}
	var b strings.Builder
	ind := e.indent
	if ind < 0 {
		ind = -ind
	}
	for ; ind > 1; ind >>= 1 {
		if ind&1 != 0 {
			b.WriteString("│  ")
		} else {
			b.WriteString("   ")
		}
	}
	if e.last {
		b.WriteString("└─ ")
	} else {
		b.WriteString("├─ ")
	}
	return b.String()
}

// HtopJSON is htop's screen as --json prints it: the header's values and
// the process lines shown, in screen order.
type HtopJSON struct {
	SampleTS int64          `json:"sample_ts_ms"`
	PrevTS   int64          `json:"prev_ts_ms,omitempty"`
	CPUs     []HtopCPUJSON  `json:"cpus"`
	Mem      HtopMemJSON    `json:"mem"`
	Swap     HtopSwapJSON   `json:"swap"`
	Tasks    HtopTasksJSON  `json:"tasks"`
	Load     [3]float64     `json:"load"`
	UptimeS  int64          `json:"uptime_s"`
	Procs    []HtopProcJSON `json:"processes"`
}

type HtopCPUJSON struct {
	CPU     int     `json:"cpu"`
	Percent float64 `json:"percent"`
	Nice    float64 `json:"nice"`
	Normal  float64 `json:"normal"`
	Kernel  float64 `json:"kernel"`
	Virt    float64 `json:"virt"`
}

type HtopMemJSON struct {
	TotalKB   int64 `json:"total_kb"`
	UsedKB    int64 `json:"used_kb"`
	SharedKB  int64 `json:"shared_kb"`
	BuffersKB int64 `json:"buffers_kb"`
	CacheKB   int64 `json:"cache_kb"`
	AvailKB   int64 `json:"available_kb"`
}

type HtopSwapJSON struct {
	TotalKB int64 `json:"total_kb"`
	UsedKB  int64 `json:"used_kb"`
	CacheKB int64 `json:"cache_kb"`
}

type HtopTasksJSON struct {
	Processes     int `json:"processes"`
	Threads       int `json:"threads"`
	KernelThreads int `json:"kernel_threads"`
	Running       int `json:"running"`
}

type HtopProcJSON struct {
	HtopProc
	Tree string `json:"tree,omitempty"` // -t: the drawing before the command
}

// HtopJSONOf: the screen's values (htop 3.4's memory partition) and its
// process lines.
func HtopJSONOf(sc HtopScreen, o HtopOpts) HtopJSON {
	j := HtopJSON{SampleTS: sc.SampleTS, PrevTS: sc.PrevTS, Load: sc.Load, UptimeS: sc.UptimeS}
	for i, c := range sc.CPUs {
		p, _ := htopCPUText(c)
		j.CPUs = append(j.CPUs, HtopCPUJSON{CPU: i, Percent: p, Nice: c.Nice, Normal: c.Normal, Kernel: c.Kernel, Virt: c.Virt})
	}
	cache := sc.Cached + sc.SReclaimable - sc.Shmem
	used := sc.MemTotal - sc.MemFree
	if d := sc.MemFree + sc.Cached + sc.SReclaimable + sc.Buffers; sc.MemTotal >= d {
		used = sc.MemTotal - d
	}
	j.Mem = HtopMemJSON{TotalKB: sc.MemTotal, UsedKB: used, SharedKB: sc.Shmem, BuffersKB: sc.Buffers, CacheKB: cache, AvailKB: sc.MemAvailable}
	j.Swap = HtopSwapJSON{TotalKB: sc.SwapTotal, UsedKB: sc.SwapTotal - sc.SwapFree - sc.SwapCached, CacheKB: sc.SwapCached}
	for _, p := range sc.Procs {
		if p.Kernel {
			j.Tasks.KernelThreads++
			continue
		}
		j.Tasks.Processes++
		j.Tasks.Threads += p.Threads - 1
	}
	j.Tasks.Running = min(sc.ProcsRunning, len(sc.CPUs))
	j.Procs = []HtopProcJSON{}
	for _, e := range htopVisible(sc, o) {
		r := HtopProcJSON{HtopProc: *e.p}
		if o.Tree {
			r.Tree = htopTreePrefix(e)
		}
		j.Procs = append(j.Procs, r)
	}
	return j
}
