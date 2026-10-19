package query

import (
	"database/sql"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"clifr/internal/store"
)

// uptime, vmstat, mpstat and iostat from the system-wide counters
// (sys_samples, cpu_samples, disk_samples). The counters are cumulative, so a
// report is either "since boot" (one sample, like the real tool without an
// interval) or the difference between two samples (like its interval lines).

// Span is one report: the counters at To minus those at From; From 0 means
// since boot.
type Span struct{ From, To int64 }

// SysSpans returns the reports for a window. At a point in time: the sample at
// or before it, since boot. For a range: one span per pair of consecutive
// samples in it that are at least step apart; a reboot between two samples
// yields no span.
func SysSpans(db *store.DB, w Window, stepMS int64) ([]Span, error) {
	if !w.IsRange() {
		var ts sql.NullInt64
		if err := db.QueryRow(`SELECT MAX(ts) FROM sys_samples WHERE ts <= ?`, w.At).Scan(&ts); err != nil {
			return nil, err
		}
		if !ts.Valid {
			return nil, fmt.Errorf("no system counters recorded at or before %s", FormatMS(w.At))
		}
		return []Span{{0, ts.Int64}}, nil
	}
	rows, err := db.Query(`SELECT ts, uptime_ms FROM sys_samples WHERE ts BETWEEN ? AND ? ORDER BY ts`, w.From, w.To)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var spans []Span
	var prev, prevUp int64
	for rows.Next() {
		var ts, up int64
		if err := rows.Scan(&ts, &up); err != nil {
			return nil, err
		}
		switch {
		case prev == 0 || up < prevUp: // first sample, or a reboot
		case ts-prev < stepMS:
			continue
		default:
			spans = append(spans, Span{prev, ts})
		}
		prev, prevUp = ts, up
	}
	if len(spans) == 0 {
		return nil, fmt.Errorf("fewer than two samples with system counters in %s .. %s", FormatMS(w.From), FormatMS(w.To))
	}
	return spans, rows.Err()
}

func loadSys(db *store.DB, ts int64) (store.SysSample, error) {
	var s store.SysSample
	if ts == 0 {
		return s, nil
	}
	err := db.QueryRow(`SELECT ts, uptime_ms, load1, load5, load15, runnable, threads, procs_running, procs_blocked,
		intr, ctxt, forks, softirq, mem_total, mem_free, mem_available, buffers, cached, swap_cached, active, inactive,
		swap_total, swap_free, dirty, writeback, shmem, slab, sreclaimable, pgpgin, pgpgout, pswpin, pswpout, pgfault, pgmajfault
		FROM sys_samples WHERE ts = ?`, ts).Scan(&s.TS, &s.UptimeMS, &s.Load1, &s.Load5, &s.Load15, &s.Runnable, &s.Threads,
		&s.ProcsRunning, &s.ProcsBlocked, &s.Intr, &s.Ctxt, &s.Forks, &s.SoftIRQ, &s.MemTotal, &s.MemFree, &s.MemAvailable,
		&s.Buffers, &s.Cached, &s.SwapCached, &s.Active, &s.Inactive, &s.SwapTotal, &s.SwapFree, &s.Dirty, &s.Writeback,
		&s.Shmem, &s.Slab, &s.SReclaimable, &s.PgpgIn, &s.PgpgOut, &s.PswpIn, &s.PswpOut, &s.PgFault, &s.PgMajFault)
	return s, err
}

// cpuTimes are a CPU's clock ticks in the order of store.CPUCols.
type cpuTimes [10]int64

const (
	cUser = iota
	cNice
	cSystem
	cIdle
	cIOWait
	cIRQ
	cSoftIRQ
	cSteal
	cGuest
	cGuestNice
)

func loadCPUs(db *store.DB, ts int64) (map[int]cpuTimes, error) {
	out := map[int]cpuTimes{}
	if ts == 0 {
		return out, nil
	}
	rows, err := db.Query(`SELECT cpu, `+strings.Join(store.CPUCols, ", ")+` FROM cpu_samples WHERE ts = ?`, ts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cpu int
		var t cpuTimes
		dst := []any{&cpu}
		for i := range t {
			dst = append(dst, &t[i])
		}
		if err := rows.Scan(dst...); err != nil {
			return nil, err
		}
		out[cpu] = t
	}
	return out, rows.Err()
}

// cpuDelta returns the ticks spent in the span per CPU (-1: all).
func cpuDelta(db *store.DB, sp Span) (map[int]cpuTimes, error) {
	to, err := loadCPUs(db, sp.To)
	if err != nil {
		return nil, err
	}
	from, err := loadCPUs(db, sp.From)
	if err != nil {
		return nil, err
	}
	for cpu, t := range to {
		f := from[cpu] // a CPU that came online in the span counts from zero
		for i := range t {
			t[i] = max(t[i]-f[i], 0)
		}
		to[cpu] = t
	}
	return to, nil
}

// seconds is the length of the span; since boot, the uptime at its end.
func (sp Span) seconds(to store.SysSample) float64 {
	if sp.From == 0 {
		return float64(to.UptimeMS) / 1000
	}
	return float64(sp.To-sp.From) / 1000
}

func clock(ts int64) string { return time.UnixMilli(ts).Format("15:04:05") }

// ---- uptime ----

// UptimeRow is what uptime prints, without the number of logged-in users
// (not recorded).
type UptimeRow struct {
	TS      int64   `json:"ts_ms"`
	Time    string  `json:"time"`
	UptimeS int64   `json:"uptime_s"`
	Load1   float64 `json:"load1"`
	Load5   float64 `json:"load5"`
	Load15  float64 `json:"load15"`
}

// Uptime returns one row per span end.
func Uptime(db *store.DB, spans []Span) ([]UptimeRow, error) {
	var out []UptimeRow
	for _, sp := range spans {
		s, err := loadSys(db, sp.To)
		if err != nil {
			return nil, err
		}
		out = append(out, UptimeRow{TS: s.TS, Time: FormatMS(s.TS), UptimeS: s.UptimeMS / 1000,
			Load1: float64(s.Load1) / 100, Load5: float64(s.Load5) / 100, Load15: float64(s.Load15) / 100})
	}
	return out, nil
}

// PrintUptime formats rows like procps uptime: " 18:11:47 up  9:21,  load average: 0.58, 0.56, 1.49".
func PrintUptime(w io.Writer, rows []UptimeRow) {
	for _, r := range rows {
		min := r.UptimeS / 60
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
		fmt.Fprintf(w, " %s up %s load average: %.2f, %.2f, %.2f\n", clock(r.TS), up, r.Load1, r.Load5, r.Load15)
	}
}

// ---- vmstat ----

// VMStatRow is one vmstat line (memory in kB, rates per second, CPU in %).
type VMStatRow struct {
	TS        int64  `json:"ts_ms"`
	Time      string `json:"time"`
	SinceBoot bool   `json:"since_boot"`
	R         int64  `json:"r"`
	B         int64  `json:"b"`
	Swpd      int64  `json:"swpd"`
	Free      int64  `json:"free"`
	Buff      int64  `json:"buff"`
	Cache     int64  `json:"cache"`
	SI        int64  `json:"si"`
	SO        int64  `json:"so"`
	BI        int64  `json:"bi"`
	BO        int64  `json:"bo"`
	In        int64  `json:"in"`
	CS        int64  `json:"cs"`
	US        int64  `json:"us"`
	SY        int64  `json:"sy"`
	ID        int64  `json:"id"`
	WA        int64  `json:"wa"`
	ST        int64  `json:"st"`
	GU        int64  `json:"gu"`
}

func rate(n int64, secs float64) int64 {
	if secs <= 0 || n < 0 {
		return 0
	}
	return int64(float64(n)/secs + 0.5)
}

// VMStat computes one line per span, the way procps vmstat does: memory and
// the r/b columns are the values at the end of the span.
func VMStat(db *store.DB, spans []Span) ([]VMStatRow, error) {
	pageKB := metaInt(db, "page_kb")
	if pageKB == 0 {
		pageKB = 4
	}
	var out []VMStatRow
	for _, sp := range spans {
		to, err := loadSys(db, sp.To)
		if err != nil {
			return nil, err
		}
		from, err := loadSys(db, sp.From)
		if err != nil {
			return nil, err
		}
		cpus, err := cpuDelta(db, sp)
		if err != nil {
			return nil, err
		}
		secs := sp.seconds(to)
		t := cpus[-1]
		use, sys := t[cUser]+t[cNice], t[cSystem]+t[cIRQ]+t[cSoftIRQ]
		div := use + sys + t[cIdle] + t[cIOWait] + t[cSteal]
		pct := func(v int64) int64 {
			if div == 0 {
				return 0
			}
			return (100*v + div/2) / div
		}
		out = append(out, VMStatRow{TS: to.TS, Time: FormatMS(to.TS), SinceBoot: sp.From == 0,
			// The process that read the counters was running itself; vmstat
			// leaves itself out the same way.
			R: int64(max(to.ProcsRunning-1, 0)), B: int64(to.ProcsBlocked),
			Swpd: to.SwapTotal - to.SwapFree, Free: to.MemFree, Buff: to.Buffers, Cache: to.Cached + to.SReclaimable,
			SI: rate((to.PswpIn-from.PswpIn)*pageKB, secs), SO: rate((to.PswpOut-from.PswpOut)*pageKB, secs),
			BI: rate(to.PgpgIn-from.PgpgIn, secs), BO: rate(to.PgpgOut-from.PgpgOut, secs),
			In: rate(to.Intr-from.Intr, secs), CS: rate(to.Ctxt-from.Ctxt, secs),
			US: pct(use), SY: pct(sys), ID: pct(t[cIdle]), WA: pct(t[cIOWait]), ST: pct(t[cSteal]), GU: pct(t[cGuest] + t[cGuestNice])})
	}
	return out, nil
}

// PrintVMStat formats rows like procps-ng 4 vmstat.
func PrintVMStat(w io.Writer, rows []VMStatRow) {
	fmt.Fprintln(w, "procs -----------memory---------- ---swap-- -----io---- -system-- -------cpu-------")
	fmt.Fprintln(w, " r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st gu")
	for _, r := range rows {
		fmt.Fprintf(w, "%2d %2d %6d %6d %6d %6d %4d %4d %5d %5d %4d %4d %2d %2d %2d %2d %2d %2d\n",
			r.R, r.B, r.Swpd, r.Free, r.Buff, r.Cache, r.SI, r.SO, r.BI, r.BO, r.In, r.CS, r.US, r.SY, r.ID, r.WA, r.ST, r.GU)
	}
}

// ---- mpstat ----

// MPStatRow is one mpstat line: a CPU's time split in %.
type MPStatRow struct {
	TS     int64   `json:"ts_ms"`
	Time   string  `json:"time"`
	CPU    string  `json:"cpu"` // "all" or the CPU number
	Usr    float64 `json:"usr"`
	Nice   float64 `json:"nice"`
	Sys    float64 `json:"sys"`
	IOWait float64 `json:"iowait"`
	IRQ    float64 `json:"irq"`
	Soft   float64 `json:"soft"`
	Steal  float64 `json:"steal"`
	Guest  float64 `json:"guest"`
	GNice  float64 `json:"gnice"`
	Idle   float64 `json:"idle"`
}

// cpuTotal is the time a CPU line accounts for: user and nice already contain
// the guest times.
func cpuTotal(t cpuTimes) int64 {
	var n int64
	for _, v := range t[:cGuest] {
		n += v
	}
	return n
}

// MPStat computes the rows of each span. which selects the CPUs: "" only the
// total, "ALL" the total and every CPU, or a comma-separated list of numbers.
func MPStat(db *store.DB, spans []Span, which string) ([]MPStatRow, error) {
	want := map[int]bool{-1: which == "" || strings.EqualFold(which, "ALL")}
	all := strings.EqualFold(which, "ALL")
	if which != "" && !all {
		for _, f := range strings.Split(which, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(f))
			if err != nil {
				return nil, fmt.Errorf("bad CPU list %q, want ALL or numbers separated by commas", which)
			}
			want[n] = true
		}
	}
	var out []MPStatRow
	for _, sp := range spans {
		cpus, err := cpuDelta(db, sp)
		if err != nil {
			return nil, err
		}
		ids := make([]int, 0, len(cpus))
		for id := range cpus {
			if all || want[id] {
				ids = append(ids, id)
			}
		}
		sort.Ints(ids)
		for _, id := range ids {
			t := cpus[id]
			total := float64(cpuTotal(t))
			p := func(v int64) float64 {
				if total == 0 {
					return 0
				}
				return 100 * float64(v) / total
			}
			name := "all"
			if id >= 0 {
				name = strconv.Itoa(id)
			}
			row := MPStatRow{TS: sp.To, Time: FormatMS(sp.To), CPU: name,
				Usr: p(t[cUser] - t[cGuest]), Nice: p(t[cNice] - t[cGuestNice]), Sys: p(t[cSystem]), IOWait: p(t[cIOWait]),
				IRQ: p(t[cIRQ]), Soft: p(t[cSoftIRQ]), Steal: p(t[cSteal]), Guest: p(t[cGuest]), GNice: p(t[cGuestNice]), Idle: p(t[cIdle])}
			if total == 0 {
				row.Idle = 100 // a tickless CPU that did nothing in the span
			}
			out = append(out, row)
		}
	}
	return out, nil
}

// PrintMPStat formats rows like sysstat mpstat (24-hour clock).
func PrintMPStat(w io.Writer, rows []MPStatRow) {
	var last int64
	for _, r := range rows {
		if r.TS != last {
			if last != 0 {
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "%s     CPU    %%usr   %%nice    %%sys %%iowait    %%irq   %%soft  %%steal  %%guest  %%gnice   %%idle\n", clock(r.TS))
			last = r.TS
		}
		fmt.Fprintf(w, "%s %7s %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f\n", clock(r.TS), r.CPU,
			r.Usr, r.Nice, r.Sys, r.IOWait, r.IRQ, r.Soft, r.Steal, r.Guest, r.GNice, r.Idle)
	}
}

// ---- iostat ----

// IOStatCPU is iostat's avg-cpu line.
type IOStatCPU struct {
	User   float64 `json:"user"`
	Nice   float64 `json:"nice"`
	System float64 `json:"system"`
	IOWait float64 `json:"iowait"`
	Steal  float64 `json:"steal"`
	Idle   float64 `json:"idle"`
}

// IOStatDev is one device of an iostat report: the basic columns and the
// extended (-x) ones. Sizes are kB, times ms.
type IOStatDev struct {
	Device  string  `json:"device"`
	TPS     float64 `json:"tps"`
	KBRead  int64   `json:"kb_read"`
	KBWrtn  int64   `json:"kb_wrtn"`
	KBDscd  int64   `json:"kb_dscd"`
	RS      float64 `json:"r_s"`
	RKBS    float64 `json:"rkb_s"`
	RRQMS   float64 `json:"rrqm_s"`
	RRQMPct float64 `json:"rrqm_pct"`
	RAwait  float64 `json:"r_await"`
	RAreqSz float64 `json:"rareq_sz"`
	WS      float64 `json:"w_s"`
	WKBS    float64 `json:"wkb_s"`
	WRQMS   float64 `json:"wrqm_s"`
	WRQMPct float64 `json:"wrqm_pct"`
	WAwait  float64 `json:"w_await"`
	WAreqSz float64 `json:"wareq_sz"`
	DS      float64 `json:"d_s"`
	DKBS    float64 `json:"dkb_s"`
	DRQMS   float64 `json:"drqm_s"`
	DRQMPct float64 `json:"drqm_pct"`
	DAwait  float64 `json:"d_await"`
	DAreqSz float64 `json:"dareq_sz"`
	FS      float64 `json:"f_s"`
	FAwait  float64 `json:"f_await"`
	AquSz   float64 `json:"aqu_sz"`
	Util    float64 `json:"util"`
}

// IOStatReport is one iostat report.
type IOStatReport struct {
	TS        int64       `json:"ts_ms"`
	Time      string      `json:"time"`
	SinceBoot bool        `json:"since_boot"`
	CPU       IOStatCPU   `json:"avg_cpu"`
	Devices   []IOStatDev `json:"devices"`
}

type diskVals [17]int64

func loadDisks(db *store.DB, ts int64, parts bool) (map[string]diskVals, error) {
	out := map[string]diskVals{}
	if ts == 0 {
		return out, nil
	}
	q := `SELECT name, ` + strings.Join(store.DiskCols, ", ") + ` FROM disk_samples WHERE ts = ?`
	if !parts {
		q += ` AND part = 0`
	}
	rows, err := db.Query(q, ts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var v diskVals
		dst := []any{&name}
		for i := range v {
			dst = append(dst, &v[i])
		}
		if err := rows.Scan(dst...); err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, rows.Err()
}

func div(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

// IOStat computes one report per span. Devices are whole disks unless parts
// is set; one that did no I/O before the end of the span is not listed.
func IOStat(db *store.DB, spans []Span, parts bool) ([]IOStatReport, error) {
	var out []IOStatReport
	for _, sp := range spans {
		to, err := loadSys(db, sp.To)
		if err != nil {
			return nil, err
		}
		rep := IOStatReport{TS: sp.To, Time: FormatMS(sp.To), SinceBoot: sp.From == 0}
		cpus, err := cpuDelta(db, sp)
		if err != nil {
			return nil, err
		}
		t := cpus[-1]
		if total := float64(cpuTotal(t)); total > 0 {
			p := func(v int64) float64 { return 100 * float64(v) / total }
			rep.CPU = IOStatCPU{User: p(t[cUser]), Nice: p(t[cNice]), System: p(t[cSystem] + t[cIRQ] + t[cSoftIRQ]),
				IOWait: p(t[cIOWait]), Steal: p(t[cSteal]), Idle: p(t[cIdle])}
		}
		now, err := loadDisks(db, sp.To, parts)
		if err != nil {
			return nil, err
		}
		before, err := loadDisks(db, sp.From, parts)
		if err != nil {
			return nil, err
		}
		secs := sp.seconds(to)
		names := make([]string, 0, len(now))
		for n := range now {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			v, b := now[n], before[n]
			var d [17]float64
			for i := range v {
				d[i] = float64(max(v[i]-b[i], 0))
			}
			// d: 0-3 reads, 4-7 writes, 8-11 discards (ios, merges, sectors,
			// ms), 12 in flight, 13 busy ms, 14 weighted ms, 15-16 flushes.
			dev := IOStatDev{Device: n, TPS: div(d[0]+d[4]+d[8], secs),
				KBRead: int64(d[2] / 2), KBWrtn: int64(d[6] / 2), KBDscd: int64(d[10] / 2),
				RS: div(d[0], secs), RKBS: div(d[2]/2, secs), RRQMS: div(d[1], secs), RRQMPct: 100 * div(d[1], d[1]+d[0]),
				RAwait: div(d[3], d[0]), RAreqSz: div(d[2]/2, d[0]),
				WS: div(d[4], secs), WKBS: div(d[6]/2, secs), WRQMS: div(d[5], secs), WRQMPct: 100 * div(d[5], d[5]+d[4]),
				WAwait: div(d[7], d[4]), WAreqSz: div(d[6]/2, d[4]),
				DS: div(d[8], secs), DKBS: div(d[10]/2, secs), DRQMS: div(d[9], secs), DRQMPct: 100 * div(d[9], d[9]+d[8]),
				DAwait: div(d[11], d[8]), DAreqSz: div(d[10]/2, d[8]),
				FS: div(d[15], secs), FAwait: div(d[16], d[15]),
				AquSz: div(d[14], secs*1000), Util: math.Min(100, div(d[13], secs*10))}
			rep.Devices = append(rep.Devices, dev)
		}
		out = append(out, rep)
	}
	return out, nil
}

// PrintIOStat formats reports like sysstat iostat: the avg-cpu block unless
// devOnly, then the basic or the extended (-x) device table.
func PrintIOStat(w io.Writer, reps []IOStatReport, extended, devOnly bool) {
	for i, rep := range reps {
		if i > 0 {
			fmt.Fprintln(w)
		}
		if len(reps) > 1 {
			fmt.Fprintln(w, FormatMS(rep.TS))
		}
		if !devOnly {
			c := rep.CPU
			io.WriteString(w, "avg-cpu:  %user   %nice %system %iowait  %steal   %idle\n")
			fmt.Fprintf(w, "        %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f\n\n", c.User, c.Nice, c.System, c.IOWait, c.Steal, c.Idle)
		}
		if extended {
			io.WriteString(w, "Device            r/s     rkB/s   rrqm/s  %rrqm r_await rareq-sz     w/s     wkB/s   wrqm/s  %wrqm w_await wareq-sz     d/s     dkB/s   drqm/s  %drqm d_await dareq-sz     f/s f_await  aqu-sz  %util\n")
			for _, d := range rep.Devices {
				fmt.Fprintf(w, "%-13s %7.2f %9.2f %8.2f %6.2f %7.2f %8.2f %7.2f %9.2f %8.2f %6.2f %7.2f %8.2f %7.2f %9.2f %8.2f %6.2f %7.2f %8.2f %7.2f %7.2f %7.2f %6.2f\n",
					d.Device, d.RS, d.RKBS, d.RRQMS, d.RRQMPct, d.RAwait, d.RAreqSz, d.WS, d.WKBS, d.WRQMS, d.WRQMPct, d.WAwait, d.WAreqSz,
					d.DS, d.DKBS, d.DRQMS, d.DRQMPct, d.DAwait, d.DAreqSz, d.FS, d.FAwait, d.AquSz, d.Util)
			}
			continue
		}
		io.WriteString(w, "Device             tps    kB_read/s    kB_wrtn/s    kB_dscd/s    kB_read    kB_wrtn    kB_dscd\n")
		for _, d := range rep.Devices {
			fmt.Fprintf(w, "%-13s %8.2f %12.2f %12.2f %12.2f %10d %10d %10d\n", d.Device, d.TPS, d.RKBS, d.WKBS, d.DKBS, d.KBRead, d.KBWrtn, d.KBDscd)
		}
	}
}
