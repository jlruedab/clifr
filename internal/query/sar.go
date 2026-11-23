// Reconstruction of sar's reports as sar -f prints them from a daily file
// (sysstat 11.7.3, 12.5.x, 12.6.1, 12.7.7).
//
// The reports, their columns, values and averages follow sysstat's code
// (sar.c, pr_stats.c, activity.c, rd_stats.c, common.c, sa_common.c),
// Copyright (C) 1999-2025 Sebastien Godard, GPL-2.0-or-later (see
// packaging/notices/sysstat.txt).

package query

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"clifr/internal/store"
)

// SarAct is one report: an activity of sar and its options.
type SarAct struct {
	Key   string // cpu pcsw irq swap mem swapmem huge ktables queue psicpu netdev netedev nfs nfsd sock ip eip icmp eicmp tcp etcp udp sock6 ip6 eip6 icmp6 eicmp6 udp6 fs
	All   bool   // -u ALL
	CPUs  []int  // -P: the CPUs (0-based); nil: only "all"; AllCPU: all and each
	Mount bool   // -F MOUNT: mount points instead of devices
	// Pretty: -p (sar -d: the name last, device-mapper devices by their
	// mapper name; sysstat 11 names devices devMAJ-MIN without it).
	Pretty bool
}

// SarAllCPU in SarAct.CPUs: -P ALL.
const SarAllCPU = -1

// SarActOrder is sysstat's activity order (activity.c's act[]), the order of
// the reports of one run.
var SarActOrder = []string{"cpu", "pcsw", "irq", "swap", "paging", "io", "mem", "swapmem", "huge", "ktables", "queue",
	"disk", "netdev", "netedev", "nfs", "nfsd", "sock", "ip", "eip", "icmp", "eicmp", "tcp", "etcp", "udp",
	"sock6", "ip6", "eip6", "icmp6", "eicmp6", "udp6", "softnet", "cpufreq", "fs", "psicpu", "psiio", "psimem"}

// SarOpts: the reports, the spacing of the records and the release.
type SarOpts struct {
	Acts    []SarAct
	StepMS  int64   // records at multiples of this (local clock); 0: every system sample
	Times   []int64 // instead: these system samples, one segment (clifr verify)
	Version string  // ToolStyle.Sar: "" 12.7.7, "12.6" 12.6.1, "12.5" 12.5.x, "11.7" 11.7.3
}

// sarRec is one record: what sadc would have read at a system sample.
type sarRec struct {
	ts, upCS int64
	sys      sarSys
	cpus     map[int]cpuTimes // by CPU, -1 the total
	net      map[string]int64
	links    []store.LinkRow
	kt       [4]int64 // dentunusd, file-nr, inode-nr, pty-nr
	ktOK     bool
	nfs      [6]int64
	nfsd     [11]int64
	fs       []DFRow
	restart  bool // the first record after a reboot
	// Schema 14 (sar14.go).
	x     sarX
	cpux  map[int]sarCPUX
	disks []sarDisk
	irq   *sarIRQ
}

type sarSys struct {
	store.SysSample
	committed, hugeTotal, hugeFree, hugeSize                 int64
	sockUsed, tcpInUse, tcpTW, udpInUse, rawInUse, fragInUse int64
	tcp6InUse, udp6InUse, raw6InUse, frag6InUse              int64
	psiCPU, psiCPU10, psiCPU60, psiCPU300                    int64
	psi                                                      bool
}

// SarData is the records of a window, split at reboots (segments).
type SarData struct {
	Segments [][]sarRec
	Restarts []int64           // per segment: when its boot was first seen (LINUX RESTART), 0 none
	Header   string            // sar's first line
	Notes    []string          // what the output cannot show (header lines)
	devNames map[[2]int]string // sar -dp: device-mapper names by major and minor
	ncpu     []int             // CPUs per segment
}

func (o SarOpts) has(key string) bool {
	for _, a := range o.Acts {
		if a.Key == key {
			return true
		}
	}
	return false
}

// Sar loads the records of the window [from, to].
func Sar(db *store.DB, from, to int64, o SarOpts) (*SarData, error) {
	rows, err := db.Query(`SELECT ts, uptime_ms, load1, load5, load15, runnable, threads, procs_running, procs_blocked,
		intr, ctxt, forks, mem_total, mem_free, mem_available, buffers, cached, swap_cached, active, inactive,
		swap_total, swap_free, dirty, slab, pswpin, pswpout,
		COALESCE(committed_as, -1), COALESCE(hugepages_total, 0), COALESCE(hugepages_free, 0), COALESCE(hugepagesize, 0),
		COALESCE(sock_used, 0), COALESCE(tcp_inuse, 0), COALESCE(tcp_tw, 0), COALESCE(udp_inuse, 0), COALESCE(raw_inuse, 0),
		COALESCE(frag_inuse, 0), COALESCE(tcp6_inuse, 0), COALESCE(udp6_inuse, 0), COALESCE(raw6_inuse, 0), COALESCE(frag6_inuse, 0),
		COALESCE(psi_cpu_some, 0), COALESCE(psi_cpu_avg10, 0), COALESCE(psi_cpu_avg60, 0), COALESCE(psi_cpu_avg300, 0), COALESCE(psi, 0)
		FROM sys_samples WHERE ts BETWEEN ? AND ? ORDER BY ts`, from, to)
	if err != nil {
		return nil, err
	}
	var all []sarRec
	noCommit := false
	for rows.Next() {
		var r sarRec
		s := &r.sys
		var psi int
		if err := rows.Scan(&r.ts, &s.UptimeMS, &s.Load1, &s.Load5, &s.Load15, &s.Runnable, &s.Threads, &s.ProcsRunning,
			&s.ProcsBlocked, &s.Intr, &s.Ctxt, &s.Forks, &s.MemTotal, &s.MemFree, &s.MemAvailable, &s.Buffers, &s.Cached,
			&s.SwapCached, &s.Active, &s.Inactive, &s.SwapTotal, &s.SwapFree, &s.Dirty, &s.Slab, &s.PswpIn, &s.PswpOut,
			&s.committed, &s.hugeTotal, &s.hugeFree, &s.hugeSize, &s.sockUsed, &s.tcpInUse, &s.tcpTW, &s.udpInUse,
			&s.rawInUse, &s.fragInUse, &s.tcp6InUse, &s.udp6InUse, &s.raw6InUse, &s.frag6InUse,
			&s.psiCPU, &s.psiCPU10, &s.psiCPU60, &s.psiCPU300, &psi); err != nil {
			rows.Close()
			return nil, err
		}
		s.psi = psi == 1
		if s.committed < 0 {
			s.committed, noCommit = 0, true
		}
		r.upCS = s.UptimeMS / 10
		all = append(all, r)
	}
	rows.Close()
	if len(all) == 0 {
		return nil, fmt.Errorf("no system counters recorded in %s .. %s", FormatMS(from), FormatMS(to))
	}
	// The records: the first sample at or after each multiple of the step
	// (local clock, as sa1's timer runs), from the first multiple at or
	// after the window's start. A boot in the window starts a segment: sar
	// prints LINUX RESTART (sa1 --boot writes only that mark) and the
	// segment's first record is the first multiple after it.
	atOrAfter := func(ts int64) int64 {
		if o.StepMS <= 0 {
			return ts
		}
		_, off := time.UnixMilli(ts).Zone()
		local := ts + int64(off)*1000
		k := (local + o.StepMS - 1) / o.StepMS
		return k*o.StepMS - int64(off)*1000
	}
	d := &SarData{}
	var nextB int64
	if len(o.Times) > 0 {
		want := map[int64]bool{}
		for _, t := range o.Times {
			want[t] = true
		}
		d.Segments, d.Restarts = [][]sarRec{nil}, []int64{0}
		for _, r := range all {
			if want[r.ts] {
				d.Segments[0] = append(d.Segments[0], r)
			}
		}
		all = nil
	}
	for i, r := range all {
		boot := i > 0 && r.sys.UptimeMS < all[i-1].sys.UptimeMS || i == 0 && r.ts-r.sys.UptimeMS >= from
		if i == 0 || boot {
			d.Segments = append(d.Segments, nil)
			d.Restarts = append(d.Restarts, 0)
			if boot {
				d.Restarts[len(d.Restarts)-1] = r.ts
				nextB = atOrAfter(r.ts + 1)
				if o.StepMS > 0 {
					continue
				}
			} else {
				nextB = atOrAfter(from)
			}
		}
		if r.ts >= nextB {
			seg := &d.Segments[len(d.Segments)-1]
			*seg = append(*seg, r)
			nextB = atOrAfter(r.ts + 1)
		}
	}
	if len(d.Segments[0]) == 0 && len(d.Segments) == 1 {
		return nil, fmt.Errorf("no system sample at a multiple of %d s in %s .. %s", o.StepMS/1000, FormatMS(from), FormatMS(to))
	}
	if err := d.load(db, o); err != nil {
		return nil, err
	}
	if noCommit && o.has("mem") {
		d.Notes = append(d.Notes, "kbcommit and %commit: Committed_AS is recorded since schema 12 (2026-11-21): shown as 0 before")
	}
	first := d.Segments[0][0]
	if len(all) > 0 {
		first = all[0]
	}
	n := d.ncpu[0]
	d.Header = SysstatFirstLine(db, first.ts, n)
	return d, nil
}

// SysstatFirstLine is the line sysstat's tools start with (print_gal_header,
// C locale): "Linux 6.8.0 (host) \t11/22/26 \t_x86_64_\t(4 CPU)", at ts.
func SysstatFirstLine(db *store.DB, ts int64, ncpu int) string {
	meta := func(k string) string {
		if v := MetaAt(db, k, ts); v != "" {
			return v
		}
		return db.Meta(k)
	}
	host := meta("hostname")
	if lines, _, ok, _ := FileAt(db, "hostname", ts); ok && len(lines) > 0 {
		host = strings.TrimSpace(lines[0])
	}
	return fmt.Sprintf("%s %s (%s) \t%s \t_%s_\t(%d CPU)", meta("uname_sysname"), meta("uname_release"),
		host, time.UnixMilli(ts).Format("01/02/06"), meta("uname_machine"), ncpu)
}

// load fills each record with what the reports need.
func (d *SarData) load(db *store.DB, o SarOpts) error {
	var tss []int64
	for _, seg := range d.Segments {
		for _, r := range seg {
			tss = append(tss, r.ts)
		}
	}
	for _, r := range d.Restarts {
		if r != 0 {
			tss = append(tss, r)
		}
	}
	if len(tss) == 0 {
		return nil
	}
	sort.Slice(tss, func(i, j int) bool { return tss[i] < tss[j] })
	lo, hi := tss[0], tss[len(tss)-1]
	// CPUs (always: the header's count and LINUX RESTART's).
	cpus := map[int64]map[int]cpuTimes{}
	rows, err := db.Query(`SELECT ts, cpu, `+strings.Join(store.CPUCols, ", ")+` FROM cpu_samples WHERE ts BETWEEN ? AND ?`, lo, hi)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ts int64
		var cpu int
		var t cpuTimes
		dst := []any{&ts, &cpu}
		for i := range t {
			dst = append(dst, &t[i])
		}
		if err := rows.Scan(dst...); err != nil {
			rows.Close()
			return err
		}
		if cpus[ts] == nil {
			cpus[ts] = map[int]cpuTimes{}
		}
		cpus[ts][cpu] = t
	}
	rows.Close()
	for si, seg := range d.Segments {
		n := 0
		for c := range cpus[d.Restarts[si]] {
			n = max(n, c+1)
		}
		for i := range seg {
			seg[i].cpus = cpus[seg[i].ts]
			for c := range seg[i].cpus {
				n = max(n, c+1)
			}
		}
		d.Segments[si] = seg
		d.ncpu = append(d.ncpu, max(n, 1))
	}
	needNet := false
	for _, k := range []string{"ip", "eip", "icmp", "eicmp", "tcp", "etcp", "udp", "ip6", "eip6", "icmp6", "eicmp6", "udp6"} {
		needNet = needNet || o.has(k)
	}
	if needNet {
		if err := d.loadSeries(db, `SELECT ts, name, value FROM net_counters WHERE ts BETWEEN ? AND ? ORDER BY ts`,
			lo-store.NetCountersFullMS-60_000, hi, func(r *sarRec, m map[string]int64) { r.net = m }); err != nil {
			return err
		}
	}
	if o.has("netdev") || o.has("netedev") {
		for si := range d.Segments {
			for i := range d.Segments[si] {
				r := &d.Segments[si][i]
				l, _, err := LinksAt(db, r.ts)
				if err != nil {
					return err
				}
				r.links = l
			}
		}
	}
	for si := range d.Segments {
		for i := range d.Segments[si] {
			r := &d.Segments[si][i]
			if o.has("ktables") {
				r.kt, r.ktOK = sarKTables(db, r.ts)
			}
			if o.has("nfs") {
				r.nfs = sarNFS(db, r.ts)
			}
			if o.has("nfsd") {
				r.nfsd = sarNFSD(db, r.ts)
			}
			if o.has("fs") {
				rows, err := DF(db, r.ts, DFSelect{All: true})
				if err != nil {
					return err
				}
				seen := map[string]bool{}
				for _, f := range rows {
					if !strings.HasPrefix(f.Source, "/") || f.FSType == "autofs" || f.SizeBytes == 0 || seen[f.Source] {
						continue
					}
					seen[f.Source] = true
					r.fs = append(r.fs, f)
				}
			}
		}
	}
	for _, a := range o.Acts {
		if a.Key == "disk" && a.Pretty {
			d.loadDevNames(db, hi)
		}
	}
	return d.load14(db, o, lo, hi)
}

// loadSeries walks rows (ts, name, value) written when they change and
// gives each record the newest value of every name at or before it.
func (d *SarData) loadDevNames(db *store.DB, t int64) {
	d.devNames = map[[2]int]string{}
	rows, err := db.Query(`SELECT maj, min, arg_max(dm_name, ts) FROM blockdevs WHERE ts <= ? AND dm_name <> '' GROUP BY maj, min`, t)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var maj, min int
		var name string
		if rows.Scan(&maj, &min, &name) == nil {
			d.devNames[[2]int{maj, min}] = name
		}
	}
}

func (d *SarData) loadSeries(db *store.DB, q string, lo, hi int64, set func(*sarRec, map[string]int64)) error {
	rows, err := db.Query(q, lo, hi)
	if err != nil {
		return err
	}
	type val struct {
		ts    int64
		name  string
		value int64
	}
	var vals []val
	for rows.Next() {
		var v val
		if err := rows.Scan(&v.ts, &v.name, &v.value); err != nil {
			rows.Close()
			return err
		}
		vals = append(vals, v)
	}
	rows.Close()
	cur := map[string]int64{}
	j := 0
	for si := range d.Segments {
		for i := range d.Segments[si] {
			r := &d.Segments[si][i]
			for ; j < len(vals) && vals[j].ts <= r.ts; j++ {
				cur[vals[j].name] = vals[j].value
			}
			m := make(map[string]int64, len(cur))
			for k, v := range cur {
				m[k] = v
			}
			set(r, m)
		}
	}
	return nil
}

// sarKTables: dentry-state's unused, file-nr's allocated less free,
// inode-state's allocated less free and pty/nr, from the sysctl snapshot
// (read every minute).
func sarKTables(db *store.DB, t int64) ([4]int64, bool) {
	var out [4]int64
	lines, _, ok, err := FileAt(db, "sysctl", t)
	if !ok || err != nil {
		return out, false
	}
	nums := func(name string) []int64 {
		for _, l := range lines {
			if k, v, ok := strings.Cut(l, " = "); ok && k == name {
				var r []int64
				for _, f := range strings.Fields(v) {
					n, _ := strconv.ParseInt(f, 10, 64)
					r = append(r, n)
				}
				return r
			}
		}
		return nil
	}
	if v := nums("fs.dentry-state"); len(v) >= 2 {
		out[0] = v[1]
	}
	if v := nums("fs.file-nr"); len(v) >= 2 {
		out[1] = v[0] - v[1]
	}
	if v := nums("fs.inode-state"); len(v) >= 2 {
		out[2] = v[0] - v[1]
	}
	if v := nums("kernel.pty.nr"); len(v) >= 1 {
		out[3] = v[0]
	}
	return out, true
}

func sarRPC(db *store.DB, source string, t int64) map[string][]int64 {
	out := map[string][]int64{}
	lines, _, ok, err := FileAt(db, source, t)
	if !ok || err != nil {
		return out
	}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		var v []int64
		for _, s := range f[1:] {
			n, _ := strconv.ParseInt(s, 10, 64)
			v = append(v, uint32ish(n))
		}
		out[f[0]] = v
	}
	return out
}

// uint32ish: sadc reads these counters as unsigned int.
func uint32ish(n int64) int64 { return int64(uint32(n)) }

func at(v []int64, i int) int64 {
	if i < len(v) {
		return v[i]
	}
	return 0
}

// sarNFS: rpc calls and retransmissions; read, write, access and getattr
// calls of NFS v3 and v4 (rd_stats.c read_net_nfs).
func sarNFS(db *store.DB, t int64) [6]int64 {
	m := sarRPC(db, "rpc/nfs", t)
	var o [6]int64
	o[0], o[1] = at(m["rpc"], 0), at(m["rpc"], 1)
	if p := m["proc3"]; p != nil { // the count of procedures, then null getattr setattr lookup access readlink read write
		o[5] += at(p, 2)
		o[4] += at(p, 5)
		o[2] += at(p, 7)
		o[3] += at(p, 8)
	}
	if p := m["proc4"]; p != nil { // count, null read write ... access(19) getattr(20)
		o[2] += at(p, 2)
		o[3] += at(p, 3)
		o[4] += at(p, 18)
		o[5] += at(p, 19)
	}
	return o
}

// sarNFSD: the server's rpc, network, reply cache and v3/v4 operation
// counts (rd_stats.c read_net_nfsd).
func sarNFSD(db *store.DB, t int64) [11]int64 {
	m := sarRPC(db, "rpc/nfsd", t)
	var o [11]int64
	o[0], o[1] = at(m["rpc"], 0), at(m["rpc"], 1)
	o[2], o[3], o[4] = at(m["net"], 0), at(m["net"], 1), at(m["net"], 2)
	o[5], o[6] = at(m["rc"], 0), at(m["rc"], 1)
	if p := m["proc3"]; p != nil {
		o[10] += at(p, 2)
		o[9] += at(p, 5)
		o[7] += at(p, 7)
		o[8] += at(p, 8)
	}
	if p := m["proc4ops"]; p != nil { // count, then ops 0..: access 3, getattr 9, read 25, write 38
		o[9] += at(p, 4)
		o[10] += at(p, 10)
		o[7] += at(p, 26)
		o[8] += at(p, 39)
	}
	return o
}

// ---- printing ----

// sarPr prints sar's lines: values as cprintf_f/cprintf_u64/cprintf_xpc do
// without colours.
type sarPr struct {
	w  io.Writer
	sb strings.Builder
	// --json: each printed line as a row (collect), mapped back to its
	// record by the time printed.
	collect bool
	rows    []SarRow
	report  string
	titles  []string // the value columns of the report being printed
	itemCol int      // where the item (CPU, interface, device...) is: 0 none, 1 first, 2 last
	isHdr   bool
	seg     []sarRec
	lastTS  int64
}

// SarRow is one line of sar's output as --json prints it: a record's line
// (Kind "record", TS its time), an "Average" or "Summary" line, or a "restart"
// (LINUX RESTART); Item is the CPU, interface, device or file system; Values
// are by column title.
type SarRow struct {
	TS     int64              `json:"ts_ms,omitempty"`
	Kind   string             `json:"kind"`
	Report string             `json:"report,omitempty"`
	Item   string             `json:"item,omitempty"`
	Values map[string]float64 `json:"values,omitempty"`
	CPUs   int                `json:"cpus,omitempty"`
}

func (p *sarPr) f(wd int, vals ...float64) {
	for _, v := range vals {
		fmt.Fprintf(&p.sb, " %9.*f", wd, v)
	}
}

func (p *sarPr) u(vals ...int64) {
	for _, v := range vals {
		fmt.Fprintf(&p.sb, " %9d", uint64(v))
	}
}

func (p *sarPr) ts(s string) { fmt.Fprintf(&p.sb, "%-11s", s) }

func (p *sarPr) s(format string, a ...any) { fmt.Fprintf(&p.sb, format, a...) }

func (p *sarPr) nl() {
	if p.collect && !p.isHdr {
		p.collectLine(p.sb.String())
	}
	p.isHdr = false
	p.sb.WriteString("\n")
	io.WriteString(p.w, p.sb.String())
	p.sb.Reset()
}

// collectLine turns a printed line into a SarRow: its time (the first 11
// columns) mapped to the segment's record printed with it, the words that
// are not numbers as the item, the numbers by the report's column titles.
func (p *sarPr) collectLine(line string) {
	line = strings.TrimLeft(line, "\n")
	if len(line) < 11 || p.report == "" {
		return
	}
	stamp := strings.TrimSpace(line[:11])
	r := SarRow{Kind: "record", Report: p.report, Values: map[string]float64{}}
	switch stamp {
	case "Average:":
		r.Kind = "Average"
	case "Summary:":
		r.Kind = "Summary"
	default:
		for _, x := range p.seg {
			if x.ts >= p.lastTS && clock(x.ts) == stamp {
				r.TS, p.lastTS = x.ts, x.ts
				break
			}
		}
	}
	f := strings.Fields(line[11:])
	switch p.itemCol {
	case 1:
		if len(f) > 0 {
			r.Item, f = f[0], f[1:]
		}
	case 2:
		if len(f) > len(p.titles) {
			r.Item, f = strings.Join(f[len(p.titles):], " "), f[:len(p.titles)]
		}
	}
	for i, x := range f {
		if v, err := strconv.ParseFloat(x, 64); err == nil && i < len(p.titles) {
			r.Values[p.titles[i]] = v
		}
	}
	p.rows = append(p.rows, r)
}

// hdr is print_hdr_line: a blank line, the time, then each column title (the
// first iwidth wide when > 0; with iwidth -1 the last title goes after the
// values' columns).
func (p *sarPr) hdr(ts string, titles string, iwidth int) {
	p.sb.WriteString("\n")
	p.ts(ts)
	f := strings.Split(titles, ";")
	p.isHdr = true
	p.titles, p.itemCol = f, 0
	switch {
	case iwidth < 0:
		p.titles, p.itemCol = f[1:], 2
	case f[0] == "CPU" || f[0] == "IFACE" || f[0] == "DEV" || f[0] == "INTR" || f[0] == "TTY":
		p.titles, p.itemCol = f[1:], 1
	}
	if iwidth < 0 {
		for _, t := range f[1:] {
			p.s(" %9s", t)
		}
		p.s(" %s", f[0])
		p.nl()
		return
	}
	for i, t := range f {
		if i == 0 && iwidth > 0 {
			p.s(" %*s", iwidth, t)
			continue
		}
		p.s(" %9s", t)
	}
	p.nl()
}

// sv is S_VALUE: a per-second rate from two counters and the interval in
// hundredths of a second.
func sv(a, b, itv int64) float64 { return float64(b-a) / float64(itv) * 100 }

// llsp is ll_sp_value: 0 when the counter went back.
func llsp(a, b, itv int64) float64 {
	if b < a {
		return 0
	}
	return float64(b-a) / float64(itv) * 100
}

// SarHeaders: each report's column titles by release.
func sarHeader(key string, all bool, v string) (string, int) {
	switch key {
	case "cpu":
		if all {
			return "CPU;%usr;%nice;%sys;%iowait;%steal;%irq;%soft;%guest;%gnice;%idle", 7
		}
		return "CPU;%user;%nice;%system;%iowait;%steal;%idle", 7
	case "pcsw":
		return "proc/s;cswch/s", 0
	case "irq":
		return "INTR;intr/s", 9
	case "swap":
		return "pswpin/s;pswpout/s", 0
	case "mem":
		if all {
			return "kbmemfree;kbavail;kbmemused;%memused;kbbuffers;kbcached;kbcommit;%commit;kbactive;kbinact;kbdirty;kbanonpg;kbslab;kbkstack;kbpgtbl;kbvmused", 0
		}
		return "kbmemfree;kbavail;kbmemused;%memused;kbbuffers;kbcached;kbcommit;%commit;kbactive;kbinact;kbdirty", 0
	case "swapmem":
		return "kbswpfree;kbswpused;%swpused;kbswpcad;%swpcad", 0
	case "huge":
		if v != "11.7" {
			return "kbhugfree;kbhugused;%hugused;kbhugrsvd;kbhugsurp", 0
		}
		return "kbhugfree;kbhugused;%hugused", 0
	case "ktables":
		return "dentunusd;file-nr;inode-nr;pty-nr", 0
	case "queue":
		return "runq-sz;plist-sz;ldavg-1;ldavg-5;ldavg-15;blocked", 0
	case "psicpu":
		return "%scpu-10;%scpu-60;%scpu-300;%scpu", 0
	case "netdev":
		return "IFACE;rxpck/s;txpck/s;rxkB/s;txkB/s;rxcmp/s;txcmp/s;rxmcst/s;%ifutil", 0
	case "netedev":
		return "IFACE;rxerr/s;txerr/s;coll/s;rxdrop/s;txdrop/s;txcarr/s;rxfram/s;rxfifo/s;txfifo/s", 0
	case "nfs":
		return "call/s;retrans/s;read/s;write/s;access/s;getatt/s", 0
	case "nfsd":
		return "scall/s;badcall/s;packet/s;udp/s;tcp/s;hit/s;miss/s;sread/s;swrite/s;saccess/s;sgetatt/s", 0
	case "sock":
		return "totsck;tcpsck;udpsck;rawsck;ip-frag;tcp-tw", 0
	case "ip":
		return "irec/s;fwddgm/s;idel/s;orq/s;asmrq/s;asmok/s;fragok/s;fragcrt/s", 0
	case "eip":
		return "ihdrerr/s;iadrerr/s;iukwnpr/s;idisc/s;odisc/s;onort/s;asmf/s;fragf/s", 0
	case "icmp":
		return "imsg/s;omsg/s;iech/s;iechr/s;oech/s;oechr/s;itm/s;itmr/s;otm/s;otmr/s;iadrmk/s;iadrmkr/s;oadrmk/s;oadrmkr/s", 0
	case "eicmp":
		return "ierr/s;oerr/s;idstunr/s;odstunr/s;itmex/s;otmex/s;iparmpb/s;oparmpb/s;isrcq/s;osrcq/s;iredir/s;oredir/s", 0
	case "tcp":
		return "active/s;passive/s;iseg/s;oseg/s", 0
	case "etcp":
		if v != "" { // retrseg/s since 12.7
			return "atmptf/s;estres/s;retrans/s;isegerr/s;orsts/s", 0
		}
		return "atmptf/s;estres/s;retrseg/s;isegerr/s;orsts/s", 0
	case "udp":
		return "idgm/s;odgm/s;noport/s;idgmerr/s", 0
	case "sock6":
		return "tcp6sck;udp6sck;raw6sck;ip6-frag", 0
	case "ip6":
		return "irec6/s;fwddgm6/s;idel6/s;orq6/s;asmrq6/s;asmok6/s;imcpck6/s;omcpck6/s;fragok6/s;fragcr6/s", 0
	case "eip6":
		return "ihdrer6/s;iadrer6/s;iukwnp6/s;i2big6/s;idisc6/s;odisc6/s;inort6/s;onort6/s;asmf6/s;fragf6/s;itrpck6/s", 0
	case "icmp6":
		return "imsg6/s;omsg6/s;iech6/s;iechr6/s;oechr6/s;igmbq6/s;igmbr6/s;ogmbr6/s;igmbrd6/s;ogmbrd6/s;irtsol6/s;ortsol6/s;irtad6/s;inbsol6/s;onbsol6/s;inbad6/s;onbad6/s", 0
	case "eicmp6":
		return "ierr6/s;idtunr6/s;odtunr6/s;itmex6/s;otmex6/s;iprmpb6/s;oprmpb6/s;iredir6/s;oredir6/s;ipck2b6/s;opck2b6/s", 0
	case "udp6":
		return "idgm6/s;odgm6/s;noport6/s;idgmer6/s", 0
	case "fs":
		return "FILESYSTEM;MBfsfree;MBfsused;%fsused;%ufsused;Ifree;Iused;%Iused", -1
	}
	return "", 0
}

// sarNetCols: the protocol counters of each report, by nstat name.
var sarNetCols = map[string][]string{
	"ip":  {"IpInReceives", "IpForwDatagrams", "IpInDelivers", "IpOutRequests", "IpReasmReqds", "IpReasmOKs", "IpFragOKs", "IpFragCreates"},
	"eip": {"IpInHdrErrors", "IpInAddrErrors", "IpInUnknownProtos", "IpInDiscards", "IpOutDiscards", "IpOutNoRoutes", "IpReasmFails", "IpFragFails"},
	"icmp": {"IcmpInMsgs", "IcmpOutMsgs", "IcmpInEchos", "IcmpInEchoReps", "IcmpOutEchos", "IcmpOutEchoReps", "IcmpInTimestamps",
		"IcmpInTimestampReps", "IcmpOutTimestamps", "IcmpOutTimestampReps", "IcmpInAddrMasks", "IcmpInAddrMaskReps",
		"IcmpOutAddrMasks", "IcmpOutAddrMaskReps"},
	"eicmp": {"IcmpInErrors", "IcmpOutErrors", "IcmpInDestUnreachs", "IcmpOutDestUnreachs", "IcmpInTimeExcds", "IcmpOutTimeExcds",
		"IcmpInParmProbs", "IcmpOutParmProbs", "IcmpInSrcQuenchs", "IcmpOutSrcQuenchs", "IcmpInRedirects", "IcmpOutRedirects"},
	"tcp":  {"TcpActiveOpens", "TcpPassiveOpens", "TcpInSegs", "TcpOutSegs"},
	"etcp": {"TcpAttemptFails", "TcpEstabResets", "TcpRetransSegs", "TcpInErrs", "TcpOutRsts"},
	"udp":  {"UdpInDatagrams", "UdpOutDatagrams", "UdpNoPorts", "UdpInErrors"},
	"ip6": {"Ip6InReceives", "Ip6OutForwDatagrams", "Ip6InDelivers", "Ip6OutRequests", "Ip6ReasmReqds", "Ip6ReasmOKs",
		"Ip6InMcastPkts", "Ip6OutMcastPkts", "Ip6FragOKs", "Ip6FragCreates"},
	"eip6": {"Ip6InHdrErrors", "Ip6InAddrErrors", "Ip6InUnknownProtos", "Ip6InTooBigErrors", "Ip6InDiscards", "Ip6OutDiscards",
		"Ip6InNoRoutes", "Ip6OutNoRoutes", "Ip6ReasmFails", "Ip6FragFails", "Ip6InTruncatedPkts"},
	"icmp6": {"Icmp6InMsgs", "Icmp6OutMsgs", "Icmp6InEchos", "Icmp6InEchoReplies", "Icmp6OutEchoReplies", "Icmp6InGroupMembQueries",
		"Icmp6InGroupMembResponses", "Icmp6OutGroupMembResponses", "Icmp6InGroupMembReductions", "Icmp6OutGroupMembReductions",
		"Icmp6InRouterSolicits", "Icmp6OutRouterSolicits", "Icmp6InRouterAdvertisements", "Icmp6InNeighborSolicits",
		"Icmp6OutNeighborSolicits", "Icmp6InNeighborAdvertisements", "Icmp6OutNeighborAdvertisements"},
	"eicmp6": {"Icmp6InErrors", "Icmp6InDestUnreachs", "Icmp6OutDestUnreachs", "Icmp6InTimeExcds", "Icmp6OutTimeExcds",
		"Icmp6InParmProblems", "Icmp6OutParmProblems", "Icmp6InRedirects", "Icmp6OutRedirects", "Icmp6InPktTooBigs", "Icmp6OutPktTooBigs"},
	"udp6": {"Udp6InDatagrams", "Udp6OutDatagrams", "Udp6NoPorts", "Udp6InErrors"},
}

// sarCounters: protocol counters as sadc reads them, unsigned long in
// /proc/net/snmp (64-bit), unsigned long long in snmp6.
func sarCounter(r *sarRec, name string) int64 { return r.net[name] }

// PrintSar prints the reports of every segment as sar -f does: per segment
// each report (its header, a line per record after the first, the Average),
// then LINUX RESTART before the next segment.
func PrintSar(w io.Writer, d *SarData, o SarOpts) { printSar(&sarPr{w: w}, d, o) }

// SarRows: sar's output as rows (--json), every line PrintSar prints but the
// first line and the headers.
func SarRows(d *SarData, o SarOpts) []SarRow {
	p := &sarPr{w: io.Discard, collect: true}
	printSar(p, d, o)
	return p.rows
}

func printSar(p *sarPr, d *SarData, o SarOpts) {
	p.isHdr = true
	p.s("%s", d.Header)
	p.nl()
	for si, seg := range d.Segments {
		if d.Restarts[si] != 0 {
			p.sb.WriteString("\n")
			p.ts(clock(d.Restarts[si]))
			p.s("  LINUX RESTART\t(%d CPU)", d.ncpu[si])
			p.isHdr = true
			p.nl()
			if p.collect {
				p.rows = append(p.rows, SarRow{TS: d.Restarts[si], Kind: "restart", CPUs: d.ncpu[si]})
			}
		}
		if len(seg) < 2 {
			continue
		}
		for _, key := range SarActOrder {
			for _, a := range o.Acts {
				if a.Key == key {
					p.report, p.seg, p.lastTS = sarReportName(a), seg, 0
					printSarAct(p, seg, a, o, d)
				}
			}
		}
	}
}

// sarReportName names a report in --json by sar's option for it.
func sarReportName(a SarAct) string {
	n := map[string]string{"cpu": "-u", "pcsw": "-w", "irq": "-I", "swap": "-W", "paging": "-B", "io": "-b", "mem": "-r",
		"swapmem": "-S", "huge": "-H", "ktables": "-v", "queue": "-q", "disk": "-d", "netdev": "-n DEV", "netedev": "-n EDEV",
		"nfs": "-n NFS", "nfsd": "-n NFSD", "sock": "-n SOCK", "ip": "-n IP", "eip": "-n EIP", "icmp": "-n ICMP",
		"eicmp": "-n EICMP", "tcp": "-n TCP", "etcp": "-n ETCP", "udp": "-n UDP", "sock6": "-n SOCK6", "ip6": "-n IP6",
		"eip6": "-n EIP6", "icmp6": "-n ICMP6", "eicmp6": "-n EICMP6", "udp6": "-n UDP6", "softnet": "-n SOFT",
		"cpufreq": "-m CPU", "fs": "-F", "psicpu": "-q CPU", "psiio": "-q IO", "psimem": "-q MEM"}[a.Key]
	if a.All && (a.Key == "cpu" || a.Key == "mem" || a.Key == "irq") {
		n += " ALL"
	}
	return n
}

// sarCPUAll is get_global_cpu_statistics: CPU "all" as the sum of the CPUs
// online at both records, and its interval in ticks.
func sarCPUs(prev, cur *sarRec) (map[int]cpuTimes, map[int]cpuTimes, map[int]bool, int64) {
	pc, cc := map[int]cpuTimes{}, map[int]cpuTimes{}
	off := map[int]bool{}
	var allP, allC cpuTimes
	var tot int64
	n := 0
	for c := range cur.cpus {
		n = max(n, c+1)
	}
	for c := range prev.cpus {
		n = max(n, c+1)
	}
	if n <= 1 { // one CPU: the total line as read
		pc[-1], cc[-1] = prev.cpus[-1], cur.cpus[-1]
		pc[0], cc[0] = prev.cpus[0], cur.cpus[0]
		return pc, cc, off, perCPUInterval(cc[-1], pc[-1])
	}
	for c := 0; c < n; c++ {
		ct, okc := cur.cpus[c]
		pt, okp := prev.cpus[c]
		if !okc {
			ct, off[c] = pt, true
		}
		if !okp {
			off[c] = true
			continue
		}
		tot += perCPUInterval(ct, pt)
		pc[c], cc[c] = pt, ct
		for i := range allC {
			allC[i] += ct[i]
			allP[i] += pt[i]
		}
	}
	pc[-1], cc[-1] = allP, allC
	return pc, cc, off, tot
}

// perCPUInterval is get_per_cpu_interval: the ticks of a CPU in the
// interval (guest counted in user and nice).
func perCPUInterval(c, p cpuTimes) int64 {
	var shift int64
	if c[cUser]-c[cGuest] < p[cUser]-p[cGuest] {
		shift += (p[cUser] - p[cGuest]) - (c[cUser] - c[cGuest])
	}
	if c[cNice]-c[cGuestNice] < p[cNice]-p[cGuestNice] {
		shift += (p[cNice] - p[cGuestNice]) - (c[cNice] - c[cGuestNice])
	}
	if c[cIOWait] < p[cIOWait] {
		if c[cIdle] > p[cIdle] {
			p[cIOWait] = c[cIOWait]
		} else {
			p[cIOWait] = 0
		}
	}
	if c[cIdle] < p[cIdle] {
		p[cIdle] = 0
	}
	sum := func(t cpuTimes) int64 {
		return t[cUser] + t[cNice] + t[cSystem] + t[cIOWait] + t[cIdle] + t[cSteal] + t[cIRQ] + t[cSoftIRQ]
	}
	return sum(c) - sum(p) + shift
}

func printSarCPU(p *sarPr, prev, cur *sarRec, a SarAct, ts string) {
	pc, cc, off, tot := sarCPUs(prev, cur)
	n := 0
	for c := range cur.cpus {
		n = max(n, c+1)
	}
	show := func(i int) bool { // i: 0 "all", 1.. the CPUs
		if a.CPUs == nil {
			return i == 0
		}
		for _, c := range a.CPUs {
			if c == SarAllCPU || c == i-1 {
				return true
			}
		}
		return false
	}
	for i := 0; i <= n; i++ {
		if n <= 1 && i > 0 {
			break
		}
		if !show(i) || i > 0 && off[i-1] {
			continue
		}
		cpu := i - 1
		c, pr := cc[cpu], pc[cpu]
		itv := tot
		p.ts(ts)
		if i == 0 {
			p.s(" %s", "    all")
			if n <= 1 {
				itv = perCPUInterval(c, pr)
			}
			if itv == 0 {
				itv = 1
			}
		} else {
			p.s(" %7d", cpu)
			itv = perCPUInterval(c, pr)
			if itv == 0 {
				p.f(2, 0, 0, 0, 0, 0)
				if a.All {
					p.f(2, 0, 0, 0, 0, 100)
				} else {
					p.f(2, 100)
				}
				p.nl()
				continue
			}
		}
		idle := llsp(pr[cIdle], c[cIdle], itv)
		if c[cIdle] < pr[cIdle] {
			idle = 0
		}
		if !a.All {
			p.f(2, llsp(pr[cUser], c[cUser], itv), llsp(pr[cNice], c[cNice], itv),
				llsp(pr[cSystem]+pr[cIRQ]+pr[cSoftIRQ], c[cSystem]+c[cIRQ]+c[cSoftIRQ], itv),
				llsp(pr[cIOWait], c[cIOWait], itv), llsp(pr[cSteal], c[cSteal], itv), idle)
		} else {
			usr := llsp(pr[cUser]-pr[cGuest], c[cUser]-c[cGuest], itv)
			if c[cUser]-c[cGuest] < pr[cUser]-pr[cGuest] {
				usr = 0
			}
			nice := llsp(pr[cNice]-pr[cGuestNice], c[cNice]-c[cGuestNice], itv)
			if c[cNice]-c[cGuestNice] < pr[cNice]-pr[cGuestNice] {
				nice = 0
			}
			p.f(2, usr, nice, llsp(pr[cSystem], c[cSystem], itv), llsp(pr[cIOWait], c[cIOWait], itv),
				llsp(pr[cSteal], c[cSteal], itv), llsp(pr[cIRQ], c[cIRQ], itv), llsp(pr[cSoftIRQ], c[cSoftIRQ], itv),
				llsp(pr[cGuest], c[cGuest], itv), llsp(pr[cGuestNice], c[cGuestNice], itv), idle)
		}
		p.nl()
	}
}

// printSarAct prints one report over a segment.
func printSarAct(p *sarPr, seg []sarRec, a SarAct, o SarOpts, d *SarData) {
	v := o.Version
	if sar14Keys[a.Key] {
		printSar14(p, seg, a, o, d.devNames, a.Pretty)
		return
	}
	if a.Key == "irq" && v != "11.7" && v != "12.5" {
		printSarIRQ(p, seg, a, a.All)
		return
	}
	first, last := &seg[0], &seg[len(seg)-1]
	titles, iw := sarHeader(a.Key, a.All, v)
	// sar -f prints the header again when the lines counted since the last
	// one reach its window height, 86400 into a pipe or a file; a record
	// counts its items, -P's every bit of its CPU bitmap (NR_CPUS 8192).
	lines := 0
	inc := func(r *sarRec) int {
		switch a.Key {
		case "cpu":
			if a.CPUs == nil {
				return 1
			}
			for _, c := range a.CPUs {
				if c == SarAllCPU {
					return (8192>>3 + 1) * 8
				}
			}
			return len(a.CPUs)
		case "netdev", "netedev":
			n := 0
			for _, l := range r.links {
				if l.HasStats {
					n++
				}
			}
			return n
		case "fs":
			return len(r.fs)
		}
		return 1
	}
	itv := func(prev, cur *sarRec) int64 { return max(cur.upCS-prev.upCS, 1) }
	// Level reports: averages of the values printed.
	var sums []float64
	add := func(vals ...float64) {
		if sums == nil {
			sums = make([]float64, len(vals))
		}
		for i, x := range vals {
			sums[i] += x
		}
	}
	count := float64(len(seg) - 1)
	avg := func(i int) float64 { return sums[i] / count }
	// Integer averages where sysstat divides unsigned long longs.
	iavg := func(i int) float64 { return math.Floor(sums[i] / count) }
	for i := 1; i < len(seg); i++ {
		prev, cur := &seg[i-1], &seg[i]
		if lines == 0 || lines >= 3600*24 {
			lines = 0
			p.hdr(clock(prev.ts), titles, iw)
		}
		lines += inc(cur)
		ts := clock(cur.ts)
		iv := itv(prev, cur)
		s, ps := &cur.sys, &prev.sys
		switch a.Key {
		case "cpu":
			printSarCPU(p, prev, cur, a, ts)
		case "pcsw":
			p.ts(ts)
			p.f(2, sv(ps.Forks, s.Forks, iv), sv(ps.Ctxt, s.Ctxt, iv))
			p.nl()
		case "irq":
			p.ts(ts)
			p.s(" %9s", "sum")
			p.f(2, sv(ps.Intr, s.Intr, iv))
			p.nl()
		case "swap":
			p.ts(ts)
			p.f(2, sv(ps.PswpIn, s.PswpIn, iv), sv(ps.PswpOut, s.PswpOut, iv))
			p.nl()
		case "mem":
			p.ts(ts)
			raw := s.MemFree + s.Buffers + s.Cached + s.Slab
			if v == "11.7" {
				raw = s.MemFree
			}
			nouse := min(raw, s.MemTotal)
			p.u(s.MemFree, s.MemAvailable, s.MemTotal-nouse)
			p.f(2, pctOf(s.MemTotal-nouse, s.MemTotal))
			p.u(s.Buffers, s.Cached, s.committed)
			p.f(2, pctOf(s.committed, s.MemTotal+s.SwapTotal))
			p.u(s.Active, s.Inactive, s.Dirty)
			x := cur.x
			if a.All {
				p.u(x.anon, s.Slab, x.kstack, x.pgtbl, x.vmalloc)
			}
			p.nl()
			add(float64(s.MemFree), float64(s.MemAvailable), float64(raw), float64(s.Buffers), float64(s.Cached),
				float64(s.committed), float64(s.Active), float64(s.Inactive), float64(s.Dirty),
				float64(x.anon), float64(s.Slab), float64(x.kstack), float64(x.pgtbl), float64(x.vmalloc))
		case "swapmem":
			p.ts(ts)
			p.u(s.SwapFree, s.SwapTotal-s.SwapFree)
			p.f(2, pctOf(s.SwapTotal-s.SwapFree, s.SwapTotal))
			p.u(s.SwapCached)
			p.f(2, pctOf(s.SwapCached, s.SwapTotal-s.SwapFree))
			p.nl()
			add(float64(s.SwapFree), float64(s.SwapTotal), float64(s.SwapCached))
		case "huge":
			tl, fr := s.hugeTotal*s.hugeSize, s.hugeFree*s.hugeSize
			rs, su := cur.x.hugeRsvd*s.hugeSize, cur.x.hugeSurp*s.hugeSize
			p.ts(ts)
			p.u(fr, tl-fr)
			p.f(2, pctOf(tl-fr, tl))
			if v != "11.7" {
				p.u(rs, su)
			}
			p.nl()
			add(float64(fr), float64(tl), float64(rs), float64(su))
		case "ktables":
			p.ts(ts)
			p.u(cur.kt[0], cur.kt[1], cur.kt[2], cur.kt[3])
			p.nl()
			add(float64(cur.kt[0]), float64(cur.kt[1]), float64(cur.kt[2]), float64(cur.kt[3]))
		case "queue":
			run := s.Runnable
			if run > 0 {
				run--
			}
			p.ts(ts)
			p.u(int64(run), int64(s.Threads))
			p.f(2, float64(s.Load1)/100, float64(s.Load5)/100, float64(s.Load15)/100)
			p.u(int64(s.ProcsBlocked))
			p.nl()
			add(float64(run), float64(s.Threads), float64(s.Load1), float64(s.Load5), float64(s.Load15), float64(s.ProcsBlocked))
		case "psicpu":
			p.ts(ts)
			p.f(2, float64(s.psiCPU10)/100, float64(s.psiCPU60)/100, float64(s.psiCPU300)/100,
				float64(s.psiCPU-ps.psiCPU)/(100*float64(iv)))
			p.nl()
			add(float64(s.psiCPU10), float64(s.psiCPU60), float64(s.psiCPU300))
		case "sock":
			p.ts(ts)
			p.u(s.sockUsed, s.tcpInUse, s.udpInUse, s.rawInUse, s.fragInUse, s.tcpTW)
			p.nl()
			add(float64(s.sockUsed), float64(s.tcpInUse), float64(s.udpInUse), float64(s.rawInUse), float64(s.fragInUse), float64(s.tcpTW))
		case "sock6":
			p.ts(ts)
			p.u(s.tcp6InUse, s.udp6InUse, s.raw6InUse, s.frag6InUse)
			p.nl()
			add(float64(s.tcp6InUse), float64(s.udp6InUse), float64(s.raw6InUse), float64(s.frag6InUse))
		case "netdev", "netedev":
			printSarNetDev(p, prev, cur, a.Key, ts, iv)
		case "nfs":
			p.ts(ts)
			for j := range cur.nfs {
				p.f(2, sv(prev.nfs[j], cur.nfs[j], iv))
			}
			p.nl()
		case "nfsd":
			p.ts(ts)
			for j := range cur.nfsd {
				p.f(2, sv(prev.nfsd[j], cur.nfsd[j], iv))
			}
			p.nl()
		case "fs":
			for _, f := range cur.fs {
				printSarFS(p, f, ts, a.Mount)
			}
		default:
			if cols, ok := sarNetCols[a.Key]; ok {
				p.ts(ts)
				for _, c := range cols {
					p.f(2, sv(sarCounter(prev, c), sarCounter(cur, c), iv))
				}
				p.nl()
			}
		}
	}
	// The Average lines.
	const av = "Average:"
	iv := itv(first, last)
	s, fs := &last.sys, &first.sys
	switch a.Key {
	case "cpu":
		printSarCPU(p, first, last, a, av)
	case "pcsw":
		p.ts(av)
		p.f(2, sv(fs.Forks, s.Forks, iv), sv(fs.Ctxt, s.Ctxt, iv))
		p.nl()
	case "irq":
		p.ts(av)
		p.s(" %9s", "sum")
		p.f(2, sv(fs.Intr, s.Intr, iv))
		p.nl()
	case "swap":
		p.ts(av)
		p.f(2, sv(fs.PswpIn, s.PswpIn, iv), sv(fs.PswpOut, s.PswpOut, iv))
		p.nl()
	case "mem":
		p.ts(av)
		tl := float64(s.MemTotal)
		p.f(0, avg(0), avg(1), tl-avg(2))
		p.f(2, pctOf64(tl-iavg(2), tl))
		p.f(0, avg(3), avg(4), avg(5))
		p.f(2, pctOf64(iavg(5), float64(s.MemTotal+s.SwapTotal)))
		p.f(0, avg(6), avg(7), avg(8))
		if a.All {
			p.f(0, avg(9), avg(10), avg(11), avg(12), avg(13))
		}
		p.nl()
	case "swapmem":
		p.ts(av)
		fr, tl, ca := avg(0), avg(1), avg(2)
		p.f(0, fr, tl-fr)
		p.f(2, pctOf64(tl-fr, tl))
		p.f(0, ca)
		if sums[1] != sums[0] {
			p.f(2, pctOf64(ca, tl-fr))
		} else {
			p.f(2, 0)
		}
		p.nl()
	case "huge":
		p.ts(av)
		fr, tl := avg(0), avg(1)
		p.f(0, fr, tl-fr)
		p.f(2, pctOf64(tl-fr, tl))
		if v != "11.7" {
			p.f(0, avg(2), avg(3))
		}
		p.nl()
	case "ktables":
		p.ts(av)
		p.f(0, avg(0), avg(1), avg(2), avg(3))
		p.nl()
	case "queue":
		p.ts(av)
		p.f(0, avg(0), avg(1))
		p.f(2, avg(2)/100, avg(3)/100, avg(4)/100)
		p.f(0, avg(5))
		p.nl()
	case "psicpu":
		p.ts(av)
		p.f(2, avg(0)/100, avg(1)/100, avg(2)/100, float64(s.psiCPU-fs.psiCPU)/(100*float64(iv)))
		p.nl()
	case "sock":
		p.ts(av)
		p.f(0, avg(0), avg(1), avg(2), avg(3), avg(4), avg(5))
		p.nl()
	case "sock6":
		p.ts(av)
		p.f(0, avg(0), avg(1), avg(2), avg(3))
		p.nl()
	case "netdev", "netedev":
		printSarNetDev(p, first, last, a.Key, av, iv)
	case "nfs":
		p.ts(av)
		for j := range last.nfs {
			p.f(2, sv(first.nfs[j], last.nfs[j], iv))
		}
		p.nl()
	case "nfsd":
		p.ts(av)
		for j := range last.nfsd {
			p.f(2, sv(first.nfsd[j], last.nfsd[j], iv))
		}
		p.nl()
	case "fs":
		// "Summary:": the last values of every file system seen.
		var all []DFRow
		seen := map[string]int{}
		for _, r := range seg[1:] {
			for _, f := range r.fs {
				if i, ok := seen[f.Source]; ok {
					all[i] = f
					continue
				}
				seen[f.Source] = len(all)
				all = append(all, f)
			}
		}
		for _, f := range all {
			printSarFS(p, f, "Summary:", a.Mount)
		}
	default:
		if cols, ok := sarNetCols[a.Key]; ok {
			p.ts(av)
			for _, c := range cols {
				p.f(2, sv(sarCounter(first, c), sarCounter(last, c), iv))
			}
			p.nl()
		}
	}
}

func pctOf(part, whole int64) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) / float64(whole) * 100
}

func pctOf64(part, whole float64) float64 {
	if whole == 0 {
		return 0
	}
	return part / whole * 100
}

// printSarNetDev prints -n DEV or EDEV: every interface of the later record
// (as /proc/net/dev lists them), rates against its row in the earlier one.
func printSarNetDev(p *sarPr, prev, cur *sarRec, key, ts string, iv int64) {
	// sa_common.c check_net_dev_reg / check_net_edev_reg: the interface of
	// the same name in the earlier record; counting from zero when one of
	// its counters went down (unregistered, then registered again), unless
	// a byte or packet counter wrapped while the other grew.
	before := map[string]store.LinkRow{}
	for _, l := range prev.links {
		if l.HasStats {
			before[l.Name] = l
		}
	}
	links := append([]store.LinkRow(nil), cur.links...)
	sort.SliceStable(links, func(i, j int) bool { return links[i].Index < links[j].Index })
	for _, c := range links {
		if !c.HasStats {
			continue
		}
		pr, ok := before[c.Name]
		const half = uint64(math.MaxUint64 >> 1)
		lt := func(i int) bool { return uint64(c.Stats[i]) < uint64(pr.Stats[i]) }
		if ok && key == "netdev" && (lt(0) || lt(1) || lt(2) || lt(3) || lt(21) || lt(22) || lt(8)) {
			ovfw := lt(2) && !lt(0) && c.Stats[0] != pr.Stats[0] && uint64(pr.Stats[2]) > half ||
				lt(3) && !lt(1) && c.Stats[1] != pr.Stats[1] && uint64(pr.Stats[3]) > half ||
				lt(0) && !lt(2) && c.Stats[2] != pr.Stats[2] && uint64(pr.Stats[0]) > half ||
				lt(1) && !lt(3) && c.Stats[3] != pr.Stats[3] && uint64(pr.Stats[1]) > half
			if !ovfw {
				ok = false
			}
		}
		if ok && key == "netedev" {
			// tx errors, collisions, rx/tx dropped, carrier, frame, fifo as
			// /proc/net/dev sums them.
			sum := func(r store.LinkRow, idx ...int) uint64 {
				var t uint64
				for _, i := range idx {
					t += uint64(r.Stats[i])
				}
				return t
			}
			for _, idx := range [][]int{{5}, {9}, {6, 15}, {7}, {17, 16, 20, 19}, {10, 11, 12, 13}, {14}, {18}} {
				if sum(c, idx...) < sum(pr, idx...) {
					ok = false
				}
			}
		}
		if !ok {
			pr = store.LinkRow{} // new, or registered again: since its registration
		}
		d := func(i int) float64 { return sv(pr.Stats[i], c.Stats[i], iv) }
		p.ts(ts)
		p.s(" %9s", c.Name)
		const (
			rxP, txP, rxB, txB, rxE, txE, rxD, txD, mc, coll = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
			rxLen, rxOver, rxCRC, rxFrame, rxFIFO, rxMiss    = 10, 11, 12, 13, 14, 15
			txAbort, txCarr, txFIFO, txHB, txWin, rxC, txC   = 16, 17, 18, 19, 20, 21, 22
		)
		if key == "netdev" {
			rx, tx := d(rxB), d(txB)
			p.f(2, d(rxP), d(txP), rx/1024, tx/1024, d(rxC), d(txC), d(mc))
			util := 0.0
			if c.Speed > 0 {
				speed := float64(c.Speed) * 1000000
				if c.Duplex == 1 {
					util = max(rx, tx) * 800 / speed
				} else {
					util = (rx + tx) * 800 / speed
				}
			}
			p.f(2, util)
		} else {
			// /proc/net/dev's columns: drop = dropped + missed, frame = length
			// + over + crc + frame errors, carrier = carrier + aborted + window
			// + heartbeat errors.
			sum := func(r store.LinkRow, idx ...int) int64 {
				var t int64
				for _, i := range idx {
					t += r.Stats[i]
				}
				return t
			}
			ds := func(idx ...int) float64 { return sv(sum(pr, idx...), sum(c, idx...), iv) }
			p.f(2, d(rxE), d(txE), d(coll), ds(rxD, rxMiss), d(txD), ds(txCarr, txAbort, txWin, txHB),
				ds(rxLen, rxOver, rxCRC, rxFrame), d(rxFIFO), d(txFIFO))
		}
		p.nl()
	}
}

func printSarFS(p *sarPr, f DFRow, ts string, mount bool) {
	blocks := float64(f.SizeBytes)
	free := float64(f.SizeBytes - f.UsedBytes)
	avail := float64(f.AvailBytes)
	p.ts(ts)
	p.f(0, free/1024/1024, (blocks-free)/1024/1024)
	p.f(2, pctOf64(blocks-free, blocks), pctOf64(blocks-avail, blocks))
	p.u(f.IFree, f.Inodes-f.IFree)
	p.f(2, pctOf64(float64(f.Inodes-f.IFree), float64(f.Inodes)))
	name := f.Source
	if mount {
		name = f.Point
	}
	p.s(" %s", name)
	p.nl()
}

// SarVersion names the sysstat release printed for a style.
func SarVersion(st ToolStyle) string {
	switch st.Sar {
	case "11.7":
		return "11.7.3"
	case "12.5":
		return "12.5"
	case "12.6":
		return "12.6.1"
	}
	return "12.7.7"
}

// HasPSI: the host had /proc/pressure (sadc collects CPU pressure only then).
func (d *SarData) HasPSI() bool {
	for _, seg := range d.Segments {
		for _, r := range seg {
			if r.sys.psi {
				return true
			}
		}
	}
	return false
}
