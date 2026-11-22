// sar's reports from what clifrd records since schema 14 (paging, I/O,
// disks, softnet, CPU frequency, I/O and memory pressure, interrupts). They
// follow sysstat's code as sar.go does (packaging/notices/sysstat.txt).

package query

import (
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// sarX: a record's schema 14 system values (sadc's stats_paging, the
// meminfo lines of sar -r ALL and -H, the I/O and memory pressure).
type sarX struct {
	ok                                               bool // recorded (schema 14)
	pgin, pgout, fault, majflt, pgfree               int64
	scanK, scanD, steal, promote, demote             int64
	anon, kstack, vmalloc, pgtbl, hugeRsvd, hugeSurp int64
	ioSome, ioFull, memSome, memFull                 int64
	ioSomeAvg, ioFullAvg, memSomeAvg, memFullAvg     [3]int64
}

// sarCPUX: a CPU's frequency (hundredths of a MHz; -1 unknown) and softnet
// counters.
type sarCPUX struct {
	mhz  int64
	sn   [6]int64
	snOK bool
}

// sarDisk: a /proc/diskstats line as sadc keeps it.
type sarDisk struct {
	major, minor, pos                              int
	name                                           string
	part, virtual                                  bool
	rdIOs, rdSect, rdTicks, wrIOs, wrSect, wrTicks int64
	dcIOs, dcSect, dcTicks, ioTicks, timeInQueue   int64
}

// sarIRQ: /proc/interrupts (the CPUs of its header, each line's counts).
type sarIRQ struct {
	ts    int64 // when it was read (rates are over the reads' own interval)
	cpus  []int
	names []string
	vals  [][]int64
}

var sar14Keys = map[string]bool{"paging": true, "io": true, "disk": true, "softnet": true, "cpufreq": true, "psiio": true, "psimem": true}

// load14 reads what the schema 14 reports need.
func (d *SarData) load14(db *store.DB, o SarOpts, lo, hi int64) error {
	recs := func(f func(r *sarRec)) {
		for si := range d.Segments {
			for i := range d.Segments[si] {
				f(&d.Segments[si][i])
			}
		}
	}
	if o.has("paging") || o.has("mem") || o.has("huge") || o.has("psiio") || o.has("psimem") {
		rows, err := db.Query(`SELECT ts, pgpgin, pgpgout, pgfault, pgmajfault, COALESCE(pgfree, -1),
			COALESCE(pgsteal_kswapd, 0) + COALESCE(pgsteal_direct, 0) + COALESCE(pgsteal_khugepaged, 0) + COALESCE(pgsteal_proactive, 0)
			  + COALESCE(pgsteal_anon, 0) + COALESCE(pgsteal_file, 0),
			COALESCE(pgscan_kswapd, 0), COALESCE(pgscan_direct, 0) + COALESCE(pgscan_direct_throttle, 0),
			COALESCE(pgpromote, 0), COALESCE(pgdemote, 0), COALESCE(anon_pages, 0), COALESCE(kernel_stack, 0),
			COALESCE(vmalloc_used, 0), COALESCE(page_tables, 0), COALESCE(hugepages_rsvd, 0), COALESCE(hugepages_surp, 0),
			COALESCE(psi_io_some, 0), COALESCE(psi_io_full, 0), COALESCE(psi_mem_some, 0), COALESCE(psi_mem_full, 0),
			COALESCE(psi_io_avg10, 0), COALESCE(psi_io_avg60, 0), COALESCE(psi_io_avg300, 0),
			COALESCE(psi_io_full_avg10, 0), COALESCE(psi_io_full_avg60, 0), COALESCE(psi_io_full_avg300, 0),
			COALESCE(psi_mem_avg10, 0), COALESCE(psi_mem_avg60, 0), COALESCE(psi_mem_avg300, 0),
			COALESCE(psi_mem_full_avg10, 0), COALESCE(psi_mem_full_avg60, 0), COALESCE(psi_mem_full_avg300, 0)
			FROM sys_samples WHERE ts BETWEEN ? AND ?`, lo, hi)
		if err != nil {
			return err
		}
		xs := map[int64]sarX{}
		for rows.Next() {
			var ts int64
			var x sarX
			if err := rows.Scan(&ts, &x.pgin, &x.pgout, &x.fault, &x.majflt, &x.pgfree, &x.steal, &x.scanK, &x.scanD,
				&x.promote, &x.demote, &x.anon, &x.kstack, &x.vmalloc, &x.pgtbl, &x.hugeRsvd, &x.hugeSurp,
				&x.ioSome, &x.ioFull, &x.memSome, &x.memFull,
				&x.ioSomeAvg[0], &x.ioSomeAvg[1], &x.ioSomeAvg[2], &x.ioFullAvg[0], &x.ioFullAvg[1], &x.ioFullAvg[2],
				&x.memSomeAvg[0], &x.memSomeAvg[1], &x.memSomeAvg[2], &x.memFullAvg[0], &x.memFullAvg[1], &x.memFullAvg[2]); err != nil {
				rows.Close()
				return err
			}
			x.ok = x.pgfree >= 0
			xs[ts] = x
		}
		rows.Close()
		recs(func(r *sarRec) { r.x = xs[r.ts] })
	}
	if o.has("softnet") || o.has("cpufreq") {
		rows, err := db.Query(`SELECT ts, cpu, COALESCE(mhz, -1), softnet_total IS NOT NULL, COALESCE(softnet_total, 0),
			COALESCE(softnet_dropped, 0), COALESCE(softnet_squeezed, 0), COALESCE(softnet_rps, 0),
			COALESCE(softnet_flow_limit, 0), COALESCE(softnet_backlog, 0)
			FROM cpu_samples WHERE ts BETWEEN ? AND ? AND cpu >= 0`, lo, hi)
		if err != nil {
			return err
		}
		xs := map[int64]map[int]sarCPUX{}
		for rows.Next() {
			var ts int64
			var cpu int
			var x sarCPUX
			if err := rows.Scan(&ts, &cpu, &x.mhz, &x.snOK, &x.sn[0], &x.sn[1], &x.sn[2], &x.sn[3], &x.sn[4], &x.sn[5]); err != nil {
				rows.Close()
				return err
			}
			if xs[ts] == nil {
				xs[ts] = map[int]sarCPUX{}
			}
			xs[ts][cpu] = x
		}
		rows.Close()
		recs(func(r *sarRec) { r.cpux = xs[r.ts] })
	}
	if o.has("io") || o.has("disk") {
		rows, err := db.Query(`SELECT ts, major, minor, name, part, COALESCE(virtual, -1), COALESCE(pos, -1),
			rd_ios, rd_sectors, rd_ticks, wr_ios, wr_sectors, wr_ticks, dc_ios, dc_sectors, dc_ticks, io_ticks, time_in_queue
			FROM disk_samples WHERE ts BETWEEN ? AND ?`, lo, hi)
		if err != nil {
			return err
		}
		xs := map[int64][]sarDisk{}
		for rows.Next() {
			var ts int64
			var k sarDisk
			var part, virt int
			if err := rows.Scan(&ts, &k.major, &k.minor, &k.name, &part, &virt, &k.pos, &k.rdIOs, &k.rdSect, &k.rdTicks,
				&k.wrIOs, &k.wrSect, &k.wrTicks, &k.dcIOs, &k.dcSect, &k.dcTicks, &k.ioTicks, &k.timeInQueue); err != nil {
				rows.Close()
				return err
			}
			if virt < 0 {
				rows.Close()
				return fmt.Errorf("sar -b and -d need each device's position and kind, recorded since schema 14 (2026-11-22)")
			}
			k.part, k.virtual = part == 1, virt == 1
			xs[ts] = append(xs[ts], k)
		}
		rows.Close()
		for ts := range xs {
			sort.Slice(xs[ts], func(i, j int) bool { return xs[ts][i].pos < xs[ts][j].pos })
		}
		recs(func(r *sarRec) { r.disks = xs[r.ts] })
	}
	if o.has("irq") && o.Version != "11.7" && o.Version != "12.5" {
		var err error
		recs(func(r *sarRec) {
			if err == nil {
				r.irq, err = sarInterrupts(db, r.ts)
			}
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// sarInterrupts parses the /proc/interrupts snapshot at or before t (read
// every minute): the header's CPUs, then each line's name and counts.
func sarInterrupts(db *store.DB, t int64) (*sarIRQ, error) {
	lines, ts, ok, err := FileAt(db, "interrupts", t)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("sar -I: /proc/interrupts is recorded since schema 14 (2026-11-22)")
	}
	q := &sarIRQ{ts: ts}
	for _, l := range lines {
		name, rest, found := strings.Cut(l, ":")
		if !found {
			for _, f := range strings.Fields(l) {
				if n, err := strconv.Atoi(strings.TrimPrefix(f, "CPU")); err == nil && strings.HasPrefix(f, "CPU") {
					q.cpus = append(q.cpus, n)
				}
			}
			continue
		}
		var v []int64
		for _, f := range strings.Fields(rest) {
			if len(v) == len(q.cpus) {
				break
			}
			n, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				break
			}
			v = append(v, int64(n))
		}
		q.names = append(q.names, strings.TrimSpace(name))
		q.vals = append(q.vals, v)
	}
	return q, nil
}

// sar14Header: the column titles of the schema 14 reports.
func sar14Header(key, v string) (string, int) {
	switch key {
	case "paging":
		if v == "" {
			return "pgpgin/s;pgpgout/s;fault/s;majflt/s;pgfree/s;pgscank/s;pgscand/s;pgsteal/s;pgprom/s;pgdem/s", 0
		}
		return "pgpgin/s;pgpgout/s;fault/s;majflt/s;pgfree/s;pgscank/s;pgscand/s;pgsteal/s;%vmeff", 0
	case "io":
		if v == "11.7" {
			return "tps;rtps;wtps;bread/s;bwrtn/s", 0
		}
		return "tps;rtps;wtps;dtps;bread/s;bwrtn/s;bdscd/s", 0
	case "disk":
		if v == "11.7" {
			return "DEV;tps;rkB/s;wkB/s;areq-sz;aqu-sz;await;svctm;%util", 0
		}
		return "DEV;tps;rkB/s;wkB/s;dkB/s;areq-sz;aqu-sz;await;%util", 0
	case "softnet":
		if v == "11.7" || v == "12.5" {
			return "CPU;total/s;dropd/s;squeezd/s;rx_rps/s;flw_lim/s", 7
		}
		return "CPU;total/s;dropd/s;squeezd/s;rx_rps/s;flw_lim/s;blg_len", 7
	case "cpufreq":
		return "CPU;MHz", 7
	case "psiio":
		return "%sio-10;%sio-60;%sio-300;%sio;%fio-10;%fio-60;%fio-300;%fio", 0
	case "psimem":
		return "%smem-10;%smem-60;%smem-300;%smem;%fmem-10;%fmem-60;%fmem-300;%fmem", 0
	}
	return "", 0
}

// sarCPUShown: the CPUs a report lists (0 "all", i the CPU i-1) for -P.
func sarCPUShown(a SarAct, i int) bool {
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

// printSar14 prints one schema 14 report over a segment, as printSarAct.
func printSar14(p *sarPr, seg []sarRec, a SarAct, o SarOpts, names map[[2]int]string, pretty bool) {
	v := o.Version
	first, last := &seg[0], &seg[len(seg)-1]
	titles, iw := sar14Header(a.Key, v)
	// -p: sysstat 12 prints the name last; 11's only changes the names.
	last12 := pretty && v != "11.7"
	if last12 && a.Key == "disk" {
		iw = -1
	}
	itv := func(prev, cur *sarRec) int64 { return max(cur.upCS-prev.upCS, 1) }
	ncpu := 0
	for c := range last.cpux {
		ncpu = max(ncpu, c+1)
	}
	lines := 0
	inc := func(r *sarRec) int {
		switch a.Key {
		case "disk":
			n := 0
			for _, k := range r.disks {
				if !k.part {
					n++
				}
			}
			return n
		case "softnet", "cpufreq":
			if a.CPUs == nil {
				return 1
			}
			for _, c := range a.CPUs {
				if c == SarAllCPU {
					return (8192>>3 + 1) * 8
				}
			}
			return len(a.CPUs)
		}
		return 1
	}
	var levels []float64 // sums of the level values printed (averages)
	var perCPU = map[int]float64{}
	count := float64(len(seg) - 1)
	row := func(prev, cur *sarRec, ts string, avg bool) {
		iv := itv(prev, cur)
		switch a.Key {
		case "paging":
			px, cx := prev.x, cur.x
			p.ts(ts)
			p.f(2, sv(px.pgin, cx.pgin, iv), sv(px.pgout, cx.pgout, iv), sv(px.fault, cx.fault, iv), sv(px.majflt, cx.majflt, iv),
				sv(px.pgfree, cx.pgfree, iv), sv(px.scanK, cx.scanK, iv), sv(px.scanD, cx.scanD, iv), sv(px.steal, cx.steal, iv))
			if v == "" {
				p.f(2, sv(px.promote, cx.promote, iv), sv(px.demote, cx.demote, iv))
			} else {
				scan := cx.scanK + cx.scanD - px.scanK - px.scanD
				eff := 0.0
				if scan != 0 {
					eff = float64(cx.steal-px.steal) / float64(scan) * 100
				}
				p.f(2, eff)
			}
			p.nl()
		case "io":
			var pt, ct [8]int64 // ios, rd, wr, dc ios; rd, wr, dc sectors
			sum := func(ds []sarDisk, t *[8]int64) {
				for _, k := range ds {
					if k.part || k.virtual {
						continue
					}
					if v == "11.7" {
						t[0] += k.rdIOs + k.wrIOs
					} else {
						t[0] += k.rdIOs + k.wrIOs + k.dcIOs
					}
					t[1] += k.rdIOs
					t[2] += k.wrIOs
					t[3] += k.dcIOs
					t[4] += k.rdSect
					t[5] += k.wrSect
					t[6] += k.dcSect
				}
			}
			sum(prev.disks, &pt)
			sum(cur.disks, &ct)
			r := func(i int) float64 {
				if ct[i] < pt[i] {
					return 0
				}
				return sv(pt[i], ct[i], iv)
			}
			p.ts(ts)
			if v == "11.7" {
				p.f(2, r(0), r(1), r(2), r(4), r(5))
			} else {
				p.f(2, r(0), r(1), r(2), r(3), r(4), r(5), r(6))
			}
			p.nl()
		case "disk":
			before := map[[2]int]sarDisk{}
			for _, k := range prev.disks {
				before[[2]int{k.major, k.minor}] = k
			}
			for _, c := range cur.disks {
				if c.part {
					continue
				}
				pr := before[[2]int{c.major, c.minor}]
				ios := func(k sarDisk) int64 {
					if v == "11.7" {
						return k.rdIOs + k.wrIOs
					}
					return k.rdIOs + k.wrIOs + k.dcIOs
				}
				dios := ios(c) - ios(pr)
				util := 0.0
				if c.ioTicks >= pr.ioTicks || v == "11.7" {
					util = sv(pr.ioTicks, c.ioTicks, iv)
				}
				await, arqsz := 0.0, 0.0
				if dios > 0 || v == "11.7" && dios != 0 {
					ticks := (c.rdTicks - pr.rdTicks) + (c.wrTicks - pr.wrTicks)
					sect := (c.rdSect - pr.rdSect) + (c.wrSect - pr.wrSect)
					if v != "11.7" {
						ticks += c.dcTicks - pr.dcTicks
						sect += c.dcSect - pr.dcSect
					}
					await, arqsz = float64(ticks)/float64(dios), float64(sect)/float64(dios)
				}
				name := names[[2]int{c.major, c.minor}]
				if name == "" {
					name = c.name
					if v == "11.7" && !pretty {
						name = fmt.Sprintf("dev%d-%d", c.major, c.minor)
					}
				}
				p.ts(ts)
				if !last12 {
					p.s(" %9s", name)
				}
				p.f(2, sv(ios(pr), ios(c), iv), sv(pr.rdSect, c.rdSect, iv)/2, sv(pr.wrSect, c.wrSect, iv)/2)
				if v != "11.7" {
					p.f(2, sv(pr.dcSect, c.dcSect, iv)/2)
				}
				p.f(2, arqsz/2, sv(pr.timeInQueue, c.timeInQueue, iv)/1000, await)
				if v == "11.7" {
					tput := float64(dios) * 100 / float64(iv)
					svctm := 0.0
					if tput != 0 {
						svctm = util / tput
					}
					p.f(2, svctm)
				}
				p.f(2, util/10)
				if last12 {
					p.s(" %s", name)
				}
				p.nl()
			}
		case "softnet":
			// get_global_soft_statistics: "all" is the CPUs online at both
			// records summed.
			var allP, allC [6]int64
			for c, x := range cur.cpux {
				y, ok := prev.cpux[c]
				if !x.snOK || !ok || !y.snOK {
					continue
				}
				for k := range allC {
					allC[k] += x.sn[k]
					allP[k] += y.sn[k]
				}
			}
			for i := 0; i <= ncpu; i++ {
				if !sarCPUShown(a, i) {
					continue
				}
				c, pc := allC, allP
				if i > 0 {
					x, ok := cur.cpux[i-1]
					y, ok2 := prev.cpux[i-1]
					if !ok || !ok2 || !x.snOK || !y.snOK {
						continue
					}
					c, pc = x.sn, y.sn
				}
				p.ts(ts)
				if i == 0 {
					p.s(" %s", "    all")
				} else {
					p.s(" %7d", i-1)
				}
				p.f(2, sv(pc[0], c[0], iv), sv(pc[1], c[1], iv), sv(pc[2], c[2], iv), sv(pc[3], c[3], iv), sv(pc[4], c[4], iv))
				if v != "11.7" && v != "12.5" {
					if avg {
						p.f(0, perCPU[i]/count)
					} else {
						p.u(c[5])
						perCPU[i] += float64(c[5])
					}
				}
				p.nl()
			}
		case "cpufreq":
			var sum, n int64
			for i := 0; i < ncpu; i++ {
				if x, ok := cur.cpux[i]; ok && x.mhz >= 0 {
					sum += x.mhz
					n++
				}
			}
			for i := 0; i <= ncpu; i++ {
				f := int64(0)
				if i == 0 {
					if n > 0 {
						f = sum / n
					}
				} else if x, ok := cur.cpux[i-1]; ok && x.mhz > 0 {
					f = x.mhz
				}
				if f == 0 && !avg || !sarCPUShown(a, i) {
					continue
				}
				name := "     all"
				if i > 0 {
					name = fmt.Sprintf("     %3d", i-1)
				}
				p.ts(ts)
				p.s("%s", name)
				if avg {
					p.f(2, perCPU[i]/(100*count))
				} else {
					p.f(2, float64(f)/100)
					perCPU[i] += float64(f)
				}
				p.nl()
			}
		case "psiio", "psimem":
			x, px := cur.x, prev.x
			sa, fa, st, ft, pst, pft := x.ioSomeAvg, x.ioFullAvg, x.ioSome, x.ioFull, px.ioSome, px.ioFull
			if a.Key == "psimem" {
				sa, fa, st, ft, pst, pft = x.memSomeAvg, x.memFullAvg, x.memSome, x.memFull, px.memSome, px.memFull
			}
			p.ts(ts)
			if avg {
				p.f(2, levels[0]/(count*100), levels[1]/(count*100), levels[2]/(count*100))
			} else {
				p.f(2, float64(sa[0])/100, float64(sa[1])/100, float64(sa[2])/100)
			}
			p.f(2, float64(st-pst)/(100*float64(iv)))
			if avg {
				p.f(2, levels[3]/(count*100), levels[4]/(count*100), levels[5]/(count*100))
			} else {
				p.f(2, float64(fa[0])/100, float64(fa[1])/100, float64(fa[2])/100)
				vals := []float64{float64(sa[0]), float64(sa[1]), float64(sa[2]), float64(fa[0]), float64(fa[1]), float64(fa[2])}
				if levels == nil {
					levels = make([]float64, 6)
				}
				for k := range vals {
					levels[k] += vals[k]
				}
			}
			p.f(2, float64(ft-pft)/(100*float64(iv)))
			p.nl()
		}
	}
	for i := 1; i < len(seg); i++ {
		prev, cur := &seg[i-1], &seg[i]
		if lines == 0 || lines >= 3600*24 {
			lines = 0
			p.hdr(clock(prev.ts), titles, iw)
		}
		lines += inc(cur)
		row(prev, cur, clock(cur.ts), false)
	}
	row(first, last, "Average:", true)
}

// printSarIRQ prints -I of sysstat 12.6 and later: from /proc/interrupts,
// the column "all" (and each CPU of -P), the rows "sum" (and with ALL each
// interrupt); the header at every record.
func printSarIRQ(p *sarPr, seg []sarRec, a SarAct, all bool) {
	first, last := &seg[0], &seg[len(seg)-1]
	if first.irq == nil || last.irq == nil {
		return
	}
	cols := []int{-1}
	for _, c := range last.irq.cpus {
		if sarCPUShown(a, c+1) && a.CPUs != nil {
			cols = append(cols, c)
		}
	}
	if a.CPUs != nil && !sarCPUShown(a, 0) {
		cols = cols[1:]
	}
	titles := "INTR"
	for _, c := range cols {
		if c < 0 {
			titles += ";all"
		} else {
			titles += ";CPU" + strconv.Itoa(c)
		}
	}
	// value: line (-1 the sum) and CPU (-1 all) of a record.
	value := func(q *sarIRQ, line, cpu int) int64 {
		var t int64
		for li := range q.vals {
			if line >= 0 && li != line {
				continue
			}
			for ci, n := range q.vals[li] {
				if cpu < 0 || ci < len(q.cpus) && q.cpus[ci] == cpu {
					t += n
				}
			}
		}
		return t
	}
	lineOf := func(q *sarIRQ, name string) int {
		for i, n := range q.names {
			if n == name {
				return i
			}
		}
		return -2
	}
	block := func(prev, cur *sarRec, ts, hdrTS string) {
		p.hdr(hdrTS, titles, 9)
		iv := max((cur.irq.ts-prev.irq.ts)/10, 1)
		rows := []string{"sum"}
		if all {
			rows = append(rows, cur.irq.names...)
		}
		for _, name := range rows {
			lc, lp := -1, -1
			if name != "sum" {
				lc, lp = lineOf(cur.irq, name), lineOf(prev.irq, name)
				if lp < -1 {
					continue
				}
			}
			p.ts(ts)
			p.s(" %9s", name)
			for _, c := range cols {
				a, b := value(prev.irq, lp, c), value(cur.irq, lc, c)
				if c < 0 && b < a {
					p.f(2, 0)
				} else {
					p.f(2, sv(a, b, iv))
				}
			}
			p.nl()
		}
	}
	for i := 1; i < len(seg); i++ {
		if seg[i].irq == nil || seg[i-1].irq == nil {
			continue
		}
		block(&seg[i-1], &seg[i], clock(seg[i].ts), clock(seg[i-1].ts))
	}
	block(first, last, "Average:", "Average:")
}

var _ = sql.ErrNoRows
