// vmstat's other reports and options (-a -w -t -S -s -d -D -p -m -f -n),
// following procps-ng's vmstat.c (4.0.4, 3.3.17, 3.3.15; LGPL-2.1-or-later;
// packaging/notices/procps.txt): its formats, headers and the values each
// report takes.

package query

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"clifr/internal/store"
)

// VmstatOpts are vmstat's output options.
type VmstatOpts struct {
	Active  bool   // -a: inact and active instead of buff and cache
	Wide    bool   // -w
	Times   bool   // -t: a timestamp after each line
	Unit    byte   // -S: b, B, k, K (default), m, M
	OneHead bool   // -n: one header only
	Version string // ToolStyle.Vmstat: "" 4.0.4, "3.3.17", "3.3.15"
}

// vmstatHeight is how many lines vmstat prints between headers when its
// output is not a terminal (winhi's 24 rows, less 3).
const vmstatHeight = 21

func (o VmstatOpts) v3() bool { return o.Version != "" }

// unitDiv is -S's unit in bytes.
func (o VmstatOpts) unitDiv() int64 {
	switch o.Unit {
	case 'b', 'B':
		return 1
	case 'k':
		return 1000
	case 'm':
		return 1000000
	case 'M':
		return 1048576
	}
	return 1024
}

// conv is unitConvert: kB in the -S unit, truncated.
func (o VmstatOpts) conv(kb int64) int64 {
	return int64(float64(kb) / float64(o.unitDiv()) * 1024)
}

// unitName is the unit as -s prints it ("K" by default, else -S's letter).
func (o VmstatOpts) unitName() string {
	if o.Unit == 0 {
		return "K"
	}
	return string(o.Unit)
}

// stamp is -t's column: the time of the line on the host's clock.
func stamp(ts int64) string { return time.UnixMilli(ts).Format("2006-01-02 15:04:05") }

// zoneHead is -t's second header field: the zone's abbreviation, right
// aligned under " -----timestamp-----".
func zoneHead(ts int64) string {
	z, _ := time.UnixMilli(ts).Zone()
	if len(z) > 19 {
		z = z[:19]
	}
	return fmt.Sprintf(" %19s", z)
}

// PrintVMStatOpts prints the default report as the release in o does, a
// header again every vmstatHeight lines (vmstat into a pipe) unless -n.
func PrintVMStatOpts(w io.Writer, rows []VMStatRow, o VmstatOpts) {
	head := func(ts int64) {
		h, h2 := "procs -----------memory---------- ---swap-- -----io---- -system-- -------cpu-------", ""
		f := "%2s %2s %6s %6s %6s %6s %4s %4s %5s %5s %4s %4s %2s %2s %2s %2s %2s %2s"
		switch {
		case o.Wide && !o.v3():
			h = "--procs-- -----------------------memory---------------------- ---swap-- -----io---- -system-- ----------cpu----------"
			f = "%4s %4s %12s %12s %12s %12s %4s %4s %5s %5s %4s %4s %3s %3s %3s %3s %3s %3s"
		case o.Wide && o.Version == "3.3.15":
			h = "procs -----------------------memory---------------------- ---swap-- -----io---- -system-- --------cpu--------"
			f = "%2s %2s %12s %12s %12s %12s %4s %4s %5s %5s %4s %4s %3s %3s %3s %3s %3s"
		case o.Wide:
			h = "--procs-- -----------------------memory---------------------- ---swap-- -----io---- -system-- --------cpu--------"
			f = "%4s %4s %12s %12s %12s %12s %4s %4s %5s %5s %4s %4s %3s %3s %3s %3s %3s"
		case o.v3():
			h = "procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----"
			f = "%2s %2s %6s %6s %6s %6s %4s %4s %5s %5s %4s %4s %2s %2s %2s %2s %2s"
		}
		b3, b4 := "buff", "cache"
		if o.Active {
			b3, b4 = "inact", "active"
		}
		names := []any{"r", "b", "swpd", "free", b3, b4, "si", "so", "bi", "bo", "in", "cs", "us", "sy", "id", "wa", "st", "gu"}
		if o.v3() {
			names = names[:17]
		}
		h2 = fmt.Sprintf(f, names...)
		if o.Times {
			h += " -----timestamp-----"
			h2 += zoneHead(ts)
		}
		fmt.Fprintln(w, h)
		fmt.Fprintln(w, h2)
	}
	f := "%2d %2d %6d %6d %6d %6d %4d %4d %5d %5d %4d %4d %2d %2d %2d %2d %2d"
	switch {
	case o.Wide && o.Version == "3.3.15":
		f = "%2d %2d %12d %12d %12d %12d %4d %4d %5d %5d %4d %4d %3d %3d %3d %3d %3d"
	case o.Wide:
		f = "%4d %4d %12d %12d %12d %12d %4d %4d %5d %5d %4d %4d %3d %3d %3d %3d %3d"
	}
	if !o.v3() {
		f += map[bool]string{false: " %2d", true: " %3d"}[o.Wide]
	}
	for i, r := range rows {
		if i == 0 || !o.OneHead && i%vmstatHeight == 0 {
			head(r.TS)
		}
		b3, b4 := r.Buff, r.Cache
		if o.Active {
			b3, b4 = r.Inact, r.ActiveKB
		}
		vals := []any{r.R, r.B, o.conv(r.Swpd), o.conv(r.Free), o.conv(b3), o.conv(b4),
			o.conv(r.SI), o.conv(r.SO), r.BI, r.BO, r.In, r.CS, r.US, r.SY, r.ID, r.WA, r.ST}
		if !o.v3() {
			vals = append(vals, r.GU)
		}
		fmt.Fprintf(w, f, vals...)
		if o.Times {
			fmt.Fprint(w, " "+stamp(r.TS))
		}
		fmt.Fprintln(w)
	}
}

// ---- vmstat -s ----

// VMStatSum is what vmstat -s prints: the counters at the sample (memory in
// kB, CPU in ticks, paging in kB (pages for swapping), boot time in Unix
// seconds).
type VMStatSum struct {
	TS                                                    int64 `json:"ts_ms"`
	MemTotal, MemUsed, Active, Inactive, MemFree, Buffers int64
	SwapCache, SwapTotal, SwapUsed, SwapFree              int64
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ        int64
	Steal, Guest, GuestNice                               int64
	PagedIn, PagedOut, SwappedIn, SwappedOut              int64
	Interrupts, CtxSwitches, BootTime, Forks              int64
}

// VMStatSumAt reads -s's values at the sample at or before t.
func VMStatSumAt(db *store.DB, t int64) (VMStatSum, error) {
	sp := Span{To: t}
	free, err := Free(db, []Span{sp})
	if err != nil {
		return VMStatSum{}, err
	}
	s, err := loadSys(db, t)
	if err != nil {
		return VMStatSum{}, err
	}
	cpus, err := loadCPUs(db, s.TS)
	if err != nil {
		return VMStatSum{}, err
	}
	c := cpus[-1]
	f := free[0]
	return VMStatSum{TS: s.TS, MemTotal: f.Total, MemUsed: f.Used, Active: s.Active, Inactive: s.Inactive, MemFree: s.MemFree,
		Buffers: s.Buffers, SwapCache: f.Cache, SwapTotal: s.SwapTotal, SwapUsed: s.SwapTotal - s.SwapFree, SwapFree: s.SwapFree,
		User: c[cUser], Nice: c[cNice], System: c[cSystem], Idle: c[cIdle], IOWait: c[cIOWait], IRQ: c[cIRQ], SoftIRQ: c[cSoftIRQ],
		Steal: c[cSteal], Guest: c[cGuest], GuestNice: c[cGuestNice], PagedIn: s.PgpgIn, PagedOut: s.PgpgOut,
		SwappedIn: s.PswpIn, SwappedOut: s.PswpOut, Interrupts: s.Intr, CtxSwitches: s.Ctxt, BootTime: BTimeAt(db, t),
		Forks: s.Forks}, nil
}

// PrintVMStatSum prints sum_format.
func PrintVMStatSum(w io.Writer, s VMStatSum, o VmstatOpts) {
	u := o.unitName()
	for _, l := range []struct {
		v    int64
		text string
	}{{o.conv(s.MemTotal), u + " total memory"}, {o.conv(s.MemUsed), u + " used memory"}, {o.conv(s.Active), u + " active memory"},
		{o.conv(s.Inactive), u + " inactive memory"}, {o.conv(s.MemFree), u + " free memory"}, {o.conv(s.Buffers), u + " buffer memory"},
		{o.conv(s.SwapCache), u + " swap cache"}, {o.conv(s.SwapTotal), u + " total swap"}, {o.conv(s.SwapUsed), u + " used swap"},
		{o.conv(s.SwapFree), u + " free swap"}, {s.User, "non-nice user cpu ticks"}, {s.Nice, "nice user cpu ticks"},
		{s.System, "system cpu ticks"}, {s.Idle, "idle cpu ticks"}, {s.IOWait, "IO-wait cpu ticks"}, {s.IRQ, "IRQ cpu ticks"},
		{s.SoftIRQ, "softirq cpu ticks"}, {s.Steal, "stolen cpu ticks"}} {
		fmt.Fprintf(w, "%13d %s\n", l.v, l.text)
	}
	paged := "K paged"
	if o.v3() {
		paged = "pages paged"
	} else {
		fmt.Fprintf(w, "%13d non-nice guest cpu ticks\n%13d nice guest cpu ticks\n", s.Guest, s.GuestNice)
	}
	fmt.Fprintf(w, "%13d %s in\n%13d %s out\n", s.PagedIn, paged, s.PagedOut, paged)
	fmt.Fprintf(w, "%13d pages swapped in\n%13d pages swapped out\n", s.SwappedIn, s.SwappedOut)
	fmt.Fprintf(w, "%13d interrupts\n%13d CPU context switches\n%13d boot time\n%13d forks\n",
		s.Interrupts, s.CtxSwitches, s.BootTime, s.Forks)
}

// PrintVMStatForks prints -f.
func PrintVMStatForks(w io.Writer, s VMStatSum) { fmt.Fprintf(w, "%13d forks\n", s.Forks) }

// ---- vmstat -d, -D, -p ----

// VMStatDisk is one device's /proc/diskstats counters since boot, as
// vmstat -d prints them (IO cur and sec divided by 1000, as vmstat does).
type VMStatDisk struct {
	Name         string `json:"name"`
	Reads        int64  `json:"reads"`
	ReadsMerged  int64  `json:"reads_merged"`
	ReadSectors  int64  `json:"read_sectors"`
	ReadMS       int64  `json:"read_ms"`
	Writes       int64  `json:"writes"`
	WritesMerged int64  `json:"writes_merged"`
	WriteSectors int64  `json:"write_sectors"`
	WriteMS      int64  `json:"write_ms"`
	InFlight     int64  `json:"in_flight"`
	IOMS         int64  `json:"io_ms"`
	WeightedMS   int64  `json:"weighted_ms"`
	part         bool
}

// VMStatDisks is the devices of one sample, in /proc/diskstats' order
// (disk_samples.pos; by name before schema 14).
type VMStatDisks struct {
	TS    int64        `json:"ts_ms"`
	Disks []VMStatDisk `json:"disks"`
}

// VMStatDisksAt reads the devices of the sample at or before t: the disks
// (parts false) or every device. Devices that did no I/O since boot are not
// in disk_samples: they come from the block devices (sysfs) with zeros.
func VMStatDisksAt(db *store.DB, t int64, parts bool) (VMStatDisks, error) {
	s, err := loadSys(db, t)
	if err != nil {
		return VMStatDisks{}, err
	}
	out := VMStatDisks{TS: s.TS}
	q := `SELECT name, part, major, minor, ` + strings.Join(store.DiskCols, ", ") + ` FROM disk_samples WHERE ts = ?`
	if !parts {
		q += ` AND part = 0`
	}
	rows, err := db.Query(q+` ORDER BY pos NULLS LAST, name`, s.TS)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	var devs []uint64 // each listed device's number
	for rows.Next() {
		var d VMStatDisk
		var v diskVals
		var maj, min int
		dst := []any{&d.Name, &d.part, &maj, &min}
		for i := range v {
			dst = append(dst, &v[i])
		}
		if err := rows.Scan(dst...); err != nil {
			return out, err
		}
		d.Reads, d.ReadsMerged, d.ReadSectors, d.ReadMS = v[0], v[1], v[2], v[3]
		d.Writes, d.WritesMerged, d.WriteSectors, d.WriteMS = v[4], v[5], v[6], v[7]
		d.InFlight, d.IOMS, d.WeightedMS = v[12], v[13], v[14]
		out.Disks = append(out.Disks, d)
		devs = append(devs, makedev(maj, min))
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	rows.Close()
	addIdleDisks(db, t, parts, &out, devs)
	return out, nil
}

// addIdleDisks adds the block devices that did no I/O since boot (not in
// disk_samples, listed by vmstat with zeros) from the sysfs table, each after
// the last listed device with a lower device number: /proc/diskstats keeps a
// driver's devices together in number order (loop0..7 before vda).
func addIdleDisks(db *store.DB, t int64, parts bool, out *VMStatDisks, devs []uint64) {
	bd, err := blockDevsAt(db, t)
	if err != nil || len(bd) == 0 {
		return
	}
	have := map[string]bool{}
	for _, d := range out.Disks {
		have[d.Name] = true
	}
	type idle struct {
		d   VMStatDisk
		num uint64
	}
	var add []idle
	for n, b := range bd {
		if have[n] || (b.Parent != "" && !parts) {
			continue
		}
		add = append(add, idle{VMStatDisk{Name: n, part: b.Parent != ""}, makedev(b.Maj, b.Min)})
	}
	sort.Slice(add, func(i, j int) bool { return add[i].num < add[j].num })
	for _, a := range add {
		at := 0
		for i, num := range devs {
			if num < a.num {
				at = i + 1
			}
		}
		out.Disks = append(out.Disks[:at], append([]VMStatDisk{a.d}, out.Disks[at:]...)...)
		devs = append(devs[:at], append([]uint64{a.num}, devs[at:]...)...)
	}
}

// PrintVMStatDisks prints -d's reports (each with every device, VMStatDisksAt
// with parts: the partitions are counted, not printed), a header at each
// multiple of vmstatHeight devices of a report that is a disk (4.0.4), or
// every vmstatHeight disks over all reports (3.3); with -n one header.
func PrintVMStatDisks(w io.Writer, reps []VMStatDisks, o VmstatOpts) {
	head := func(ts int64) {
		h := "disk- ------------reads------------ ------------writes----------- -----IO------"
		f := "%5s %6s %6s %7s %7s %6s %6s %7s %7s %6s %6s"
		if o.Wide {
			h = "disk- -------------------reads------------------- -------------------writes------------------ ------IO-------"
			f = "%5s %9s %9s %11s %11s %9s %9s %11s %11s %7s %7s"
		}
		h2 := fmt.Sprintf(f, " ", "total", "merged", "sectors", "ms", "total", "merged", "sectors", "ms", "cur", "sec")
		if o.Times {
			h += " -----timestamp-----"
			h2 += zoneHead(ts)
		}
		fmt.Fprintln(w, h)
		fmt.Fprintln(w, h2)
	}
	f := "%-5s %6d %6d %7d %7d %6d %6d %7d %7d %6d %6d"
	if o.Wide {
		f = "%-5s %9d %9d %11d %11d %9d %9d %11d %11d %7d %7d"
	}
	k := 0
	for ri, rep := range reps {
		if o.OneHead && ri == 0 {
			head(rep.TS)
		}
		for j, d := range rep.Disks {
			// 4.0.4 counts every device of /proc/diskstats (partitions too,
			// not printed), 3.3 the disks printed over all reports.
			if d.part {
				continue
			}
			n := j
			if o.v3() {
				n = k
			}
			if !o.OneHead && n%vmstatHeight == 0 {
				head(rep.TS)
			}
			k++
			fmt.Fprintf(w, f, d.Name, d.Reads, d.ReadsMerged, d.ReadSectors, d.ReadMS, d.Writes, d.WritesMerged,
				d.WriteSectors, d.WriteMS, d.InFlight/1000, d.IOMS/1000)
			if o.Times {
				fmt.Fprint(w, " "+stamp(rep.TS))
			}
			fmt.Fprintln(w)
		}
	}
}

// VMStatDiskSum is vmstat -D: the number of disks and partitions (sysfs
// block devices) and the disks' counters summed.
type VMStatDiskSum struct {
	TS         int64 `json:"ts_ms"`
	Disks      int   `json:"disks"`
	Partitions int   `json:"partitions"`
	VMStatDisk
}

// VMStatDiskSumAt adds up the disks of the sample at or before t; the counts
// are the block devices recorded then (blockdevs), else the disks listed.
func VMStatDiskSumAt(db *store.DB, t int64) (VMStatDiskSum, error) {
	d, err := VMStatDisksAt(db, t, false)
	if err != nil {
		return VMStatDiskSum{}, err
	}
	out := VMStatDiskSum{TS: d.TS, Disks: len(d.Disks)}
	if devs, err := blockDevsAt(db, t); err == nil && len(devs) > 0 {
		out.Disks = 0
		for _, b := range devs {
			if b.Parent == "" {
				out.Disks++
			} else {
				out.Partitions++
			}
		}
	}
	for _, x := range d.Disks {
		s := &out.VMStatDisk
		s.Reads += x.Reads
		s.ReadsMerged += x.ReadsMerged
		s.ReadSectors += x.ReadSectors
		s.ReadMS += x.ReadMS
		s.Writes += x.Writes
		s.WritesMerged += x.WritesMerged
		s.WriteSectors += x.WriteSectors
		s.WriteMS += x.WriteMS
		s.InFlight += x.InFlight / 1000
		s.IOMS += x.IOMS / 1000
		s.WeightedMS += x.WeightedMS / 1000
	}
	return out, nil
}

// PrintVMStatDiskSum prints disksum_format (3.3: a space after the counts'
// words, no weighted line).
func PrintVMStatDiskSum(w io.Writer, s VMStatDiskSum, o VmstatOpts) {
	sp := ""
	if o.v3() {
		sp = " "
	}
	fmt.Fprintf(w, "%13d disks%s\n%13d partitions%s\n", s.Disks, sp, s.Partitions, sp)
	for _, l := range []struct {
		v    int64
		text string
	}{{s.Reads, "total reads"}, {s.ReadsMerged, "merged reads"}, {s.ReadSectors, "read sectors"}, {s.ReadMS, "milli reading"},
		{s.Writes, "writes"}, {s.WritesMerged, "merged writes"}, {s.WriteSectors, "written sectors"}, {s.WriteMS, "milli writing"},
		{s.InFlight, "inprogress IO"}, {s.IOMS, "milli spent IO"}} {
		fmt.Fprintf(w, "%13d %s\n", l.v, l.text)
	}
	if !o.v3() {
		fmt.Fprintf(w, "%13d milli weighted IO\n", s.WeightedMS)
	}
}

// VMStatPart is one -p line: a device's reads, read sectors, writes and
// written sectors since boot at a sample.
type VMStatPart struct {
	TS           int64 `json:"ts_ms"`
	Reads        int64 `json:"reads"`
	ReadSectors  int64 `json:"read_sectors"`
	Writes       int64 `json:"writes"`
	WriteSectors int64 `json:"write_sectors"`
}

// VMStatPartAt reads device name at the sample at or before t; ok false when
// the device is not in the recording then (neither its counters nor sysfs).
func VMStatPartAt(db *store.DB, t int64, name string) (VMStatPart, bool, error) {
	d, err := VMStatDisksAt(db, t, true)
	if err != nil {
		return VMStatPart{}, false, err
	}
	for _, x := range d.Disks {
		if x.Name == name {
			return VMStatPart{TS: d.TS, Reads: x.Reads, ReadSectors: x.ReadSectors, Writes: x.Writes, WriteSectors: x.WriteSectors}, true, nil
		}
	}
	if devs, err := blockDevsAt(db, t); err == nil {
		if _, ok := devs[name]; ok { // no I/O since boot: not in disk_samples
			return VMStatPart{TS: d.TS}, true, nil
		}
	}
	return VMStatPart{TS: d.TS}, false, nil
}

// PrintVMStatParts prints -p: one header, then a line per report.
func PrintVMStatParts(w io.Writer, name string, parts []VMStatPart) {
	fmt.Fprintf(w, "%-10s %10s  %16s  %10s  %16s\n", name, "reads", "read sectors", "writes", "requested writes")
	for _, p := range parts {
		fmt.Fprintf(w, "%21d  %16d  %10d  %16d\n", p.Reads, p.ReadSectors, p.Writes, p.WriteSectors)
	}
}

// ---- vmstat -m ----

// VMStatSlabs is one -m report: the slab caches as clifrd last read
// /proc/slabinfo (every minute), sorted by name (4.0.4) or in the file's
// order (3.3).
type VMStatSlabs struct {
	TS    int64  `json:"ts_ms"`
	Slabs []Slab `json:"slabs"`
}

// PrintVMStatSlabs prints slabformat's reports.
func PrintVMStatSlabs(w io.Writer, reps []VMStatSlabs, o VmstatOpts) {
	head := func() { fmt.Fprintf(w, "%-24s %6s %6s %6s %6s\n", "Cache", "Num", "Total", "Size", "Pages") }
	if o.OneHead {
		head()
	}
	k := 0
	for ri, rep := range reps {
		if ri == 1 { // 3.3's loop counts from 1 again after the first report
			k = 1
		}
		slabs := rep.Slabs
		if !o.v3() {
			slabs = append([]Slab(nil), slabs...)
			sortSlabsByName(slabs)
		}
		for j, s := range slabs {
			n := j
			if o.v3() {
				n = k
			}
			if !o.OneHead && n%vmstatHeight == 0 {
				head()
			}
			k++
			name := s.Name
			if !o.v3() && len(name) > 24 { // %-24.24s
				name = name[:24]
			}
			fmt.Fprintf(w, "%-24s %6d %6d %6d %6d\n", name, s.ActiveObjs, s.Objs, s.ObjSize, s.ObjsPerSlab)
		}
	}
}

func sortSlabsByName(s []Slab) {
	sort.SliceStable(s, func(i, j int) bool { return s[i].Name < s[j].Name })
}
