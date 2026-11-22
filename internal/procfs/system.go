package procfs

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Pressure is one /proc/pressure file (PSI): the total time, in µs, that
// some or all ("full") non-idle tasks were stalled on the resource.
type Pressure struct {
	Some, Full uint64
	HasFull    bool // the file has a full line (cpu has one since Linux 5.13)
	// SomeAvg: the some line's avg10, avg60 and avg300 in hundredths of a
	// percent (the file's two decimals); FullAvg the full line's (sar -q).
	SomeAvg, FullAvg [3]int64
}

// ReadPressure reads /proc/pressure/<resource> (cpu, memory, io, irq). An
// error wrapping fs.ErrNotExist means no PSI (CONFIG_PSI off, psi=0, or no
// such resource on this kernel).
func (f FS) ReadPressure(resource string) (Pressure, error) {
	b, err := os.ReadFile(f.path("pressure", resource))
	if err != nil {
		return Pressure{}, err
	}
	var p Pressure
	for len(b) > 0 {
		line := b
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			b = nil
		}
		kind, rest, _ := bytes.Cut(line, []byte(" "))
		_, total, ok := bytes.Cut(rest, []byte("total="))
		if !ok {
			continue
		}
		v, err := strconv.ParseUint(string(bytes.TrimSpace(total)), 10, 64)
		if err != nil {
			return Pressure{}, fmt.Errorf("pressure/%s: %q: %w", resource, line, err)
		}
		avgs := func(dst *[3]int64) {
			for i, k := range []string{"avg10=", "avg60=", "avg300="} {
				if _, a, ok := bytes.Cut(rest, []byte(k)); ok {
					if j := bytes.IndexByte(a, ' '); j >= 0 {
						a = a[:j]
					}
					w, f, _ := bytes.Cut(a, []byte("."))
					n, _ := strconv.ParseInt(string(w), 10, 64)
					d, _ := strconv.ParseInt(string(f), 10, 64)
					dst[i] = n*100 + d
				}
			}
		}
		switch string(kind) {
		case "some":
			p.Some = v
			avgs(&p.SomeAvg)
		case "full":
			p.Full, p.HasFull = v, true
			avgs(&p.FullAvg)
		}
	}
	return p, nil
}

// The system-wide counters behind uptime, vmstat, mpstat and iostat. All of
// them are the kernel's raw values: cumulative since boot unless noted.

// CPUTimes is one "cpu" line of /proc/stat, in clock ticks.
type CPUTimes struct {
	CPU int // -1 for the total over all CPUs
	// user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
	T [10]uint64
}

// SysStat is the part of /proc/stat that is not per process.
type SysStat struct {
	CPUs         []CPUTimes // the total first, then the online CPUs
	Intr         uint64     // interrupts serviced
	Ctxt         uint64     // context switches
	Forks        uint64     // processes and threads created
	ProcsRunning int        // now
	ProcsBlocked int        // now
	SoftIRQ      uint64
}

// fields splits a line at spaces without allocating strings.
func fields(line []byte, dst [][]byte) [][]byte {
	dst = dst[:0]
	for len(line) > 0 {
		for len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			line = line[1:]
		}
		i := bytes.IndexAny(line, " \t")
		if i < 0 {
			i = len(line)
		}
		if i > 0 {
			dst = append(dst, line[:i])
		}
		line = line[i:]
	}
	return dst
}

func u64(b []byte) uint64 {
	var n uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

// lines calls fn for every line of b.
func lines(b []byte, fn func(line []byte)) {
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			i = len(b)
		}
		fn(b[:i])
		if i == len(b) {
			break
		}
		b = b[i+1:]
	}
}

// ReadSysStat parses /proc/stat.
func (f FS) ReadSysStat() (SysStat, error) {
	b, err := os.ReadFile(f.path("stat"))
	if err != nil {
		return SysStat{}, err
	}
	var s SysStat
	var fs [][]byte
	lines(b, func(line []byte) {
		// Only the first value of the long intr and softirq lines is used.
		head := line
		if len(head) > 64 && !bytes.HasPrefix(head, []byte("cpu")) {
			head = head[:64]
		}
		fs = fields(head, fs)
		if len(fs) < 2 {
			return
		}
		key := string(fs[0])
		switch {
		case len(key) >= 3 && key[:3] == "cpu":
			c := CPUTimes{CPU: -1}
			if len(key) > 3 {
				n, err := strconv.Atoi(key[3:])
				if err != nil {
					return
				}
				c.CPU = n
			}
			for i := 0; i < len(c.T) && i+1 < len(fs); i++ {
				c.T[i] = u64(fs[i+1])
			}
			s.CPUs = append(s.CPUs, c)
		case key == "intr":
			s.Intr = u64(fs[1])
		case key == "ctxt":
			s.Ctxt = u64(fs[1])
		case key == "processes":
			s.Forks = u64(fs[1])
		case key == "procs_running":
			s.ProcsRunning = int(u64(fs[1]))
		case key == "procs_blocked":
			s.ProcsBlocked = int(u64(fs[1]))
		case key == "softirq":
			s.SoftIRQ = u64(fs[1])
		}
	})
	if len(s.CPUs) == 0 {
		return s, errShort
	}
	return s, nil
}

// LoadAvg is /proc/loadavg; the averages are in hundredths.
type LoadAvg struct {
	Load1, Load5, Load15 int
	Runnable, Threads    int // scheduling entities: runnable now, existing
}

// hundredths parses "1.49" as 149.
func hundredths(b []byte) int {
	whole, frac, _ := bytes.Cut(b, []byte("."))
	n := int(u64(whole)) * 100
	if len(frac) >= 2 {
		n += int(u64(frac[:2]))
	} else if len(frac) == 1 {
		n += int(u64(frac)) * 10
	}
	return n
}

func (f FS) ReadLoadAvg() (LoadAvg, error) {
	b, err := os.ReadFile(f.path("loadavg"))
	if err != nil {
		return LoadAvg{}, err
	}
	fs := fields(bytes.TrimSpace(b), nil)
	if len(fs) < 4 {
		return LoadAvg{}, errShort
	}
	l := LoadAvg{Load1: hundredths(fs[0]), Load5: hundredths(fs[1]), Load15: hundredths(fs[2])}
	run, all, _ := bytes.Cut(fs[3], []byte("/"))
	l.Runnable, l.Threads = int(u64(run)), int(u64(all))
	return l, nil
}

// MemInfo is the part of /proc/meminfo that free and vmstat show, in kB.
type MemInfo struct {
	Total, Free, Available, Buffers, Cached, SwapCached uint64
	Active, Inactive, SwapTotal, SwapFree               uint64
	Dirty, Writeback, Shmem, Slab, SReclaimable         uint64
	// atop's (schema 12): committed memory and its limit, page tables, huge
	// pages (counts; Hugepagesize in kB), transparent huge pages, zswap.
	CommittedAS, CommitLimit, PageTables        uint64
	HugePagesTotal, HugePagesFree, Hugepagesize uint64
	AnonHugePages, Zswap, Zswapped              uint64
	// sar's (schema 14): sar -r ALL's anonymous pages, kernel stacks and
	// vmalloc use; sar -H's reserved and surplus huge pages (counts).
	AnonPages, KernelStack, VmallocUsed uint64
	HugePagesRsvd, HugePagesSurp        uint64
}

func (f FS) ReadMemInfo() (MemInfo, error) {
	b, err := os.ReadFile(f.path("meminfo"))
	if err != nil {
		return MemInfo{}, err
	}
	var m MemInfo
	dst := map[string]*uint64{
		"MemTotal:": &m.Total, "MemFree:": &m.Free, "MemAvailable:": &m.Available, "Buffers:": &m.Buffers,
		"Cached:": &m.Cached, "SwapCached:": &m.SwapCached, "Active:": &m.Active, "Inactive:": &m.Inactive,
		"SwapTotal:": &m.SwapTotal, "SwapFree:": &m.SwapFree, "Dirty:": &m.Dirty, "Writeback:": &m.Writeback,
		"Shmem:": &m.Shmem, "Slab:": &m.Slab, "SReclaimable:": &m.SReclaimable,
		"Committed_AS:": &m.CommittedAS, "CommitLimit:": &m.CommitLimit, "PageTables:": &m.PageTables,
		"HugePages_Total:": &m.HugePagesTotal, "HugePages_Free:": &m.HugePagesFree, "Hugepagesize:": &m.Hugepagesize,
		"AnonHugePages:": &m.AnonHugePages, "Zswap:": &m.Zswap, "Zswapped:": &m.Zswapped,
		"AnonPages:": &m.AnonPages, "KernelStack:": &m.KernelStack, "VmallocUsed:": &m.VmallocUsed,
		"HugePages_Rsvd:": &m.HugePagesRsvd, "HugePages_Surp:": &m.HugePagesSurp,
	}
	var fs [][]byte
	found := 0
	lines(b, func(line []byte) {
		fs = fields(line, fs)
		if len(fs) < 2 {
			return
		}
		if p := dst[string(fs[0])]; p != nil {
			*p = u64(fs[1])
			found++
		}
	})
	if found == 0 {
		return m, errShort
	}
	return m, nil
}

// VMStat is the paging part of /proc/vmstat: pages swapped in and out, and
// kB read from and written to block devices (pgpgin, pgpgout).
type VMStat struct {
	PgpgIn, PgpgOut, PswpIn, PswpOut, PgFault, PgMajFault uint64
	// atop's (schema 12): pages scanned and reclaimed by kswapd, by direct
	// reclaim, by khugepaged and by proactive reclaim (6.x); direct reclaim stalls (allocstall, summed over
	// its per-zone lines), compaction stalls, page migration, OOM kills, zswap.
	// Kernels before 4.8 count scans and steals per zone (pgscan_kswapd_normal):
	// those lines are summed into the same counters.
	// pgscan_anon/file and pgsteal_anon/file split the same pages by type.
	PgscanKswapd, PgscanDirect, PgscanKhugepaged, PgscanProactive     uint64
	PgstealKswapd, PgstealDirect, PgstealKhugepaged, PgstealProactive uint64
	AllocStall, CompactStall, PgmigrateSuccess                        uint64
	NumaPagesMigrated, OOMKill, ZswpIn, ZswpOut                       uint64
	// PgscanDirectThrottle: direct reclaim throttled (not a scan count; atop
	// adds it to its scans: its prefix match takes it).
	PgscanDirectThrottle uint64
	// sar -B's (schema 14): pages freed, the anon and file split of the
	// steals (sar adds every pgsteal_ line), promotions and demotions (every
	// pgdemote_ line summed).
	PgFree, PgstealAnon, PgstealFile, PgPromoteSuccess, PgDemote uint64
}

func (f FS) ReadVMStat() (VMStat, error) {
	b, err := os.ReadFile(f.path("vmstat"))
	if err != nil {
		return VMStat{}, err
	}
	var v VMStat
	dst := map[string]*uint64{"pgpgin": &v.PgpgIn, "pgpgout": &v.PgpgOut, "pswpin": &v.PswpIn,
		"pswpout": &v.PswpOut, "pgfault": &v.PgFault, "pgmajfault": &v.PgMajFault,
		"compact_stall": &v.CompactStall, "pgmigrate_success": &v.PgmigrateSuccess,
		"numa_pages_migrated": &v.NumaPagesMigrated, "oom_kill": &v.OOMKill, "zswpin": &v.ZswpIn, "zswpout": &v.ZswpOut,
		"pgscan_direct_throttle": &v.PgscanDirectThrottle, "pgfree": &v.PgFree, "pgsteal_anon": &v.PgstealAnon,
		"pgsteal_file": &v.PgstealFile, "pgpromote_success": &v.PgPromoteSuccess}
	// Summed: the name alone or with a zone suffix.
	sums := []struct {
		prefix string
		p      *uint64
	}{{"pgscan_kswapd", &v.PgscanKswapd}, {"pgscan_direct", &v.PgscanDirect}, {"pgscan_khugepaged", &v.PgscanKhugepaged},
		{"pgscan_proactive", &v.PgscanProactive}, {"pgsteal_proactive", &v.PgstealProactive},
		{"pgsteal_kswapd", &v.PgstealKswapd}, {"pgsteal_direct", &v.PgstealDirect}, {"pgsteal_khugepaged", &v.PgstealKhugepaged},
		{"allocstall", &v.AllocStall}, {"pgdemote", &v.PgDemote}}
	var fs [][]byte
	found := 0
	lines(b, func(line []byte) {
		fs = fields(line, fs)
		if len(fs) < 2 {
			return
		}
		name := string(fs[0])
		if p := dst[name]; p != nil {
			*p = u64(fs[1])
			found++
			return
		}
		for _, s := range sums {
			// pgscan_direct_throttle is not a scan count.
			if name == s.prefix || strings.HasPrefix(name, s.prefix+"_") && name != "pgscan_direct_throttle" {
				*s.p += u64(fs[1])
				return
			}
		}
	})
	if found == 0 {
		return v, errShort
	}
	return v, nil
}

// DiskStat is one line of /proc/diskstats. Sectors are 512 bytes, times ms.
type DiskStat struct {
	Pos          int // the line's position (sar -d lists devices in this order)
	Major, Minor int
	Name         string
	// reads, writes, discards: completed, merged, sectors, ms spent
	Rd, Wr, Dc  [4]uint64
	InFlight    uint64 // now
	IOTicks     uint64 // ms with I/O in progress
	TimeInQueue uint64 // weighted ms
	FlIOs       uint64 // flush requests
	FlTicks     uint64
}

// Used reports whether the device has ever done I/O: iostat hides the others.
func (d *DiskStat) Used() bool { return d.Rd[0]+d.Wr[0]+d.Dc[0]+d.FlIOs > 0 }

func (f FS) ReadDiskStats() ([]DiskStat, error) {
	b, err := os.ReadFile(f.path("diskstats"))
	if err != nil {
		return nil, err
	}
	var out []DiskStat
	var fs [][]byte
	lines(b, func(line []byte) {
		fs = fields(line, fs)
		if len(fs) < 14 {
			return
		}
		d := DiskStat{Pos: len(out), Major: int(u64(fs[0])), Minor: int(u64(fs[1])), Name: string(fs[2])}
		v := func(i int) uint64 {
			if i < len(fs) {
				return u64(fs[i])
			}
			return 0
		}
		for i := 0; i < 4; i++ {
			d.Rd[i], d.Wr[i], d.Dc[i] = v(3+i), v(7+i), v(14+i)
		}
		d.InFlight, d.IOTicks, d.TimeInQueue = v(11), v(12), v(13)
		d.FlIOs, d.FlTicks = v(18), v(19)
		out = append(out, d)
	})
	return out, nil
}

// SockStat is /proc/net/sockstat and sockstat6: socket counts by protocol
// (what ss -s prints). Mem values are in pages. Without IPv6 the 6 fields
// stay 0.
type SockStat struct {
	Used                                         uint64 // sockets of every family
	TCPInUse, TCPOrphan, TCPTW, TCPAlloc, TCPMem uint64
	UDPInUse, UDPMem, UDPLiteInUse, RawInUse     uint64
	FragInUse, FragMemory                        uint64
	TCP6InUse, UDP6InUse, UDPLite6InUse          uint64
	Raw6InUse, Frag6InUse, Frag6Memory           uint64
}

func (f FS) ReadSockStat() (SockStat, error) { return f.readSockStat("net") }

// ReadSockStatPID is /proc/<pid>/net/sockstat and sockstat6: the counters of
// the process's network namespace (no table walk: a few µs).
func (f FS) ReadSockStatPID(pid int) (SockStat, error) {
	return f.readSockStat(strconv.Itoa(pid) + "/net")
}

func (f FS) readSockStat(dir string) (SockStat, error) {
	var s SockStat
	vals := map[string]*uint64{
		"sockets used": &s.Used, "TCP inuse": &s.TCPInUse, "TCP orphan": &s.TCPOrphan, "TCP tw": &s.TCPTW,
		"TCP alloc": &s.TCPAlloc, "TCP mem": &s.TCPMem, "UDP inuse": &s.UDPInUse, "UDP mem": &s.UDPMem,
		"UDPLITE inuse": &s.UDPLiteInUse, "RAW inuse": &s.RawInUse, "FRAG inuse": &s.FragInUse, "FRAG memory": &s.FragMemory,
		"TCP6 inuse": &s.TCP6InUse, "UDP6 inuse": &s.UDP6InUse, "UDPLITE6 inuse": &s.UDPLite6InUse,
		"RAW6 inuse": &s.Raw6InUse, "FRAG6 inuse": &s.Frag6InUse, "FRAG6 memory": &s.Frag6Memory,
	}
	// "TCP: inuse 41 orphan 0 tw 2 alloc 46 mem 1015": name value pairs.
	parse := func(b []byte) {
		for _, line := range bytes.Split(b, []byte("\n")) {
			key, rest, ok := bytes.Cut(line, []byte(":"))
			if !ok {
				continue
			}
			fs := fields(rest, nil)
			for i := 0; i+1 < len(fs); i += 2 {
				if p := vals[string(key)+" "+string(fs[i])]; p != nil {
					*p = u64(fs[i+1])
				}
			}
		}
	}
	b, err := os.ReadFile(f.path(dir + "/sockstat"))
	if err != nil {
		return s, err
	}
	parse(b)
	if b, err := os.ReadFile(f.path(dir + "/sockstat6")); err == nil {
		parse(b)
	}
	return s, nil
}

// NetCounter is one protocol counter of /proc/net/snmp, netstat or snmp6,
// named as nstat names them ("IpInReceives", "TcpExtListenDrops",
// "Ip6InReceives"), with its section in snmp and netstat ("Ip", "TcpExt";
// "" in snmp6, which has none).
type NetCounter struct {
	Section string
	Name    string
	Value   int64
}

// ReadNetCounters reads every counter of /proc/net/snmp and netstat (a
// header line of names and a line of values per protocol) and snmp6 (a name
// and a value per line), in file order. A missing file is left out.
func (f FS) ReadNetCounters() ([]NetCounter, error) {
	var out []NetCounter
	pairs := func(b []byte) {
		lines := bytes.Split(b, []byte("\n"))
		for i := 0; i+1 < len(lines); i += 2 {
			hk, hv, ok1 := bytes.Cut(lines[i], []byte(":"))
			vk, vv, ok2 := bytes.Cut(lines[i+1], []byte(":"))
			if !ok1 || !ok2 || !bytes.Equal(hk, vk) {
				continue
			}
			names, vals := fields(hv, nil), fields(vv, nil)
			for j := 0; j < len(names) && j < len(vals); j++ {
				v, _ := strconv.ParseInt(string(vals[j]), 10, 64)
				out = append(out, NetCounter{Section: string(hk), Name: string(hk) + string(names[j]), Value: v})
			}
		}
	}
	b, err := os.ReadFile(f.path("net/snmp"))
	if err != nil {
		return nil, err
	}
	pairs(b)
	if b, err := os.ReadFile(f.path("net/netstat")); err == nil {
		pairs(b)
	}
	if b, err := os.ReadFile(f.path("net/snmp6")); err == nil {
		for _, l := range bytes.Split(b, []byte("\n")) {
			if fs := fields(l, nil); len(fs) == 2 {
				v, _ := strconv.ParseInt(string(fs[1]), 10, 64)
				out = append(out, NetCounter{Name: string(fs[0]), Value: v})
			}
		}
	}
	return out, nil
}

// Softnet is one CPU's line of /proc/net/softnet_stat (sar -n SOFT): packets
// processed, dropped, times net_rx_action ran out of budget, received by
// RPS from another CPU, dropped by the flow limit, and the backlog length
// (input and process queues; 0 before Linux 6.0). Hexadecimal in the file.
type Softnet struct {
	CPU                                     int
	Processed, Dropped, Squeezed, RPS, Flow uint64
	Backlog                                 uint64
	HasCPU                                  bool // the line names its CPU (Linux 5.10+); else the n-th online CPU
}

// ReadSoftnet reads /proc/net/softnet_stat.
func (f FS) ReadSoftnet() ([]Softnet, error) {
	b, err := os.ReadFile(f.path("net", "softnet_stat"))
	if err != nil {
		return nil, err
	}
	var out []Softnet
	var fs [][]byte
	lines(b, func(line []byte) {
		fs = fields(line, fs)
		if len(fs) < 11 {
			return
		}
		x := func(i int) uint64 {
			if i >= len(fs) {
				return 0
			}
			v, _ := strconv.ParseUint(string(fs[i]), 16, 64)
			return v
		}
		s := Softnet{CPU: len(out), Processed: x(0), Dropped: x(1), Squeezed: x(2), RPS: x(9), Flow: x(10), Backlog: x(11)}
		if len(fs) >= 13 {
			s.CPU, s.HasCPU = int(x(12)), true
		}
		out = append(out, s)
	})
	return out, nil
}

// ReadCPUFreq reads each CPU's "cpu MHz" (x86) or "clock" (POWER) line of
// /proc/cpuinfo as sadc does: hundredths of a MHz from the integer part and
// the first two digits read of the fraction (sar -m CPU).
func (f FS) ReadCPUFreq() (map[int]int64, error) {
	b, err := os.ReadFile(f.path("cpuinfo"))
	if err != nil {
		return nil, err
	}
	out := map[int]int64{}
	cpu := 0
	lines(b, func(line []byte) {
		k, v, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			return
		}
		key := string(bytes.TrimRight(k, " \t"))
		switch {
		case key == "processor":
			n, _ := strconv.Atoi(string(bytes.TrimSpace(v)))
			cpu = n
		case key == "cpu MHz" || key == "clock":
			w, frac, _ := bytes.Cut(bytes.TrimSpace(v), []byte("."))
			i, _ := strconv.ParseInt(string(w), 10, 64)
			end := 0
			for end < len(frac) && frac[end] >= '0' && frac[end] <= '9' {
				end++
			}
			d, _ := strconv.ParseInt(string(frac[:end]), 10, 64)
			out[cpu] = i*100 + d/10
		}
	})
	return out, nil
}
