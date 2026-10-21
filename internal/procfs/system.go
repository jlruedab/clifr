package procfs

import (
	"bytes"
	"os"
	"strconv"
)

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
}

func (f FS) ReadVMStat() (VMStat, error) {
	b, err := os.ReadFile(f.path("vmstat"))
	if err != nil {
		return VMStat{}, err
	}
	var v VMStat
	dst := map[string]*uint64{"pgpgin": &v.PgpgIn, "pgpgout": &v.PgpgOut, "pswpin": &v.PswpIn,
		"pswpout": &v.PswpOut, "pgfault": &v.PgFault, "pgmajfault": &v.PgMajFault}
	var fs [][]byte
	found := 0
	lines(b, func(line []byte) {
		if len(line) < 2 || line[0] != 'p' { // every wanted key starts with "p"
			return
		}
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
		return v, errShort
	}
	return v, nil
}

// DiskStat is one line of /proc/diskstats. Sectors are 512 bytes, times ms.
type DiskStat struct {
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
		d := DiskStat{Major: int(u64(fs[0])), Minor: int(u64(fs[1])), Name: string(fs[2])}
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

func (f FS) ReadSockStat() (SockStat, error) {
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
	b, err := os.ReadFile(f.path("net/sockstat"))
	if err != nil {
		return s, err
	}
	parse(b)
	if b, err := os.ReadFile(f.path("net/sockstat6")); err == nil {
		parse(b)
	}
	return s, nil
}
