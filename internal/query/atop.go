// Parts of this file follow atop's showlinux.c, showsys.c, showgeneric.c and
// photosyst.c (GPL-2.0-or-later), used under the GPL-3.0: see LICENSING.md
// and packaging/notices/atop.txt.

package query

import (
	"cmp"
	"database/sql"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// atop's screen since boot (atop 1 1 into a pipe, as root), rebuilt from a
// recording at a moment: 80 columns, its system lines, then its processes.
// The layout and rules are atop 2.12.1's (showlinux.c prisyst, showsys.c).

// atopWidth is atop's line length into a pipe (linelen).
const atopWidth = 80

// AtopSys is what atop's system lines show at a moment, since boot.
type AtopSys struct {
	Host           string
	T, BootMS      int64
	Sys            store.SysSample
	OOMKnown       bool // vmstat has oom_kill (Linux 4.13+); atop leaves OOMKILLS out otherwise
	CPU            cpuTimes
	CPUs           []atopCPUStat
	Disks          []atopDisk // in /proc/diskstats order
	Net            map[string]int64
	Intfs          []atopIntf // in interface index order
	NUMANodes      int
	ShmRSS, ShmSwp int64 // bytes
	Procs          AtopProcSum
	List           []atopProc // in PID order
	PIDMax         int64      // kernel.pid_max: atop's PID column is as wide as it
}

// atopProc is one process as atop's process list shows it since boot: its
// totals since it started.
type atopProc struct {
	pid, threads, cpu, uid int
	state                  string
	stime, utime, blkTicks int64 // clock ticks
	runNS                  int64
	vszKB, rssKB           int64
	rbytes, wbytes, cancel int64
	comm                   string
}

type atopCPUStat struct {
	nr int
	t  cpuTimes
}

type atopDisk struct {
	name                string
	kind                byte // 'L' LVM (device mapper), 'M' MD, 'D' a disk
	nread, nwrite, ioMS int64
}

type atopIntf struct {
	name                       string
	rpack, spack, rbyte, sbyte int64
	speed                      int64 // Mb/s, 0 unknown
	duplex                     bool
}

// AtopProcSum is atop's process summary (PRC): the live processes' CPU
// time (clock ticks), their number and their idle threads.
type AtopProcSum struct {
	Stime, Utime  int64
	NProc, NTIdle int
}

// AtopSysAt loads the system values of the sample at or before t.
func AtopSysAt(db *store.DB, t int64) (*AtopSys, error) {
	var ts sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM sys_samples WHERE ts <= ?`, t).Scan(&ts); err != nil || !ts.Valid {
		return nil, fmt.Errorf("atop: no system sample at or before %s", FormatMS(t))
	}
	a := &AtopSys{Host: HostnameAt(db, t), T: t, BootMS: BootAt(db, t)}
	s := &a.Sys
	var psi, zsw, oom sql.NullInt64
	var ext [37]sql.NullInt64
	err := db.QueryRow(`SELECT ts, uptime_ms, load1, load5, load15, intr, ctxt, mem_total, mem_free, mem_available,
		buffers, cached, swap_cached, swap_total, swap_free, dirty, shmem, slab, sreclaimable,
		pgpgin, pgpgout, pswpin, pswpout, tcp_mem, udp_mem,
		committed_as, commit_limit, page_tables, hugepages_total, hugepages_free, hugepagesize, anon_hugepages,
		pgscan_kswapd, pgscan_direct, pgscan_khugepaged, pgscan_direct_throttle,
		pgsteal_kswapd, pgsteal_direct, pgsteal_khugepaged, allocstall, compact_stall, pgmigrate_success,
		numa_pages_migrated, oom_kill, zswpin, zswpout,
		psi, psi_cpu_some, psi_mem_some, psi_mem_full, psi_io_some, psi_io_full,
		psi_cpu_avg10, psi_cpu_avg60, psi_cpu_avg300, psi_mem_avg10, psi_mem_avg60, psi_mem_avg300,
		psi_io_avg10, psi_io_avg60, psi_io_avg300, zswap_enabled
		FROM sys_samples WHERE ts = ?`, ts.Int64).Scan(&s.TS, &s.UptimeMS, &s.Load1, &s.Load5, &s.Load15, &s.Intr, &s.Ctxt,
		&s.MemTotal, &s.MemFree, &s.MemAvailable, &s.Buffers, &s.Cached, &s.SwapCached, &s.SwapTotal, &s.SwapFree,
		&s.Dirty, &s.Shmem, &s.Slab, &s.SReclaimable, &s.PgpgIn, &s.PgpgOut, &s.PswpIn, &s.PswpOut, &s.TCPMem, &s.UDPMem,
		&ext[0], &ext[1], &ext[2], &ext[3], &ext[4], &ext[5], &ext[6],
		&ext[7], &ext[8], &ext[9], &ext[10], &ext[11], &ext[12], &ext[13], &ext[14], &ext[15], &ext[16],
		&ext[17], &oom, &ext[18], &ext[19],
		&psi, &ext[20], &ext[21], &ext[22], &ext[23], &ext[24],
		&ext[25], &ext[26], &ext[27], &ext[28], &ext[29], &ext[30], &ext[31], &ext[32], &ext[33], &zsw)
	if err != nil {
		return nil, err
	}
	v := func(i int) int64 { return ext[i].Int64 }
	s.CommittedAS, s.CommitLimit, s.PageTables = v(0), v(1), v(2)
	s.HugePagesTotal, s.HugePagesFree, s.Hugepagesize, s.AnonHugePages = v(3), v(4), v(5), v(6)
	s.PgscanKswapd, s.PgscanDirect, s.PgscanKhugepaged, s.PgscanDirectThrottle = v(7), v(8), v(9), v(10)
	s.PgstealKswapd, s.PgstealDirect, s.PgstealKhugepaged = v(11), v(12), v(13)
	s.AllocStall, s.CompactStall, s.PgmigrateSuccess, s.NumaPagesMigrated = v(14), v(15), v(16), v(17)
	s.OOMKill, a.OOMKnown = oom.Int64, oom.Valid && ext[0].Valid
	s.ZswpIn, s.ZswpOut = v(18), v(19)
	s.PSI = psi.Int64 == 1
	s.PSICPUSome, s.PSIMemSome, s.PSIMemFull, s.PSIIOSome, s.PSIIOFull = v(20), v(21), v(22), v(23), v(24)
	s.PSICPUAvg = [3]int64{v(25), v(26), v(27)}
	s.PSIMemAvg = [3]int64{v(28), v(29), v(30)}
	s.PSIIOAvg = [3]int64{v(31), v(32), v(33)}
	s.ZswapEnabled = zsw.Int64 == 1

	rows, err := db.Query(`SELECT cpu, user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
		FROM cpu_samples WHERE ts = ? ORDER BY cpu`, ts.Int64)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c atopCPUStat
		if err := rows.Scan(&c.nr, &c.t[0], &c.t[1], &c.t[2], &c.t[3], &c.t[4], &c.t[5], &c.t[6], &c.t[7], &c.t[8], &c.t[9]); err != nil {
			rows.Close()
			return nil, err
		}
		if c.nr < 0 {
			a.CPU = c.t
		} else {
			a.CPUs = append(a.CPUs, c)
		}
	}
	rows.Close()

	if err := a.loadDisks(db, ts.Int64, t); err != nil {
		return nil, err
	}
	if net, _, err := netCountersAt(db, t); err == nil {
		a.Net = map[string]int64{}
		for k, r := range net {
			a.Net[k] = r.Value
		}
	}
	if links, _, err := LinksAt(db, t); err == nil {
		for _, l := range links {
			if l.Gone || !l.HasStats {
				continue
			}
			a.Intfs = append(a.Intfs, atopIntf{name: l.Name, rpack: l.Stats[0], spack: l.Stats[1], rbyte: l.Stats[2],
				sbyte: l.Stats[3], speed: max(l.Speed, 0), duplex: l.Duplex == 1})
		}
	}
	if snap, err := SnapshotAt(db, t, false); err == nil {
		if procs, err := processesAt(db, snap, t); err == nil {
			for _, p := range procs {
				a.Procs.NProc++
				if p.state.String == "I" {
					a.Procs.NTIdle++
				}
				a.Procs.Stime += p.stime.Int64
				a.Procs.Utime += p.cpuTicks.Int64 - p.stime.Int64
				a.List = append(a.List, atopProc{pid: p.pid, uid: p.uid, threads: int(max(p.threads.Int64, 1)), cpu: int(p.psr.Int64),
					state: p.state.String, stime: p.stime.Int64, utime: p.cpuTicks.Int64 - p.stime.Int64,
					blkTicks: p.blkio.Int64, runNS: p.waitNS.Int64, vszKB: p.vszKB.Int64, rssKB: p.rssKB.Int64,
					rbytes: p.rbytes.Int64, wbytes: p.wbytes.Int64, cancel: p.cancelled.Int64, comm: p.comm})
			}
		}
	}
	a.PIDMax = 32768
	if lines, err := SysctlAt(db, t); err == nil {
		for _, l := range lines {
			if l.Name == "kernel.pid_max" {
				fmt.Sscan(l.Value, &a.PIDMax)
			}
		}
	}
	a.NUMANodes = 1
	if nodes, err := NUMAAt(db, t); err == nil && len(nodes) > 0 {
		a.NUMANodes = len(nodes)
	}
	if ipc, err := IPCAt(db, t); err == nil {
		for _, m := range ipc.Shm {
			a.ShmRSS += m["rss"]
			a.ShmSwp += m["swap"]
		}
	}
	return a, nil
}

// atop's disk names (photosyst.c validdisk): the devices it shows and what
// kind they are; others (partitions, loop, ram) are left out.
var atopDiskNames = []struct {
	re   *regexp.Regexp
	kind byte
}{
	{regexp.MustCompile(`^ram[0-9]+$`), 0},
	{regexp.MustCompile(`^loop[0-9]+$`), 0},
	{regexp.MustCompile(`^sd[a-z]+$`), 'D'},
	{regexp.MustCompile(`^dm-[0-9]+$`), 'L'},
	{regexp.MustCompile(`^md[0-9]+$`), 'M'},
	{regexp.MustCompile(`^vd[a-z]+$`), 'D'},
	{regexp.MustCompile(`^nvme[0-9]+n[0-9]+$`), 'D'},
	{regexp.MustCompile(`^nvme[0-9]+c[0-9]+n[0-9]+$`), 'D'},
	{regexp.MustCompile(`^nbd[0-9]+$`), 'D'},
	{regexp.MustCompile(`^hd[a-z]$`), 'D'},
	{regexp.MustCompile(`^rd/c[0-9]+d[0-9]+$`), 'D'},
	{regexp.MustCompile(`^cciss/c[0-9]+d[0-9]+$`), 'D'},
	{regexp.MustCompile(`^fio[a-z]+$`), 'D'},
	{regexp.MustCompile(`^xvd[a-z]+[0-9]*$`), 'D'},
	{regexp.MustCompile(`^dasd[a-z]+$`), 'D'},
	{regexp.MustCompile(`^mmcblk[0-9]+$`), 'D'},
	{regexp.MustCompile(`^emcpower[a-z]+$`), 'D'},
	{regexp.MustCompile(`^rbd[0-9]+$`), 'D'},
	{regexp.MustCompile(`^rbd[0-9]+p[0-9]+$`), 'D'},
}

func (a *AtopSys) loadDisks(db *store.DB, ts, t int64) error {
	dm := map[string]string{}
	if rows, err := db.Query(`SELECT name, arg_max(dm_name, ts) FROM blockdevs WHERE ts <= ? GROUP BY name`, t); err == nil {
		for rows.Next() {
			var n string
			var d sql.NullString
			if rows.Scan(&n, &d) == nil && d.String != "" {
				dm[n] = d.String
			}
		}
		rows.Close()
	}
	// The order of /proc/diskstats: by major and minor number.
	rows, err := db.Query(`SELECT name, rd_ios, wr_ios, dc_ios, io_ticks FROM disk_samples WHERE ts = ? ORDER BY major, minor`, ts)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var d atopDisk
		var dc int64
		if err := rows.Scan(&d.name, &d.nread, &d.nwrite, &dc, &d.ioMS); err != nil {
			return err
		}
		if d.nread+d.nwrite+dc == 0 {
			continue
		}
		for _, v := range atopDiskNames {
			if v.re.MatchString(d.name) {
				d.kind = v.kind
				break
			}
		}
		if d.kind == 0 {
			continue
		}
		if d.kind == 'L' && dm[d.name] != "" {
			d.name = dm[d.name]
		}
		a.Disks = append(a.Disks, d)
	}
	return rows.Err()
}

// atopField is one system box: its text from the values (nil: left out of
// this line, atop's validate function).
type atopField func(a *AtopSys, x *atopExtra) (string, bool)

type atopExtra struct {
	nsecs     int64
	cputot    int64 // all CPUs' ticks
	percputot int64
	cpu       *atopCPUStat
	disk      *atopDisk
	mstot     int64
	intf      *atopIntf
}

// atopBox is a label padded to the value's offset, then the value.
func atopBox(label string, off int, val string) string {
	return fmt.Sprintf("%-*s%s", off, label, val)
}

func atopMemMB(v int64) string { return atopMem(v, atopMB, false, 0) }

func cpuPerc(v, tot int64) float64 { return float64(v) * 100 / float64(tot) }

var atopFields = map[string]atopField{
	"BLANKBOX": func(*AtopSys, *atopExtra) (string, bool) { return atopBlank.text, true },
	// PRC
	"PRCSYS": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("sys", 6, atopCPU(a.Procs.Stime*1000/procfs.ClockTicks)), true
	},
	"PRCUSER": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("user", 6, atopCPU(a.Procs.Utime*1000/procfs.ClockTicks)), true
	},
	"PRCNPROC": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("#proc", 6, atopVal(int64(a.Procs.NProc), 6, false, 0)), true
	},
	"PRCNIDLE": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("#tidle", 8, atopVal(int64(a.Procs.NTIdle), 4, false, 0)), true
	},
	// As root, with process accounting active: no process exited before
	// the first sample.
	"PRCNNEXIT": func(*AtopSys, *atopExtra) (string, bool) { return atopBox("#exit", 6, atopVal(0, 6, false, 0)), true },
	// CPU and cpu
	"CPUSYS": func(a *AtopSys, x *atopExtra) (string, bool) { return cpuBox("sys", a.CPU[cSystem], x.percputot), true },
	"CPUUSER": func(a *AtopSys, x *atopExtra) (string, bool) {
		return cpuBox("user", a.CPU[cUser]+a.CPU[cNice], x.percputot), true
	},
	"CPUIRQ": func(a *AtopSys, x *atopExtra) (string, bool) {
		return cpuBox("irq", a.CPU[cIRQ]+a.CPU[cSoftIRQ], x.percputot), true
	},
	"CPUIDLE": func(a *AtopSys, x *atopExtra) (string, bool) { return cpuBox("idle", a.CPU[cIdle], x.percputot), true },
	"CPUWAIT": func(a *AtopSys, x *atopExtra) (string, bool) {
		return cpuBox("wait", a.CPU[cIOWait], x.percputot), true
	},
	"CPUISYS": func(_ *AtopSys, x *atopExtra) (string, bool) {
		return cpuBox("sys", x.cpu.t[cSystem], x.percputot), true
	},
	"CPUIUSER": func(_ *AtopSys, x *atopExtra) (string, bool) {
		return cpuBox("user", x.cpu.t[cUser]+x.cpu.t[cNice], x.percputot), true
	},
	"CPUIIRQ": func(_ *AtopSys, x *atopExtra) (string, bool) {
		return cpuBox("irq", x.cpu.t[cIRQ]+x.cpu.t[cSoftIRQ], x.percputot), true
	},
	"CPUIIDLE": func(_ *AtopSys, x *atopExtra) (string, bool) {
		return cpuBox("idle", x.cpu.t[cIdle], x.percputot), true
	},
	"CPUIWAIT": func(_ *AtopSys, x *atopExtra) (string, bool) {
		return fmt.Sprintf("cpu%03d w%3.0f%%", x.cpu.nr, cpuPerc(x.cpu.t[cIOWait], x.percputot)), true
	},
	// CPL
	"CPLNUMCPU": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("numcpu", 7, atopVal(int64(len(a.CPUs)), 5, false, 0)), true
	},
	"CPLAVG1": func(a *AtopSys, _ *atopExtra) (string, bool) { return atopBox("avg1", 5, atopLoad(a.Sys.Load1)), true },
	"CPLAVG5": func(a *AtopSys, _ *atopExtra) (string, bool) { return atopBox("avg5", 5, atopLoad(a.Sys.Load5)), true },
	"CPLAVG15": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("avg15", 5, atopLoad(a.Sys.Load15)), true
	},
	"CPLCSW": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("csw", 4, atopVal(a.Sys.Ctxt, 8, false, 0)), true
	},
	"CPLINTR": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("intr", 5, atopVal(a.Sys.Intr, 7, false, 0)), true
	},
	// MEM (kB in the recording)
	"MEMTOT":    memField("tot", func(s *store.SysSample) int64 { return s.MemTotal }),
	"MEMFREE":   memField("free", func(s *store.SysSample) int64 { return s.MemFree }),
	"MEMAVAIL":  memField("avail", func(s *store.SysSample) int64 { return s.MemAvailable }),
	"MEMCACHE":  memField("cache", func(s *store.SysSample) int64 { return s.Cached }),
	"MEMDIRTY":  memField("dirty", func(s *store.SysSample) int64 { return s.Dirty }),
	"MEMBUFFER": memField("buff", func(s *store.SysSample) int64 { return s.Buffers }),
	"MEMSLAB":   memField("slab", func(s *store.SysSample) int64 { return s.Slab }),
	"RECSLAB":   memField("slrec", func(s *store.SysSample) int64 { return s.SReclaimable }),
	"HUPTOT": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("hptot", 6, atopMemMB(a.Sys.HugePagesTotal*a.Sys.Hugepagesize*1024)), a.Sys.HugePagesTotal > 0
	},
	"HUPUSE": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("hpuse", 6, atopMemMB((a.Sys.HugePagesTotal-a.Sys.HugePagesFree)*a.Sys.Hugepagesize*1024)), a.Sys.HugePagesTotal > 0
	},
	"NUMNUMA": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("numnode", 8, atopVal(int64(a.NUMANodes), 4, false, 0)), true
	},
	"SHMEM":    memField("shmem", func(s *store.SysSample) int64 { return s.Shmem }),
	"SHMRSS":   func(a *AtopSys, _ *atopExtra) (string, bool) { return atopBox("shrss", 6, atopMemMB(a.ShmRSS)), true },
	"SHMSWP":   func(a *AtopSys, _ *atopExtra) (string, bool) { return atopBox("shswp", 6, atopMemMB(a.ShmSwp)), true },
	"PAGETABS": memField("pgtab", func(s *store.SysSample) int64 { return s.PageTables }),
	"ANONTHP": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("anthp", 6, atopMemMB(a.Sys.AnonHugePages*1024)), a.Sys.AnonHugePages > 0
	},
	"TCPSOCK": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("tcpsk", 6, atopMemMB(a.Sys.TCPMem*atopPage)), true
	},
	"UDPSOCK": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("udpsk", 6, atopMemMB(a.Sys.UDPMem*atopPage)), true
	},
	// Not recorded (VMware balloon, ZFS ARC, KSM): atop leaves them out where
	// they do not exist.
	"VMWBAL":     atopNever,
	"ZFSARC":     atopNever,
	"KSMSHARED":  atopNever,
	"KSMSHARING": atopNever,
	// SWP
	"SWPTOT":       memField("tot", func(s *store.SysSample) int64 { return s.SwapTotal }),
	"SWPFREE":      memField("free", func(s *store.SysSample) int64 { return s.SwapFree }),
	"SWPCACHE":     memField("swcac", func(s *store.SysSample) int64 { return s.SwapCached }),
	"SWPCOMMITTED": memField("vmcom", func(s *store.SysSample) int64 { return s.CommittedAS }),
	"SWPCOMMITLIM": memField("vmlim", func(s *store.SysSample) int64 { return s.CommitLimit }),
	"ZSWPOOL":      memField("zpool", func(s *store.SysSample) int64 { return s.Zswap }),
	"ZSWSTORED":    memField("zstor", func(s *store.SysSample) int64 { return s.Zswapped }),
	// PAG
	"PAGSCAN": pagField("scan", 5, 7, func(s *store.SysSample) int64 {
		return s.PgscanKswapd + s.PgscanDirect + s.PgscanDirectThrottle + s.PgscanKhugepaged
	}),
	"PAGSTEAL": pagField("steal", 6, 6, func(s *store.SysSample) int64 {
		return s.PgstealKswapd + s.PgstealDirect + s.PgstealKhugepaged
	}),
	"PAGSTALL":    pagField("stall", 6, 6, func(s *store.SysSample) int64 { return s.AllocStall }),
	"PAGCOMPACT":  pagField("compact", 8, 4, func(s *store.SysSample) int64 { return s.CompactStall }),
	"NUMAMIGRATE": pagField("numamig", 8, 4, func(s *store.SysSample) int64 { return s.NumaPagesMigrated }),
	"PGMIGRATE":   pagField("migrate", 8, 4, func(s *store.SysSample) int64 { return s.PgmigrateSuccess }),
	"PAGPGIN":     pagField("pgin", 5, 7, func(s *store.SysSample) int64 { return s.PgpgIn * 1024 / atopPage }),
	"PAGPGOUT":    pagField("pgout", 6, 6, func(s *store.SysSample) int64 { return s.PgpgOut * 1024 / atopPage }),
	"PAGSWIN":     pagField("swin", 5, 7, func(s *store.SysSample) int64 { return s.PswpIn }),
	"PAGSWOUT":    pagField("swout", 6, 6, func(s *store.SysSample) int64 { return s.PswpOut }),
	"PAGZSWIN": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("zswin", 6, atopVal(a.Sys.ZswpIn, 6, false, 0)), a.Sys.ZswapEnabled
	},
	"PAGZSWOUT": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("zswout", 7, atopVal(a.Sys.ZswpOut, 5, false, 0)), a.Sys.ZswapEnabled
	},
	"OOMKILLS": func(a *AtopSys, _ *atopExtra) (string, bool) {
		v := "    "
		if a.Sys.OOMKill != 0 {
			v = atopVal(a.Sys.OOMKill, 4, false, 0)
		}
		return atopBox("oomkill", 8, v), a.OOMKnown
	},
	// PSI: the share of the time since boot that tasks stalled
	"PSICPUSTOT": psiField("cpusome", func(s *store.SysSample) int64 { return s.PSICPUSome }),
	"PSIMEMSTOT": psiField("memsome", func(s *store.SysSample) int64 { return s.PSIMemSome }),
	"PSIMEMFTOT": psiField("memfull", func(s *store.SysSample) int64 { return s.PSIMemFull }),
	"PSIIOSTOT":  psiField("iosome", func(s *store.SysSample) int64 { return s.PSIIOSome }),
	"PSIIOFTOT":  psiField("iofull", func(s *store.SysSample) int64 { return s.PSIIOFull }),
	// DSK, LVM, MDD
	"DSKNAME": func(_ *AtopSys, x *atopExtra) (string, bool) {
		n := x.disk.name
		if len(n) > 12 {
			n = n[len(n)-12:]
		}
		return fmt.Sprintf("%12.12s", n), true
	},
	"DSKBUSY": func(_ *AtopSys, x *atopExtra) (string, bool) {
		p := float64(x.disk.ioMS) * 100 / float64(x.mstot)
		if !(p >= 0 && p < 1000000) {
			p = 999999
		}
		return atopBox("busy", 5, fmt.Sprintf("%6.0f%%", p)), true
	},
	"DSKNREAD": func(_ *AtopSys, x *atopExtra) (string, bool) {
		return atopBox("read", 5, atopVal(max(x.disk.nread, 0), 7, false, 0)), true
	},
	"DSKNWRITE": func(_ *AtopSys, x *atopExtra) (string, bool) {
		return atopBox("write", 6, atopVal(max(x.disk.nwrite, 0), 6, false, 0)), true
	},
	"DSKAVIO": func(_ *AtopSys, x *atopExtra) (string, bool) { return atopBox("avio", 5, atopAvio(x.disk)), true },
	// NET
	"NETTRANSPORT": func(*AtopSys, *atopExtra) (string, bool) { return "transport   ", true },
	"NETTCPI":      netField("tcpi", 5, 7, "TcpInSegs"),
	"NETTCPO":      netField("tcpo", 5, 7, "TcpOutSegs"),
	"NETUDPI":      netField("udpi", 5, 7, "UdpInDatagrams", "Udp6InDatagrams"),
	"NETUDPO":      netField("udpo", 5, 7, "UdpOutDatagrams", "Udp6OutDatagrams"),
	"NETNETWORK":   func(*AtopSys, *atopExtra) (string, bool) { return "network     ", true },
	"NETIPI":       netField("ipi", 4, 8, "IpInReceives", "Ip6InReceives"),
	"NETIPO":       netField("ipo", 4, 8, "IpOutRequests", "Ip6OutRequests"),
	"NETIPFRW":     netField("ipfrw", 6, 6, "IpForwDatagrams", "Ip6OutForwDatagrams"),
	"NETIPDELIV":   netField("deliv", 6, 6, "IpInDelivers", "Ip6InDelivers"),
	"NETNAME": func(_ *AtopSys, x *atopExtra) (string, bool) {
		i := x.intf
		if i.speed == 0 {
			return fmt.Sprintf("%-7.7s ----", i.name), true
		}
		in, out := i.rbyte/125/x.nsecs, i.sbyte/125/x.nsecs
		var busy int64
		if i.duplex {
			busy = max(in, out) / (i.speed * 10)
		} else {
			busy = (in + out) / (i.speed * 10)
		}
		return fmt.Sprintf("%-7.7s %3d%%", i.name, min(max(busy, -99), 999)), true
	},
	"NETPCKI": func(_ *AtopSys, x *atopExtra) (string, bool) {
		return atopBox("pcki", 5, atopVal(x.intf.rpack, 7, false, 0)), true
	},
	"NETPCKO": func(_ *AtopSys, x *atopExtra) (string, bool) {
		return atopBox("pcko", 5, atopVal(x.intf.spack, 7, false, 0)), true
	},
	"NETSPEEDIN":  func(_ *AtopSys, x *atopExtra) (string, bool) { return atopNetSpeed("si", x.intf.rbyte, x.nsecs), true },
	"NETSPEEDOUT": func(_ *AtopSys, x *atopExtra) (string, bool) { return atopNetSpeed("so", x.intf.sbyte, x.nsecs), true },
}

// atopPage is the page size atop converts with (x86_64, arm64 4K pages).
const atopPage = 4096

func atopNever(*AtopSys, *atopExtra) (string, bool) { return "", false }

func cpuBox(label string, v, tot int64) string {
	return fmt.Sprintf("%-4s %6.0f%%", label, cpuPerc(v, tot))
}

func memField(label string, kb func(*store.SysSample) int64) atopField {
	return func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox(label, 6, atopMemMB(kb(&a.Sys)*1024)), true
	}
}

func pagField(label string, off, width int, v func(*store.SysSample) int64) atopField {
	return func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox(label, off, atopVal(v(&a.Sys), width, false, 0)), true
	}
}

func psiField(label string, total func(*store.SysSample) int64) atopField {
	return func(a *AtopSys, x *atopExtra) (string, bool) {
		p := min(total(&a.Sys)/(x.nsecs*10000), 100)
		return fmt.Sprintf("%-7.7s %3d%%", label, p), true
	}
}

func netField(label string, off, width int, names ...string) atopField {
	return func(a *AtopSys, _ *atopExtra) (string, bool) {
		var v int64
		for _, n := range names {
			v += a.Net[n]
		}
		return atopBox(label, off, atopVal(v, width, false, 0)), true
	}
}

// atopLoad is a load average in 7 positions (recorded in hundredths).
func atopLoad(h int) string {
	l := float64(h) / 100
	switch {
	case l > 999999:
		return ">999999"
	case l > 999:
		return fmt.Sprintf("%7.0f", l)
	}
	return fmt.Sprintf("%7.2f", l)
}

// atopAvio is the average service time of a disk's transfers.
func atopAvio(d *atopDisk) string {
	var ms float64
	if n := d.nread + d.nwrite; n > 0 {
		ms = float64(d.ioMS) / float64(n)
	}
	switch {
	case ms >= 9995:
		return atopVal(int64(ms)/1000, 5, false, 0) + " s"
	case ms >= 99.95:
		return fmt.Sprintf("%4.0f ms", ms)
	case ms >= 9.995:
		return fmt.Sprintf("%4.1f ms", ms)
	case ms >= 0.09995:
		return fmt.Sprintf("%4.2f ms", ms)
	case ms >= 0.01:
		return fmt.Sprintf("%4.1f µs", ms*1000)
	case ms >= 0.0001:
		return fmt.Sprintf("%4.2f µs", ms*1000)
	}
	return fmt.Sprintf("%4.1f ns", ms*1000000)
}

// atopNetSpeed is makenetspeed: bytes since boot as a rate, Kbps up to
// 9999, then Mbps, Gbps, Tbps.
func atopNetSpeed(label string, bytes, nsecs int64) string {
	v := bytes / 125 / nsecs
	c := 'K'
	switch {
	case v < 10000:
	case v < 10000*1000:
		v, c = v/1000, 'M'
	case v < 10000*1000*1000:
		v, c = v/1000/1000, 'G'
	default:
		v, c = v/1000/1000/1000, 'T'
	}
	v = min(max(v, -999), 9999)
	return fmt.Sprintf("%s %4d %cbps", label, v, c)
}

// atop 2.12.1's built-in system lines (showlinux.c).
var atopLines = map[string]string{
	"PRC": "PRCSYS:8 PRCUSER:8 BLANKBOX:0 PRCNPROC:7 PRCNRUNNING:5 PRCNSLEEPING:5 PRCNDSLEEPING:5 PRCNIDLE:5 " +
		"PRCNZOMBIE:4 PRCCLONES:3 BLANKBOX:0 PRCNNEXIT:6",
	"CPU": "CPUSYS:9 CPUUSER:8 CPUIRQ:6 BLANKBOX:0 CPUIDLE:7 CPUWAIT:7 CPUSTEAL:2 CPUGUEST:3 BLANKBOX:0 " +
		"CPUIPC:5 CPUCYCLE:4 CPUFREQ:4 CPUSCALE:4",
	"cpu": "CPUISYS:9 CPUIUSER:8 CPUIIRQ:6 BLANKBOX:0 CPUIIDLE:7 CPUIWAIT:7 CPUISTEAL:2 CPUIGUEST:3 BLANKBOX:0 " +
		"CPUIIPC:5 CPUICYCLE:4 CPUIFREQ:4 CPUISCALE:4",
	"CPL":  "CPLNUMCPU:7BLANKBOX:0 CPLAVG1:4 CPLAVG5:3 CPLAVG15:2 BLANKBOX:0 CPLCSW:6 CPLINTR:5",
	"MEM1": "MEMTOT:8 MEMFREE:9 MEMAVAIL:7 BLANKBOX:0 MEMCACHE:7 MEMDIRTY:5 MEMBUFFER:6 BLANKBOX:0 MEMSLAB:6 RECSLAB:2 BLANKBOX:0 HUPTOT:4 HUPUSE:1",
	"MEM2": "NUMNUMA:8 BLANKBOX:1 SHMEM:6 SHMRSS:4 SHMSWP:4 BLANKBOX:0 TCPSOCK:3 UDPSOCK:2 BLANKBOX:0 PAGETABS:5 BLANKBOX:0 " +
		"ANONTHP:4 VMWBAL:4 BLANKBOX:0 ZFSARC:5",
	"SWP": "SWPTOT:5 SWPFREE:6 SWPCACHE:4 BLANKBOX:0 ZSWPOOL:3 ZSWSTORED:3 BLANKBOX:0 KSMSHARED:2 KSMSHARING:2 BLANKBOX:0 " +
		"SWPCOMMITTED:7 SWPCOMMITLIM:8",
	"PAG": "PAGSCAN:3 PAGSTEAL:2 PAGSTALL:1 PAGCOMPACT:5 NUMAMIGRATE:5PGMIGRATE:6PAGPGIN:6 PAGPGOUT:6 PAGZSWIN:4 " +
		"PAGZSWOUT:7 PAGSWIN:5 PAGSWOUT:8 OOMKILLS:9",
	"PSI": "PSICPUSTOT:7 PSIMEMSTOT:7 PSIMEMFTOT:8 PSIIOSTOT:7 PSIIOFTOT:8 PSICPUS:6 PSIMEMS:5 PSIMEMF:3 PSIIOS:4 PSIIOF:2 BLANKBOX:0",
	"DSK": "DSKNAME:9 DSKBUSY:8 DSKNREAD:7 DSKNWRITE:7 DSKNDISC:6 DSKKBPERRD:5 DSKKBPERWR:5 DSKKBPERDS:4 DSKMBPERSECRD:6 " +
		"DSKMBPERSECWR:6 DSKINFLIGHT:2 DSKAVQUEUE:1 DSKAVIO:6",
	"NETT": "NETTRANSPORT:9 NETTCPI:8 NETTCPO:8 NETUDPI:8 NETUDPO:8 NETTCPACTOPEN:6 NETTCPPASVOPEN:5 NETTCPRETRANS:4 " +
		"NETTCPINERR:3 NETTCPORESET:2 NETTCPCSUMERR:2 NETUDPNOPORT:1 NETUDPINERR:3",
	"NETN": "NETNETWORK:5 NETIPI:4 NETIPO:4 NETIPFRW:4 NETIPDELIV:4 BLANKBOX:0 BLANKBOX:0 BLANKBOX:0 NETICMPIN:1 NETICMPOUT:1",
	"NETI": "NETNAME:8 BLANKBOX:0 NETPCKI:7 NETPCKO:7 BLANKBOX:0 NETSPEEDMAX:5 NETSPEEDIN:6 NETSPEEDOUT:6 BLANKBOX:0 " +
		"NETCOLLIS:2 NETMULTICASTIN:2 NETRCVERR:4 NETSNDERR:4 NETRCVDROP:3 NETSNDDROP:3",
}

// atopValid are atop's validate functions (make_sys_prints, at the first
// sample): a field they reject is not in the line at all, so the next one
// takes its place. Fields clifr does not build yet are valid but never in
// the 80 columns' five boxes.
func atopValid(name string, a *AtopSys) bool {
	switch name {
	case "ANONTHP":
		return a.Sys.AnonHugePages > 0
	case "HUPTOT", "HUPUSE":
		return a.Sys.HugePagesTotal > 0
	case "OOMKILLS":
		return a.OOMKnown
	case "PAGZSWIN", "PAGZSWOUT":
		return a.Sys.ZswapEnabled
	case "VMWBAL", "ZFSARC", "KSMSHARED", "KSMSHARING":
		return false
	case "CPUIPC", "CPUCYCLE", "CPUIIPC", "CPUICYCLE": // no CPU cycle counters recorded
		return false
	case "CPUFREQ", "CPUIFREQ", "CPUSCALE", "CPUISCALE": // no CPU frequencies recorded
		return false
	case "DSKNDISC", "DSKKBPERDS": // discards: Linux 4.18+ diskstats
		return true
	}
	return true
}

// atopLine builds one system line: atop's fields of line in its order,
// the invalid ones left out, as many as fit.
func atopLine(label, line string, a *AtopSys, x *atopExtra) string {
	names, prios := atopDefs(atopLines[line])
	var items []atopItem
	for i, n := range names {
		if !atopValid(n, a) {
			continue
		}
		items = append(items, atopItem{text: n, prio: prios[i]}) // text: the field, formatted below
	}
	// Only the boxes that stay are formatted (atop formats after choosing).
	avail := (atopWidth - 5) / 15
	for len(items) > avail {
		low := 0
		for i := range items {
			if items[i].prio < items[low].prio {
				low = i
			}
		}
		items = append(items[:low], items[low+1:]...)
	}
	for i := range items {
		f, ok := atopFields[items[i].text]
		if !ok {
			items[i].text = "           ?"
			continue
		}
		items[i].text, _ = f(a, x)
	}
	return atopSysLine(label, items, atopWidth)
}

// PrintAtopSys prints atop's header and system lines.
func PrintAtopSys(w io.Writer, a *AtopSys) {
	// atop's boot time is /proc/stat's btime: whole seconds.
	nsecs := max(a.T/1000-a.BootMS/1000, 1)
	x := &atopExtra{nsecs: nsecs}
	t := time.UnixMilli(a.T)
	elapsed := atopElapsed(nsecs)
	lenAvail := atopWidth - 60 - len(elapsed) - len(a.Host)
	len1 := max(lenAvail/3, 1)
	len2 := lenAvail - len1 - len1
	fmt.Fprintf(w, "\n\nATOP - %s%*s%s %s %s %*s%s%*s%s elapsed\n", a.Host, len1, "", t.Format("2006/01/02"), t.Format("15:04:05"),
		"      ", len1, "", "-----------------7", max(len2, 0), "", elapsed)
	fmt.Fprintln(w, atopLine("PRC", "PRC", a, x))

	c := a.CPU
	x.cputot = c[cSystem] + c[cUser] + c[cNice] + c[cIdle] + c[cIOWait] + c[cIRQ] + c[cSoftIRQ] + c[cSteal]
	x.cputot = max(x.cputot, 1)
	x.percputot = max(x.cputot/int64(max(len(a.CPUs), 1)), 1)
	fmt.Fprintln(w, atopLine("CPU", "CPU", a, x))
	if len(a.CPUs) > 1 {
		cpus := slices.Clone(a.CPUs)
		slices.SortStableFunc(cpus, func(p, q atopCPUStat) int {
			return cmp.Compare(p.t[cIdle]+p.t[cIOWait], q.t[cIdle]+q.t[cIOWait])
		})
		for i := range cpus {
			t := &cpus[i].t
			tot := t[cSystem] + t[cUser] + t[cNice] + t[cIdle] + t[cIOWait] + t[cIRQ] + t[cSoftIRQ] + t[cSteal]
			if tot == t[cIdle]+t[cIOWait] {
				continue // an inactive CPU
			}
			x.cpu, x.percputot = &cpus[i], max(tot, 1)
			fmt.Fprintln(w, atopLine("cpu", "cpu", a, x))
		}
	}
	x.percputot = max(x.cputot/int64(max(len(a.CPUs), 1)), 1)
	fmt.Fprintln(w, atopLine("CPL", "CPL", a, x))
	fmt.Fprintln(w, atopLine("MEM", "MEM1", a, x))
	fmt.Fprintln(w, atopLine("MEM", "MEM2", a, x))
	fmt.Fprintln(w, atopLine("SWP", "SWP", a, x))
	s := &a.Sys
	if s.PgscanKswapd+s.PgscanDirect+s.PgscanDirectThrottle+s.PgscanKhugepaged != 0 ||
		s.PgstealKswapd+s.PgstealDirect+s.PgstealKhugepaged != 0 || s.AllocStall != 0 || s.CompactStall != 0 ||
		s.PgpgIn != 0 || s.PgpgOut != 0 || s.TCPMem != 0 || s.UDPMem != 0 || s.PswpIn != 0 || s.PswpOut != 0 ||
		s.OOMKill > 0 || s.PgmigrateSuccess != 0 || s.NumaPagesMigrated != 0 {
		fmt.Fprintln(w, atopLine("PAG", "PAG", a, x))
	}
	if s.PSI && (s.PSICPUAvg != [3]int64{} || s.PSIMemAvg != [3]int64{} || s.PSIIOAvg != [3]int64{}) {
		fmt.Fprintln(w, atopLine("PSI", "PSI", a, x))
	}
	x.mstot = max(x.cputot*1000/procfs.ClockTicks/int64(max(len(a.CPUs), 1)), 1)
	for _, kind := range []struct {
		k     byte
		label string
	}{{'L', "LVM"}, {'M', "MDD"}, {'D', "DSK"}} {
		var ds []atopDisk
		for _, d := range a.Disks {
			if d.kind == kind.k {
				ds = append(ds, d)
			}
		}
		slices.SortStableFunc(ds, func(p, q atopDisk) int { return cmp.Compare(q.ioMS, p.ioMS) })
		for i := range ds {
			x.disk = &ds[i]
			fmt.Fprintln(w, atopLine(kind.label, "DSK", a, x))
		}
	}
	if a.Net != nil {
		n := a.Net
		if n["TcpInSegs"]+n["TcpOutSegs"]+n["UdpInDatagrams"]+n["Udp6InDatagrams"]+n["UdpOutDatagrams"]+n["Udp6OutDatagrams"] != 0 {
			fmt.Fprintln(w, atopLine("NET", "NETT", a, x))
		}
		if n["IpInReceives"]+n["Ip6InReceives"]+n["IpOutRequests"]+n["Ip6OutRequests"] != 0 {
			fmt.Fprintln(w, atopLine("NET", "NETN", a, x))
		}
	}
	intfs := slices.Clone(a.Intfs)
	slices.SortStableFunc(intfs, atopIntfCompare)
	for i := range intfs {
		if intfs[i].rpack == 0 && intfs[i].spack == 0 {
			continue
		}
		x.intf = &intfs[i]
		fmt.Fprintln(w, atopLine("NET", "NETI", a, x))
	}
}

// atopIntfCompare is intfcompar: the busiest interface first, by its load
// relative to its speed where known; interfaces of known speed first.
func atopIntfCompare(a, b atopIntf) int {
	factor := func(i atopIntf) int64 {
		if i.speed == 0 {
			return 0
		}
		if i.duplex {
			return max(i.rbyte, i.sbyte) * 10 / i.speed
		}
		return (i.rbyte + i.sbyte) * 10 / i.speed
	}
	switch {
	case a.speed != 0 && b.speed != 0:
		return cmp.Compare(factor(b), factor(a))
	case a.speed == 0 && b.speed == 0:
		return cmp.Compare(b.rbyte+b.sbyte, a.rbyte+a.sbyte)
	case a.speed != 0:
		return -1
	}
	return 1
}

// atopCol is one process column: its header, width, priority (atop's
// default list) and value.
type atopCol struct {
	head  string
	width int
	prio  int
	val   func(p *atopProc, perc float64) string
}

// atopProcCols are atop 2.12.1's default process columns as root
// (make_proc_dynamicgen with IOSTAT; no containers, no netatop).
func atopProcCols(pidWidth, sortWidth int) []atopCol {
	cpu := func(ticks int64) string { return atopCPU(ticks * 1000 / procfs.ClockTicks) }
	mem := func(b int64) string { return atopMem(b, atopB, false, 0) }
	return []atopCol{
		{"PID", pidWidth, 10, func(p *atopProc, _ float64) string { return fmt.Sprintf("%*d", pidWidth, p.pid) }},
		{"SYSCPU", 6, 9, func(p *atopProc, _ float64) string { return cpu(p.stime) }},
		{"USRCPU", 6, 9, func(p *atopProc, _ float64) string { return cpu(p.utime) }},
		{"RDELAY", 6, 4, func(p *atopProc, _ float64) string { return atopCPU(p.runNS / 1000000) }},
		{"BDELAY", 6, 4, func(p *atopProc, _ float64) string { return cpu(p.blkTicks) }},
		{" VGROW", 6, 8, func(p *atopProc, _ float64) string { return mem(p.vszKB * 1024) }},
		{" RGROW", 6, 8, func(p *atopProc, _ float64) string { return mem(p.rssKB * 1024) }},
		{" RDDSK", 6, 7, func(p *atopProc, _ float64) string { return mem(p.rbytes / 512 * 512) }},
		{" WRDSK", 6, 7, func(p *atopProc, _ float64) string {
			return mem(max(p.wbytes/512-p.cancel/512, 0) * 512)
		}},
		{"RUID ", 8, 2, func(p *atopProc, _ float64) string { return fmt.Sprintf("%-8.8s", UserName(p.uid, false)) }},
		{"EUID ", 8, 1, func(p *atopProc, _ float64) string { return fmt.Sprintf("%-8.8s", UserName(p.uid, false)) }},
		{"ST", 2, 3, func(*atopProc, float64) string { return "N-" }},
		{"EXC", 3, 3, func(*atopProc, float64) string { return "  -" }},
		{" THR", 4, 3, func(p *atopProc, _ float64) string { return fmt.Sprintf("%4d", p.threads) }},
		{"S", 1, 3, func(p *atopProc, _ float64) string { return cmp.Or(p.state, "E") }},
		{"CPUNR", 5, 3, func(p *atopProc, _ float64) string { return fmt.Sprintf("%5d", p.cpu) }},
		{"CPU", sortWidth, 10, func(_ *atopProc, perc float64) string { return fmt.Sprintf("%*.0f%%", sortWidth-1, perc) }},
		{"CMD ", 14, 10, func(p *atopProc, _ float64) string { return fmt.Sprintf("%-14.14s", p.comm) }},
	}
}

// atopFit leaves out the lowest priority columns (the first of equal ones)
// while they do not fit in width with a space between them (getspacings).
func atopFit(cols []atopCol, width int) []atopCol {
	cols = slices.Clone(cols)
	sum := 0
	for _, c := range cols {
		sum += c.width
	}
	for len(cols) > 1 && sum+len(cols)-1 > width {
		low := 0
		for i := range cols {
			if cols[i].prio < cols[low].prio {
				low = i
			}
		}
		sum -= cols[low].width
		cols = append(cols[:low], cols[low+1:]...)
	}
	return cols
}

// PrintAtopProcs prints atop's banner and process list since boot: every
// process, the most CPU time first (equal ones in PID order).
func PrintAtopProcs(w io.Writer, a *AtopSys) {
	const initMsg, viewMsg = "*** System and Process Activity since Boot ***", "Unrestricted view (privileged)"
	fmt.Fprintf(w, "%s%*s%s\n", initMsg, atopWidth-len(initMsg)-len(viewMsg), " ", viewMsg)
	ncpu := int64(max(len(a.CPUs), 1))
	cols := atopFit(atopProcCols(len(fmt.Sprint(a.PIDMax)), len(fmt.Sprint(ncpu*100))+1), atopWidth)
	var b strings.Builder
	for _, c := range cols {
		// atop right-aligns PID (init_proc_prints) and the sort column.
		if c.head == "CPU" || c.head == "PID" {
			fmt.Fprintf(&b, "%*s ", c.width, c.head)
		} else {
			fmt.Fprintf(&b, "%-*s ", c.width, c.head)
		}
	}
	fmt.Fprintln(w, b.String())
	c := a.CPU
	avail := c[cSystem] + c[cUser] + c[cNice] + c[cIdle] + c[cIOWait] + c[cIRQ] + c[cSoftIRQ] + c[cSteal]
	procs := slices.Clone(a.List)
	slices.SortStableFunc(procs, func(p, q atopProc) int { return cmp.Compare(q.stime+q.utime, p.stime+p.utime) })
	for i := range procs {
		p := &procs[i]
		var perc float64
		if avail > 0 {
			perc = float64(p.stime+p.utime) * 100 / float64(avail/ncpu)
			perc = min(perc, 100*float64(ncpu), 100*float64(p.threads))
		}
		b.Reset()
		for _, col := range cols {
			b.WriteString(col.val(p, perc))
			b.WriteByte(' ')
		}
		fmt.Fprintln(w, b.String())
	}
}
