// Parts of this file follow atop's showlinux.c, showsys.c, showgeneric.c and
// photosyst.c (GPL-2.0-or-later), used under the GPL-3.0: see LICENSING.md
// and packaging/notices/atop.txt.

package query

import (
	"bytes"
	"cmp"
	"database/sql"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
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
	Host      string
	T, BootMS int64
	// BTime is /proc/stat's btime (whole seconds), atop's boot time: the
	// run's meta boot_time, else BootMS cut to seconds.
	BTime int64
	// NSecs: the interval of an interval screen (AtopIntervalAt); 0: the
	// screen since boot.
	NSecs int64
	// Interval: an interval screen (no banner; only the processes active in
	// it, their increases).
	Interval       bool
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
	V271           bool       // atop 2.7.1's screen (ToolStyle.Atop271)
	V210           bool       // atop 2.10.0's header (ToolStyle.Atop210)
	View           string     // process view: "" generic, m, d, s, v, c (atop's -m -d -s -v -c)
}

// atopProc is one process as atop's process list shows it since boot: its
// totals since it started.
type atopProc struct {
	pid, threads, cpu, uid int
	state                  string
	stime, utime, blkTicks int64 // clock ticks; blkTicks over all threads
	runNS                  int64
	nvcsw, nivcsw          int64 // all threads' context switches
	// Threads running, sleeping, in uninterruptible sleep, idle (schema 12;
	// before it the process's own state counts once).
	thrRun, thrSlpI, thrSlpU, thrIdle int
	// Memory segments in kB (atop -m; 0 before schema 12) and the real gid
	// (-1: unknown).
	vmStk, vmSwap, vmData, vmExe, vmLib, vmLck int64
	rgid                                       int
	vszKB, rssKB                               int64 // rssKB: /proc/PID/stat's rss, as atop reads it
	vgrowKB, rgrowKB                           int64 // the sizes since boot, their growth in an interval
	minflt, majflt                             int64
	ppid, ruid                                 int
	nice, prio, policy                         int // prio as atop shows it: stat's priority + 100
	rtprio                                     int
	wchan                                      string
	cmdline                                    string // as recorded (arguments joined by spaces)
	cmdlinePad                                 int    // NUL bytes after it
	isNew                                      bool   // started in the interval (atop's ST "N")
	rbytes, wbytes, cancel                     int64
	comm                                       string
	startMS                                    int64
	id, sampleTS                               int64
	exited                                     bool
	excode                                     int // atop's: exit code << 8, or the signal
}

// SetStyle takes atop's version from a tool style (StyleAt): 2.7.1's or
// 2.10.0's screen, else 2.12.1's.
func (a *AtopSys) SetStyle(st ToolStyle) { a.V271, a.V210 = st.Atop271, st.Atop210 }

// atopProcOf is a recorded process as atop reads it. Without schema 12's
// sums over the threads, the main thread's values and the process's state.
func atopProcOf(p procAt) atopProc {
	x := atopProc{pid: p.pid, uid: p.uid, threads: int(max(p.threads.Int64, 1)), cpu: int(p.psr.Int64),
		state: p.state.String, stime: p.stime.Int64, utime: p.cpuTicks.Int64 - p.stime.Int64,
		blkTicks: p.blkio.Int64, runNS: cmp.Or(p.runDelay.Int64, p.waitNS.Int64), vszKB: p.vszKB.Int64,
		rssKB: cmp.Or(p.rssStat.Int64, p.rssKB.Int64), startMS: p.startMS,
		rbytes: p.rbytes.Int64, wbytes: p.wbytes.Int64, cancel: p.cancelled.Int64, comm: p.comm,
		id: p.id, sampleTS: p.sampleTS.Int64, nvcsw: p.volCtx.Int64, nivcsw: p.nonVolCtx.Int64,
		vmStk: p.vmStk.Int64, vmSwap: p.vmSwap.Int64, vmData: p.vmData.Int64, vmExe: p.vmExe.Int64,
		vmLib: p.vmLib.Int64, vmLck: p.vmLck.Int64, rgid: -1,
		minflt: p.minFlt.Int64, majflt: p.majFlt.Int64, ppid: p.ppid, ruid: p.uid,
		nice: int(p.nice.Int64), prio: int(p.prio.Int64) + 100, policy: int(p.policy.Int64), rtprio: int(p.rtPrio.Int64),
		wchan: p.wchan.String, cmdline: p.cmdline, cmdlinePad: int(cmp.Or(p.cmdlinePad.Int64, 1)), isNew: true}
	if p.ruid.Valid {
		x.ruid = int(p.ruid.Int64)
	}
	x.vgrowKB, x.rgrowKB = x.vszKB, x.rssKB
	if p.rgid.Valid {
		x.rgid = int(p.rgid.Int64)
	}
	if p.thrRun.Valid { // schema 12: over all threads
		x.blkTicks, x.nvcsw, x.nivcsw = p.blkioAll.Int64, p.volCtxAll.Int64, p.nonVolCtxAll.Int64
		x.thrRun, x.thrSlpI, x.thrSlpU, x.thrIdle = int(p.thrRun.Int64), int(p.thrSleepI.Int64), int(p.thrSleepU.Int64), int(p.thrIdle.Int64)
		return x
	}
	switch x.state {
	case "R":
		x.thrRun = 1
	case "S":
		x.thrSlpI = 1
	case "D":
		x.thrSlpU = 1
	case "I":
		x.thrIdle = 1
	}
	return x
}

// add counts a live process as atop's deviate does: a zombie, else its
// threads by state.
func (s *AtopProcSum) add(p *atopProc) {
	s.NProc++
	if p.state == "Z" {
		s.NZombie++
		return
	}
	s.NTRun += p.thrRun
	s.NTSlpI += p.thrSlpI
	s.NTSlpU += p.thrSlpU
	s.NTIdle += p.thrIdle
}

// StartedAfter reports whether process pid started after ts (atop may show
// it, clifrd's sample at ts did not have its values).
func (a *AtopSys) StartedAfter(pid int, ts int64) bool {
	for _, p := range a.List {
		if p.pid == pid {
			return p.startMS > ts
		}
	}
	return false
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
	Stime, Utime           int64
	NProc, NTIdle, NZombie int
	NTRun, NTSlpI, NTSlpU  int // threads running, sleeping, in uninterruptible sleep
	NExit                  int // exited in the interval
}

// AtopSysAt loads the system values of the sample at or before t.
func AtopSysAt(db *store.DB, t int64) (*AtopSys, error) {
	var ts sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM sys_samples WHERE ts <= ?`, t).Scan(&ts); err != nil || !ts.Valid {
		return nil, fmt.Errorf("atop: no system sample at or before %s", FormatMS(t))
	}
	a := &AtopSys{Host: HostnameAt(db, t), T: t, BootMS: BootAt(db, t)}
	a.BTime = a.BootMS / 1000
	if bt, err := strconv.ParseInt(MetaAt(db, "boot_time", t), 10, 64); err == nil && bt > 0 {
		a.BTime = bt
	}
	// atop shows the node name up to its first dot.
	a.Host, _, _ = strings.Cut(a.Host, ".")
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
				x := atopProcOf(p)
				a.Procs.add(&x)
				a.Procs.Stime += x.stime
				a.Procs.Utime += x.utime
				a.List = append(a.List, x)
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
	"PRCNZOMBIE": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("#zombie", 8, atopVal(int64(a.Procs.NZombie), 4, false, 0)), true
	},
	// As root, with process accounting active: the processes that exited in
	// the interval (none before the first sample).
	"PRCNNEXIT": func(a *AtopSys, _ *atopExtra) (string, bool) {
		return atopBox("#exit", 6, atopVal(int64(a.Procs.NExit), 6, false, 0)), true
	},
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
		return atopBox("oomkill", 8, atopVal(a.Sys.OOMKill, 4, false, 0)), a.OOMKnown
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

// atopLoad6 is CPLAVG15's 6 positions.
func atopLoad6(h int) string {
	l := float64(h) / 100
	switch {
	case l > 99999:
		return ">99999"
	case l > 999:
		return fmt.Sprintf("%6.0f", l)
	}
	return fmt.Sprintf("%6.2f", l)
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

// atop 2.7.1's built-in lines where they differ from 2.12.1's.
var atopLines271 = map[string]string{
	"PRC": "PRCSYS:8 PRCUSER:8 BLANKBOX:0 PRCNPROC:7 PRCNRUNNING:5 PRCNSLEEPING:5 PRCNDSLEEPING:5 PRCNZOMBIE:5 " +
		"PRCCLONES:4 BLANKBOX:0 PRCNNEXIT:6",
	"CPL": "CPLAVG1:4 CPLAVG5:3 CPLAVG15:2 BLANKBOX:0 CPLCSW:6 CPLINTR:5 BLANKBOX:0 CPLNUMCPU:1",
	"MEM1": "MEMTOT:8 MEMFREE:9 MEMCACHE:7 MEMDIRTY:5 MEMBUFFER:7 MEMSLAB:7 RECSLAB:4 BLANKBOX:0 SHMEM:4 SHMRSS:4 " +
		"SHMSWP:3 BLANKBOX:0 VMWBAL:5 BLANKBOX:0 ZFSARC:6 BLANKBOX:0 HUPTOT:6 HUPUSE:3 NUMNUMA:7",
	"SWP": "SWPTOT:5 SWPFREE:6 SWPCACHE:4 BLANKBOX:0 ZSWPOOL:3 ZSWSTORED:3 BLANKBOX:0 KSMSHARED:2 KSMSHARING:2 BLANKBOX:0 " +
		"SWPCOMMITTED:7 SWPCOMMITLIM:8",
	"PAG": "PAGSCAN:3 PAGSTEAL:2 PAGSTALL:1 PAGCOMPACT:5 NUMAMIGRATE:5PGMIGRATE:6BLANKBOX:0 BLANKBOX:0 BLANKBOX:0 " +
		"PAGSWIN:5 PAGSWOUT:7 OOMKILLS:8",
	"DSK": "DSKNAME:9 DSKBUSY:8 DSKNREAD:7 DSKNWRITE:7 DSKNDISC:6 DSKKBPERRD:5 DSKKBPERWR:5 DSKKBPERDS:4 DSKMBPERSECRD:6 " +
		"DSKMBPERSECWR:6 DSKAVQUEUE:1 DSKAVIO:6",
	"NETT": "NETTRANSPORT:9 NETTCPI:8 NETTCPO:8 NETUDPI:8 NETUDPO:8 NETTCPACTOPEN:6 NETTCPPASVOPEN:5 NETTCPRETRANS:4 " +
		"NETTCPINERR:3 NETTCPORESET:2 NETUDPNOPORT:1 NETUDPINERR:3",
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
	def := atopLines[line]
	if d, ok := atopLines271[line]; ok && a.V271 {
		def = d
	}
	names, prios := atopDefs(def)
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
	nsecs := max(a.T/1000-a.BTime, 1)
	if a.NSecs > 0 {
		nsecs = a.NSecs
	}
	x := &atopExtra{nsecs: nsecs}
	t := time.UnixMilli(a.T)
	elapsed := atopElapsed(nsecs)
	lenAvail := atopWidth - 60 - len(elapsed) - len(a.Host)
	len1 := max(lenAvail/3, 1)
	len2 := lenAvail - len1 - len1
	// A negative width pads on the left in C's printf and Go's fmt alike: a
	// long host name still gets its spaces.
	if a.V271 || a.V210 {
		lenAvail = atopWidth - 52 - len(elapsed) - len(a.Host)
		len1, len2 = lenAvail/3, lenAvail-lenAvail/3*2
		fmt.Fprintf(w, "\n\nATOP - %s%*s%s  %s%*s%s%*s%s elapsed\n", a.Host, len1, "", t.Format("2006/01/02"),
			t.Format("15:04:05"), len1, "", "-----------------", len2, "", elapsed)
	} else {
		fmt.Fprintf(w, "\n\nATOP - %s%*s%s %s %s %*s%s%*s%s elapsed\n", a.Host, len1, "", t.Format("2006/01/02"), t.Format("15:04:05"),
			"      ", len1, "", "-----------------7", len2, "", elapsed)
	}
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
	if !a.V271 {
		fmt.Fprintln(w, atopLine("MEM", "MEM2", a, x))
	}
	fmt.Fprintln(w, atopLine("SWP", "SWP", a, x))
	s := &a.Sys
	if s.PgscanKswapd+s.PgscanDirect+s.PgscanDirectThrottle+s.PgscanKhugepaged != 0 ||
		s.PgstealKswapd+s.PgstealDirect+s.PgstealKhugepaged != 0 || s.AllocStall != 0 || s.CompactStall != 0 ||
		!a.V271 && (s.PgpgIn != 0 || s.PgpgOut != 0 || s.TCPMem != 0 || s.UDPMem != 0) || s.PswpIn != 0 || s.PswpOut != 0 ||
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

// atopCol is one process column (showprocs.c's procprt_*): its header,
// width (0: atop's variable-width command line), priority (from the view's
// list) and value.
type atopCol struct {
	head  string
	width int
	prio  int
	right bool // header right-aligned (PID-like columns and the sort column)
	val   func(p *atopProc, perc float64) string
}

// atopViews are atop's process views as root (showlinux.c's built-in
// lists; the generic one as make_proc_dynamicgen builds it with IOSTAT, no
// containers, no netatop): the columns by priority, the sort column. A
// version's own list where it differs.
var atopViews = map[string]struct{ defs, defs271, sort string }{
	"": {"PID:10 SYSCPU:9 USRCPU:9 RDELAY:4 BDELAY:4 VGROW:8 RGROW:8 RDDSK:7 CWRDSK:7 RUID:2 EUID:1 " +
		"ST:3 EXC:3 THR:3 S:3 CPUNR:3 SORTITEM:10 CMD:10",
		"PID:10 SYSCPU:9 USRCPU:9 RDELAY:4 VGROW:8 RGROW:8 RDDSK:7 CWRDSK:7 RUID:2 EUID:1 " +
			"ST:3 EXC:3 THR:3 S:3 CPUNR:3 SORTITEM:10 CMD:10", "CPU"},
	"m": {"PID:10 TID:3 MINFLT:2 MAJFLT:2 VSTEXT:4 VSLIBS:4 VDATA:4 VSTACK:4 LOCKSZ:3 VSIZE:6 RSIZE:7 PSIZE:5 " +
		"VGROW:7 RGROW:8 SWAPSZ:5 RUID:1 EUID:0 SORTITEM:9 CMD:10", "", "MEM"},
	"d": {"PID:10 TID:4 RDDSK:9 WRDSK:9 WCANCL:8 SORTITEM:10 CMD:10", "", "DSK"},
	"s": {"PID:10 TID:6 CID:4 VPID:3 CTID:3 TRUN:7 TSLPI:7 TSLPU:7 TIDLE:7 POLI:8 NICE:9 PRI:5 RTPR:9 CPUNR:8 " +
		"ST:8 EXC:8 S:8 RDELAY:8 BDELAY:7 WCHAN:5 NVCSW:7 NIVCSW:7 SORTITEM:10 CMD:10",
		"PID:10 TID:6 CID:4 VPID:3 CTID:3 TRUN:7 TSLPI:7 TSLPU:7 POLI:8 NICE:9 PRI:5 RTPR:9 CPUNR:8 ST:8 " +
			"EXC:8 S:8 RDELAY:8 WCHAN:5 SORTITEM:10 CMD:10", "CPU"},
	"v": {"PID:10 TID:4 PPID:9 CID:2 VPID:1 CTID:1 RUID:8 RGID:8 EUID:5 EGID:4 SUID:3 SGID:2 FSUID:3 FSGID:2 " +
		"STDATE:7 STTIME:7 ENDATE:5 ENTIME:5 ST:6 EXC:6 S:6 SORTITEM:10 CMD:10", "", "CPU"},
	"c": {"PID:10 TID:4 S:8 SORTITEM:10 COMMAND-LINE:10", "", "CPU"},
}

// atopColumns are the process columns atop's views use, by atop's names,
// with their exit variants (procprt_*_e) for a process that exited in the
// interval. Columns of what clifrd does not record (containers, saved and
// file-system ids) print "?": no view shows them at 80 columns.
func atopColumns(a *AtopSys, pidWidth, sortWidth int) map[string]atopCol {
	cpu := func(ticks int64) string { return atopCPU(ticks * 1000 / procfs.ClockTicks) }
	mem := func(kb int64) string { return atopMem(kb*1024, atopB, false, 0) }
	sect := func(n int64) string { return atopMem(n*512, atopB, false, 0) } // 512-byte sectors
	ex := func(e string, f func(p *atopProc) string) func(p *atopProc, _ float64) string {
		return func(p *atopProc, _ float64) string {
			if p.exited {
				return e
			}
			return f(p)
		}
	}
	ae := func(f func(p *atopProc) string) func(p *atopProc, _ float64) string {
		return func(p *atopProc, _ float64) string { return f(p) }
	}
	// uid2str, gid2str: a name longer than 8 characters as the number
	// (2.12.1) or cut to 8 (2.7.1 and 2.10.0).
	id := func(n int, name string) string {
		if name != "" && (len(name) <= 8 || a.V271 || a.V210) {
			return fmt.Sprintf("%-8.8s", name)
		}
		return fmt.Sprintf("%-8d", n)
	}
	uid := func(n int) string { return id(n, UserName(n, false)) }
	na := func(w int) func(*atopProc, float64) string {
		return func(*atopProc, float64) string { return fmt.Sprintf("%*s", w, "?") }
	}
	// The start in whole seconds as atop has it: (starttime + the boot
	// time it measures in ticks, getbootlinux) / hertz, the precise start.
	start := func(p *atopProc) time.Time { return time.Unix(p.startMS/1000, 0).In(time.Local) }
	dash := fmt.Sprintf("%*s", pidWidth, "-")
	nettWsz := func(p *atopProc) int64 { return max(p.wbytes/512-p.cancel/512, 0) }
	cols := map[string]atopCol{
		"PID": {"PID", pidWidth, 0, true, ae(func(p *atopProc) string { return fmt.Sprintf("%*d", pidWidth, p.pid) })},
		"TID": {"TID", pidWidth, 0, true, func(*atopProc, float64) string { return dash }},
		"PPID": {"PPID", pidWidth, 0, true, ae(func(p *atopProc) string {
			if p.exited && p.ppid == 0 {
				return dash
			}
			return fmt.Sprintf("%*d", pidWidth, p.ppid)
		})},
		"VPID":   {"VPID", pidWidth, 0, true, na(pidWidth)},
		"CTID":   {" CTID", 5, 0, false, na(5)},
		"CID":    {"CID/POD        ", 15, 0, false, na(15)},
		"SYSCPU": {"SYSCPU", 6, 0, false, ae(func(p *atopProc) string { return cpu(p.stime) })},
		"USRCPU": {"USRCPU", 6, 0, false, ae(func(p *atopProc) string { return cpu(p.utime) })},
		"RDELAY": {"RDELAY", 6, 0, false, ex("     -", func(p *atopProc) string { return atopCPU(p.runNS / 1000000) })},
		"BDELAY": {"BDELAY", 6, 0, false, ex("     -", func(p *atopProc) string { return cpu(p.blkTicks) })},
		"VGROW":  {" VGROW", 6, 0, false, ex("    0K", func(p *atopProc) string { return mem(p.vgrowKB) })},
		"RGROW":  {" RGROW", 6, 0, false, ex("    0K", func(p *atopProc) string { return mem(p.rgrowKB) })},
		"MINFLT": {"MINFLT", 6, 0, false, ae(func(p *atopProc) string { return atopVal(p.minflt, 6, false, 0) })},
		"MAJFLT": {"MAJFLT", 6, 0, false, ae(func(p *atopProc) string { return atopVal(p.majflt, 6, false, 0) })},
		"VSTEXT": {"VSTEXT", 6, 0, false, ex("    0K", func(p *atopProc) string { return mem(p.vmExe) })},
		"VSLIBS": {"VSLIBS", 6, 0, false, ex("    0K", func(p *atopProc) string { return mem(p.vmLib) })},
		"VDATA":  {" VDATA", 6, 0, false, ex("    0K", func(p *atopProc) string { return mem(p.vmData) })},
		"VSTACK": {"VSTACK", 6, 0, false, ex("    0K", func(p *atopProc) string { return mem(p.vmStk) })},
		"LOCKSZ": {"LOCKSZ", 6, 0, false, ex("    0K", func(p *atopProc) string { return atopMem(p.vmLck*1024, atopKB, false, 0) })},
		"VSIZE":  {" VSIZE", 6, 0, false, ex("    0K", func(p *atopProc) string { return mem(p.vszKB) })},
		"RSIZE":  {" RSIZE", 6, 0, false, ex("    0K", func(p *atopProc) string { return mem(p.rssKB) })},
		// PSS: only with atop's -R (smaps_rollup per process).
		"PSIZE":  {" PSIZE", 6, 0, false, ex("    0K", func(*atopProc) string { return mem(0) })},
		"SWAPSZ": {"SWAPSZ", 6, 0, false, ex("    0K", func(p *atopProc) string { return mem(p.vmSwap) })},
		"RDDSK":  {" RDDSK", 6, 0, false, ex("     -", func(p *atopProc) string { return sect(p.rbytes / 512) })},
		"WRDSK":  {" WRDSK", 6, 0, false, ex("     -", func(p *atopProc) string { return sect(p.wbytes / 512) })},
		"CWRDSK": {" WRDSK", 6, 0, false, ex("     -", func(p *atopProc) string { return sect(nettWsz(p)) })},
		"WCANCL": {"WCANCL", 6, 0, false, ex("     -", func(p *atopProc) string { return sect(p.cancel / 512) })},
		"RUID":   {"RUID    ", 8, 0, false, ae(func(p *atopProc) string { return uid(p.ruid) })},
		"EUID":   {"EUID    ", 8, 0, false, ex("-       ", func(p *atopProc) string { return uid(p.uid) })},
		"RGID": {"RGID    ", 8, 0, false, ae(func(p *atopProc) string {
			if p.rgid < 0 {
				return "?       "
			}
			return id(p.rgid, GroupName(p.rgid))
		})},
		"EGID":   {"EGID    ", 8, 0, false, na(8)},
		"SUID":   {"SUID    ", 8, 0, false, na(8)},
		"SGID":   {"SGID    ", 8, 0, false, na(8)},
		"FSUID":  {"FSUID   ", 8, 0, false, na(8)},
		"FSGID":  {"FSGID   ", 8, 0, false, na(8)},
		"STDATE": {"  STDATE  ", 10, 0, false, ae(func(p *atopProc) string { return start(p).Format("2006/01/02") })},
		"STTIME": {" STTIME ", 8, 0, false, ae(func(p *atopProc) string { return start(p).Format("15:04:05") })},
		"ENDATE": {"  ENDATE  ", 10, 0, false, ex("  active  ", func(*atopProc) string { return "  active  " })},
		"ENTIME": {" ENTIME ", 8, 0, false, ex(" active ", func(*atopProc) string { return " active " })},
		"THR":    {" THR", 4, 0, false, ex("   0", func(p *atopProc) string { return fmt.Sprintf("%4d", p.threads) })},
		"TRUN":   {"TRUN", 4, 0, false, ex("   0", func(p *atopProc) string { return fmt.Sprintf("%4d", p.thrRun) })},
		"TSLPI":  {"TSLPI", 5, 0, false, ex("    0", func(p *atopProc) string { return fmt.Sprintf("%5d", p.thrSlpI) })},
		"TSLPU":  {"TSLPU", 5, 0, false, ex("    0", func(p *atopProc) string { return fmt.Sprintf("%5d", p.thrSlpU) })},
		"TIDLE":  {"TIDLE", 5, 0, false, ex("    0", func(p *atopProc) string { return fmt.Sprintf("%5d", p.thrIdle) })},
		"POLI": {"POLI", 4, 0, false, ex("-   ", func(p *atopProc) string {
			if p.policy >= 0 && p.policy < 7 {
				return []string{"norm", "fifo", "rr  ", "btch", "iso ", "idle", "dead"}[p.policy]
			}
			return "?   "
		})},
		"NICE":  {"NICE", 4, 0, false, ex("   -", func(p *atopProc) string { return fmt.Sprintf("%4d", p.nice) })},
		"PRI":   {"PRI", 3, 0, false, ex("  -", func(p *atopProc) string { return fmt.Sprintf("%3d", p.prio) })},
		"RTPR":  {"RTPR", 4, 0, false, ex("   -", func(p *atopProc) string { return fmt.Sprintf("%4d", p.rtprio) })},
		"CPUNR": {"CPUNR", 5, 0, false, ex("    -", func(p *atopProc) string { return fmt.Sprintf("%5d", p.cpu) })},
		"ST": {"ST", 2, 0, false, ae(func(p *atopProc) string {
			st := []byte("--")
			if p.isNew {
				st[0] = 'N'
			}
			if p.exited {
				switch {
				case p.excode&0xff == 0:
					st[1] = 'E'
				case p.excode&0x80 != 0:
					st[1] = 'C'
				default:
					st[1] = 'S'
				}
			}
			return string(st)
		})},
		"EXC": {"EXC", 3, 0, false, ex("  -", func(*atopProc) string { return "" })},
		// "-": a process known from its fork or exec only (no sample yet), as ps.
		"S": {"S", 1, 0, false, ae(func(p *atopProc) string { return cmp.Or(p.state, "-") })},
		"WCHAN": {"WCHAN          ", 15, 0, false, ex(fmt.Sprintf("%-15s", ""), func(p *atopProc) string {
			if p.state == "R" {
				return fmt.Sprintf("%-15s", "")
			}
			return fmt.Sprintf("%-15.15s", p.wchan)
		})},
		"NVCSW":  {" NVCSW", 6, 0, false, ex("     -", func(p *atopProc) string { return atopVal(p.nvcsw, 6, false, 0) })},
		"NIVCSW": {"NIVCSW", 6, 0, false, ex("     -", func(p *atopProc) string { return atopVal(p.nivcsw, 6, false, 0) })},
		"SORTITEM": {"", sortWidth, 0, true, func(_ *atopProc, perc float64) string {
			return fmt.Sprintf("%*.0f%%", sortWidth-1, perc)
		}},
		"CMD": {"CMD           ", 14, 0, false, ae(func(p *atopProc) string {
			if p.exited {
				name := p.comm
				if len(name) > 12 {
					name = name[:12]
				}
				return fmt.Sprintf("%-14.14s", "<"+name+">")
			}
			return fmt.Sprintf("%-14.14s", p.comm)
		})},
		"COMMAND-LINE": {"COMMAND-LINE (horizontal scroll with <- and -> keys)", 0, 0, false, ae(atopCmdline)},
	}
	exc := cols["EXC"]
	exc.val = func(p *atopProc, _ float64) string {
		if !p.exited {
			return "  -"
		}
		if p.excode&0xff != 0 {
			return fmt.Sprintf("%3d", p.excode&0x7f)
		}
		return fmt.Sprintf("%3d", p.excode>>8&0xff)
	}
	cols["EXC"] = exc
	return cols
}

// atopCmdline is atop's command line (proccmd): the first 255 bytes of
// /proc/PID/cmdline with each NUL, newline, CR and tab but the last byte read
// made a space, up to the first NUL left; the process name without one
// (stat's, at most 15 characters: clifrd records a kernel thread's full
// name where the kernel gives it).
func atopCmdline(p *atopProc) string {
	const cmdLen = 255
	if p.cmdline == "" {
		return p.comm[:min(len(p.comm), 15)]
	}
	raw := []byte(p.cmdline + strings.Repeat("\x00", max(p.cmdlinePad, 1)))
	raw = raw[:min(len(raw), cmdLen)]
	for i := 0; i < len(raw)-1; i++ {
		switch raw[i] {
		case 0, '\n', '\r', '\t':
			raw[i] = ' '
		}
	}
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	return string(raw)
}

// atopFit leaves out the lowest priority columns (the first of equal ones)
// while they do not fit in width with a space between them, and 12 columns
// for a variable-width one (getspacings).
func atopFit(cols []atopCol, width int) []atopCol {
	cols = slices.Clone(cols)
	sum := 0
	for _, c := range cols {
		sum += c.width
		if c.width == 0 {
			sum += 12
		}
	}
	for len(cols) > 1 && sum+len(cols)-1 > width {
		low := 0
		for i := range cols {
			if cols[i].prio < cols[low].prio {
				low = i
			}
		}
		sum -= cols[low].width
		if cols[low].width == 0 {
			sum -= 12
		}
		cols = append(cols[:low], cols[low+1:]...)
	}
	return cols
}

// PrintAtopProcs prints atop's banner and process list in the view a.View
// ("" generic, m memory, d disk, s scheduling, v various, c command line),
// sorted as atop sorts it (CPU, then memory; memory; disk, then CPU), equal
// ones in PID order.
func PrintAtopProcs(w io.Writer, a *AtopSys) {
	const initMsg, viewMsg = "*** System and Process Activity since Boot ***", "Unrestricted view (privileged)"
	switch {
	case a.Interval: // no banner after the first screen
		fmt.Fprintln(w)
	case a.V271:
		fmt.Fprintf(w, "        %s     %s\n", initMsg, viewMsg)
	default:
		fmt.Fprintf(w, "%s%*s%s\n", initMsg, atopWidth-len(initMsg)-len(viewMsg), " ", viewMsg)
	}
	ncpu := int64(max(len(a.CPUs), 1))
	view := atopViews[a.View]
	defs := view.defs
	if a.V271 && view.defs271 != "" {
		defs = view.defs271
	}
	catalog := atopColumns(a, len(fmt.Sprint(a.PIDMax)), len(fmt.Sprint(ncpu*100))+1)
	names, prios := atopDefs(defs)
	var all []atopCol
	for i, n := range names {
		c := catalog[n]
		c.prio = prios[i]
		if n == "SORTITEM" {
			c.head = view.sort
		}
		all = append(all, c)
	}
	cols := atopFit(all, atopWidth)
	var b strings.Builder
	for _, c := range cols {
		if c.right {
			fmt.Fprintf(&b, "%*s ", c.width, c.head)
		} else {
			fmt.Fprintf(&b, "%-*s ", c.width, c.head)
		}
	}
	fmt.Fprintln(w, b.String())
	c := a.CPU
	avail := c[cSystem] + c[cUser] + c[cNice] + c[cIdle] + c[cIOWait] + c[cIRQ] + c[cSoftIRQ] + c[cSteal]
	dsk := func(p *atopProc) int64 { return p.rbytes/512 + max(p.wbytes/512-p.cancel/512, 0) }
	var availDsk int64
	for i := range a.List {
		availDsk += dsk(&a.List[i])
	}
	byCPU := func(p, q atopProc) int {
		return cmp.Or(cmp.Compare(q.stime+q.utime, p.stime+p.utime), cmp.Compare(q.rssKB, p.rssKB))
	}
	procs := slices.Clone(a.List)
	switch view.sort {
	case "MEM":
		slices.SortStableFunc(procs, func(p, q atopProc) int { return cmp.Compare(q.rssKB, p.rssKB) })
	case "DSK":
		slices.SortStableFunc(procs, func(p, q atopProc) int { return cmp.Or(cmp.Compare(dsk(&q), dsk(&p)), byCPU(p, q)) })
	default:
		slices.SortStableFunc(procs, byCPU)
	}
	for i := range procs {
		p := &procs[i]
		var perc float64
		switch view.sort {
		case "MEM":
			if a.Sys.MemTotal > 0 {
				perc = min(float64(p.rssKB)*100/float64(a.Sys.MemTotal), 100)
			}
		case "DSK":
			if availDsk > 0 {
				perc = min(float64(dsk(p))*100/float64(availDsk), 100)
			}
		default:
			if avail > 0 {
				perc = float64(p.stime+p.utime) * 100 / float64(avail/ncpu)
				perc = min(perc, 100*float64(ncpu), 100*float64(p.threads))
			}
		}
		b.Reset()
		for _, col := range cols {
			b.WriteString(col.val(p, perc))
			b.WriteByte(' ')
		}
		fmt.Fprintln(w, b.String())
	}
}

// AtopIntervalAt is atop's screen for the interval between the samples at
// or before from and to: counters as their increase, gauges (memory sizes,
// load, the averages of PSI) at the end.
func AtopIntervalAt(db *store.DB, from, to int64) (*AtopSys, error) {
	a0, err := AtopSysAt(db, from)
	if err != nil {
		return nil, err
	}
	a, err := AtopSysAt(db, to)
	if err != nil {
		return nil, err
	}
	a.NSecs = max((a.Sys.TS-a0.Sys.TS+500)/1000, 1)
	s, p := &a.Sys, &a0.Sys
	for _, c := range []struct{ now, prev *int64 }{
		{&s.Intr, &p.Intr}, {&s.Ctxt, &p.Ctxt}, {&s.PgpgIn, &p.PgpgIn}, {&s.PgpgOut, &p.PgpgOut},
		{&s.PswpIn, &p.PswpIn}, {&s.PswpOut, &p.PswpOut}, {&s.PgscanKswapd, &p.PgscanKswapd},
		{&s.PgscanDirect, &p.PgscanDirect}, {&s.PgscanKhugepaged, &p.PgscanKhugepaged},
		{&s.PgscanDirectThrottle, &p.PgscanDirectThrottle}, {&s.PgstealKswapd, &p.PgstealKswapd},
		{&s.PgstealDirect, &p.PgstealDirect}, {&s.PgstealKhugepaged, &p.PgstealKhugepaged},
		{&s.AllocStall, &p.AllocStall}, {&s.CompactStall, &p.CompactStall}, {&s.PgmigrateSuccess, &p.PgmigrateSuccess},
		{&s.NumaPagesMigrated, &p.NumaPagesMigrated}, {&s.OOMKill, &p.OOMKill}, {&s.ZswpIn, &p.ZswpIn},
		{&s.ZswpOut, &p.ZswpOut}, {&s.PSICPUSome, &p.PSICPUSome}, {&s.PSIMemSome, &p.PSIMemSome},
		{&s.PSIMemFull, &p.PSIMemFull}, {&s.PSIIOSome, &p.PSIIOSome}, {&s.PSIIOFull, &p.PSIIOFull},
	} {
		*c.now -= *c.prev
	}
	for i := range a.CPU {
		a.CPU[i] -= a0.CPU[i]
	}
	prevCPU := map[int]cpuTimes{}
	for _, c := range a0.CPUs {
		prevCPU[c.nr] = c.t
	}
	for i := range a.CPUs {
		pt := prevCPU[a.CPUs[i].nr]
		for j := range a.CPUs[i].t {
			a.CPUs[i].t[j] -= pt[j]
		}
	}
	prevDisk := map[string]atopDisk{}
	for _, d := range a0.Disks {
		prevDisk[d.name] = d
	}
	disks := a.Disks[:0]
	for _, d := range a.Disks {
		pd := prevDisk[d.name]
		d.nread, d.nwrite, d.ioMS = d.nread-pd.nread, d.nwrite-pd.nwrite, d.ioMS-pd.ioMS
		if d.nread+d.nwrite != 0 {
			disks = append(disks, d) // atop: a disk without transfers is left out
		}
	}
	a.Disks = disks
	for k, v := range a0.Net {
		a.Net[k] -= v
	}
	prevIntf := map[string]atopIntf{}
	for _, i := range a0.Intfs {
		prevIntf[i.name] = i
	}
	for i := range a.Intfs {
		pi := prevIntf[a.Intfs[i].name]
		a.Intfs[i].rpack -= pi.rpack
		a.Intfs[i].spack -= pi.spack
		a.Intfs[i].rbyte -= pi.rbyte
		a.Intfs[i].sbyte -= pi.sbyte
	}
	a.Interval = true
	a.List, a.Procs = atopIntervalProcs(db, a0, a)
	return a, nil
}

// atopIntervalProcs are the processes atop shows for an interval: those
// active in it (a sample row written in it: clifrd writes one when anything
// changed; or started in it) with their increases, and those that exited
// in it. The summary (PRC) counts all.
func atopIntervalProcs(db *store.DB, a0, a *AtopSys) ([]atopProc, AtopProcSum) {
	prev := map[int64]atopProc{}
	for _, p := range a0.List {
		prev[p.id] = p
	}
	var sum AtopProcSum
	var out []atopProc
	for _, p := range a.List {
		sum.add(&p)
		q, known := prev[p.id]
		if known && p.sampleTS <= q.sampleTS {
			continue // not active
		}
		p.stime -= q.stime
		p.utime -= q.utime
		p.blkTicks -= q.blkTicks
		p.runNS -= q.runNS
		p.nvcsw -= q.nvcsw
		p.nivcsw -= q.nivcsw
		p.vgrowKB = p.vszKB - q.vszKB
		p.rgrowKB = p.rssKB - q.rssKB
		p.minflt -= q.minflt
		p.majflt -= q.majflt
		p.isNew = !known
		p.rbytes -= q.rbytes
		p.wbytes -= q.wbytes
		p.cancel -= q.cancel
		sum.Stime += p.stime
		sum.Utime += p.utime
		out = append(out, p)
	}
	// Exited in the interval: their CPU time up to their last sample.
	rows, err := db.Query(`
		SELECT p.id, p.pid, p.comm, p.start_time, p.exit_code, p.signal, p.ppid, p.uid, COALESCE(p.ruid, p.uid),
		       COALESCE(p.rgid, -1), COALESCE(p.cmdline, ''), COALESCE(p.cmdline_pad, 1),
		       (SELECT arg_max(x.cpu_ticks, x.ts) FROM proc_samples x WHERE x.proc_id = p.id AND x.ts <= ?2),
		       (SELECT arg_max(x.stime_ticks, x.ts) FROM proc_samples x WHERE x.proc_id = p.id AND x.ts <= ?2)
		FROM processes p
		WHERE COALESCE(p.ended, p.last_seen) > ?1 AND COALESCE(p.ended, p.last_seen) <= ?2 AND p.first_seen <= ?2
		ORDER BY p.pid`, a0.Sys.TS, a.Sys.TS)
	if err == nil {
		defer rows.Close()
		alive := map[int64]bool{}
		for _, p := range a.List {
			alive[p.id] = true
		}
		for rows.Next() {
			var e atopProc
			var code, sig, cpu, st sql.NullInt64
			if rows.Scan(&e.id, &e.pid, &e.comm, &e.startMS, &code, &sig, &e.ppid, &e.uid, &e.ruid, &e.rgid,
				&e.cmdline, &e.cmdlinePad, &cpu, &st) != nil {
				continue
			}
			// An open process's row carries the last sample as last_seen:
			// still alive at the end, it did not exit.
			if alive[e.id] {
				continue
			}
			q := prev[e.id]
			e.exited, e.state, e.threads = true, "E", 1
			e.isNew = e.startMS > a0.Sys.TS
			e.stime = max(st.Int64-q.stime, 0)
			e.utime = max(cpu.Int64-st.Int64-q.utime, 0)
			switch {
			case sig.Valid && sig.Int64 > 0:
				e.excode = int(sig.Int64)
			case code.Valid:
				e.excode = int(code.Int64) << 8
			}
			sum.Stime += e.stime
			sum.Utime += e.utime
			sum.NExit++
			out = append(out, e)
		}
	}
	return out, sum
}
