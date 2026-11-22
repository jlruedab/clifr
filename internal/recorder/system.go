package recorder

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"clifr/internal/metrics"
	"clifr/internal/procfs"
	"clifr/internal/rtnl"
	"clifr/internal/store"

	"golang.org/x/sys/unix"
)

// readPressure reads /proc/pressure (recorded since schema 12, and for /metrics). A
// kernel without PSI, or without one of the files, is not an error.
func (r *Recorder) readPressure(fail func(string, error) bool) map[string]procfs.Pressure {
	out := map[string]procfs.Pressure{}
	for _, res := range metrics.PressureResources {
		p, err := r.fs.ReadPressure(res)
		if errors.Is(err, fs.ErrNotExist) || fail("pressure/"+res, err) {
			continue
		}
		out[res] = p
	}
	return out
}

// clockBoot is the uptime at ts and the boot time on the clock: ts -
// CLOCK_BOOTTIME. r.boot, measured when clifrd started, stays the run's
// (process start times are keyed by it); when the clock is stepped later
// (the first NTP sync at boot, a VM's clock corrected), the boot time moves
// by the step: a clock_step guard event above 100 ms. With --proc-root
// fixtures the run's boot time.
func (r *Recorder) clockBoot(ts int64) (uptime, boot int64) {
	if r.fs.Root != "/proc" {
		return ts - r.boot, r.boot
	}
	// Both clocks now (ts is when the sample began, some ms earlier).
	var bt unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &bt); err != nil {
		return ts - r.boot, r.boot
	}
	boot = time.Now().UnixMilli() - bt.Nano()/1e6
	return ts - boot, boot
}

// noteClockStep records a clock_step guard event when the boot time on the
// clock moved by more than 100 ms since the last system sample: the sample
// times before it are on the old clock.
func (r *Recorder) noteClockStep(ts, boot int64, b *store.Batch) {
	prev := cmp.Or(r.sys.bootMS, r.boot)
	r.sys.bootMS = boot
	if d := boot - prev; d > 100 || d < -100 {
		detail := fmt.Sprintf("the clock moved %+.3f s (boot time %s -> %s)", float64(d)/1000,
			time.UnixMilli(prev).UTC().Format("15:04:05.000"), time.UnixMilli(boot).UTC().Format("15:04:05.000"))
		b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "clock_step", Detail: detail})
		r.log.Printf("clock step: %s", detail)
	}
}

// sysSampler reads the system-wide counters behind uptime, vmstat, mpstat and
// iostat once per sample.
type sysSampler struct {
	virtual map[string]bool // sar -b: whole devices without /sys/block/NAME/device
	warned  map[string]bool
	part    map[string]bool // disk name -> is a partition
	sysfs   bool            // /sys describes the recorded machine
	// Protocol counters as last written, and when all of them were.
	netLast map[string]int64
	netFull int64
	// Network interfaces likewise (by ifindex; the row without TS).
	linkLast map[int]store.LinkRow
	linkFull int64
	snaps    map[string]*snapState // by source
	// Block devices likewise (by name).
	blockLast  map[string]store.BlockDevRow
	blockFull  int64
	blockRead  int64       // when they were last read
	blockDirty atomic.Bool // a uevent reported a change (startUevents)
	neighs     *neighState
	bootMS     int64 // the boot time at the last sample (clock steps)
}

func newSysSampler(procRoot string) *sysSampler {
	return &sysSampler{warned: map[string]bool{}, part: map[string]bool{}, sysfs: procRoot == "" || procRoot == "/proc"}
}

// isPart reports whether a /proc/diskstats name is a partition: those have no
// directory of their own in /sys/block.
func (s *sysSampler) isPart(name string) bool {
	if !s.sysfs {
		return false
	}
	p, ok := s.part[name]
	if !ok {
		_, err := os.Stat("/sys/block/" + strings.ReplaceAll(name, "/", "!"))
		p = err != nil
		s.part[name] = p
	}
	return p
}

// sampleSystem adds the system-wide rows of this sample to the batch. A file
// that cannot be read is reported once and leaves its values at zero; without
// /proc/stat there is no row at all.
func (r *Recorder) sampleSystem(ts int64, b *store.Batch) {
	s := r.sys
	fail := func(what string, err error) bool {
		if err != nil && !s.warned[what] {
			s.warned[what] = true
			r.log.Errorf("system counters: %s: %v", what, err)
		}
		return err != nil
	}
	st, err := r.fs.ReadSysStat()
	if fail("stat", err) {
		return
	}
	uptime, boot := r.clockBoot(ts)
	r.noteClockStep(ts, boot, b)
	row := &store.SysSample{TS: ts, UptimeMS: uptime, BootMS: boot, ProcsRunning: st.ProcsRunning, ProcsBlocked: st.ProcsBlocked,
		Intr: int64(st.Intr), Ctxt: int64(st.Ctxt), Forks: int64(st.Forks), SoftIRQ: int64(st.SoftIRQ)}
	firstCPU := len(b.CPUs)
	// sar -m CPU and -n SOFT (schema 14): each CPU's frequency and
	// softnet_stat line; a line without its CPU number is the n-th online CPU.
	mhz, err := r.fs.ReadCPUFreq()
	if err != nil {
		mhz = nil
	}
	soft := map[int]procfs.Softnet{}
	if sn, err := r.fs.ReadSoftnet(); err == nil {
		var online []int
		for _, c := range st.CPUs {
			if c.CPU >= 0 {
				online = append(online, c.CPU)
			}
		}
		for i, x := range sn {
			if !x.HasCPU {
				if i >= len(online) {
					break
				}
				x.CPU = online[i]
			}
			soft[x.CPU] = x
		}
	}
	for _, c := range st.CPUs {
		cs := store.CPUSample{TS: ts, CPU: c.CPU, MHz: -1}
		for i, v := range c.T {
			cs.T[i] = int64(v)
		}
		if f, ok := mhz[c.CPU]; ok {
			cs.MHz = f
		}
		if x, ok := soft[c.CPU]; ok {
			cs.Softnet = [6]int64{int64(x.Processed), int64(x.Dropped), int64(x.Squeezed), int64(x.RPS), int64(x.Flow), int64(x.Backlog)}
			cs.HasSoftnet = true
		}
		b.CPUs = append(b.CPUs, cs)
	}
	if l, err := r.fs.ReadLoadAvg(); !fail("loadavg", err) {
		row.Load1, row.Load5, row.Load15, row.Runnable, row.Threads = l.Load1, l.Load5, l.Load15, l.Runnable, l.Threads
	}
	if m, err := r.fs.ReadMemInfo(); !fail("meminfo", err) {
		row.MemTotal, row.MemFree, row.MemAvailable, row.Buffers, row.Cached = int64(m.Total), int64(m.Free), int64(m.Available), int64(m.Buffers), int64(m.Cached)
		row.SwapCached, row.Active, row.Inactive, row.SwapTotal, row.SwapFree = int64(m.SwapCached), int64(m.Active), int64(m.Inactive), int64(m.SwapTotal), int64(m.SwapFree)
		row.Dirty, row.Writeback, row.Shmem, row.Slab, row.SReclaimable = int64(m.Dirty), int64(m.Writeback), int64(m.Shmem), int64(m.Slab), int64(m.SReclaimable)
		row.CommittedAS, row.CommitLimit, row.PageTables = int64(m.CommittedAS), int64(m.CommitLimit), int64(m.PageTables)
		row.HugePagesTotal, row.HugePagesFree, row.Hugepagesize = int64(m.HugePagesTotal), int64(m.HugePagesFree), int64(m.Hugepagesize)
		row.AnonHugePages, row.Zswap, row.Zswapped = int64(m.AnonHugePages), int64(m.Zswap), int64(m.Zswapped)
		row.AnonPages, row.KernelStack, row.VmallocUsed = int64(m.AnonPages), int64(m.KernelStack), int64(m.VmallocUsed)
		row.HugePagesRsvd, row.HugePagesSurp = int64(m.HugePagesRsvd), int64(m.HugePagesSurp)
	}
	if v, err := r.fs.ReadVMStat(); !fail("vmstat", err) {
		row.PgpgIn, row.PgpgOut, row.PswpIn, row.PswpOut = int64(v.PgpgIn), int64(v.PgpgOut), int64(v.PswpIn), int64(v.PswpOut)
		row.PgFault, row.PgMajFault = int64(v.PgFault), int64(v.PgMajFault)
		row.PgscanKswapd, row.PgscanDirect, row.PgscanKhugepaged, row.PgscanProactive = int64(v.PgscanKswapd), int64(v.PgscanDirect), int64(v.PgscanKhugepaged), int64(v.PgscanProactive)
		row.PgstealKswapd, row.PgstealDirect, row.PgstealKhugepaged, row.PgstealProactive = int64(v.PgstealKswapd), int64(v.PgstealDirect), int64(v.PgstealKhugepaged), int64(v.PgstealProactive)
		row.AllocStall, row.CompactStall, row.PgmigrateSuccess, row.NumaPagesMigrated = int64(v.AllocStall), int64(v.CompactStall), int64(v.PgmigrateSuccess), int64(v.NumaPagesMigrated)
		row.OOMKill, row.ZswpIn, row.ZswpOut = int64(v.OOMKill), int64(v.ZswpIn), int64(v.ZswpOut)
		row.PgscanDirectThrottle = int64(v.PgscanDirectThrottle)
		row.PgFree, row.PgstealAnon, row.PgstealFile = int64(v.PgFree), int64(v.PgstealAnon), int64(v.PgstealFile)
		row.PgPromote, row.PgDemote = int64(v.PgPromoteSuccess), int64(v.PgDemote)
	}
	press := r.readPressure(fail)
	if c, ok := press["cpu"]; ok {
		row.PSI = true
		row.PSICPUSome, row.PSICPUFull = int64(c.Some), int64(c.Full)
		m, i := press["memory"], press["io"]
		row.PSIMemSome, row.PSIMemFull, row.PSIIOSome, row.PSIIOFull = int64(m.Some), int64(m.Full), int64(i.Some), int64(i.Full)
		row.PSICPUAvg, row.PSIMemAvg, row.PSIIOAvg = c.SomeAvg, m.SomeAvg, i.SomeAvg
		row.PSIMemFullAvg, row.PSIIOFullAvg = m.FullAvg, i.FullAvg
	}
	row.ZswapEnabled = zswapEnabled()
	if k, err := r.fs.ReadSockStat(); !fail("net/sockstat", err) {
		row.SockUsed, row.TCPInUse, row.TCPOrphan, row.TCPTW, row.TCPAlloc, row.TCPMem = int64(k.Used), int64(k.TCPInUse), int64(k.TCPOrphan), int64(k.TCPTW), int64(k.TCPAlloc), int64(k.TCPMem)
		row.UDPInUse, row.UDPMem, row.UDPLiteInUse, row.RawInUse, row.FragInUse = int64(k.UDPInUse), int64(k.UDPMem), int64(k.UDPLiteInUse), int64(k.RawInUse), int64(k.FragInUse)
		row.FragMemory, row.TCP6InUse, row.UDP6InUse, row.UDPLite6InUse = int64(k.FragMemory), int64(k.TCP6InUse), int64(k.UDP6InUse), int64(k.UDPLite6InUse)
		row.Raw6InUse, row.Frag6InUse, row.Frag6Memory = int64(k.Raw6InUse), int64(k.Frag6InUse), int64(k.Frag6Memory)
	}
	b.Sys = append(b.Sys, *row)
	if r.cfg.Metrics {
		// Published when the rest (interfaces, disks) is read too. New
		// slices: the published snapshot stays as it is.
		firstDisk := len(b.Disks)
		defer func() {
			r.live.Version, r.live.BootMS = r.cfg.Version, r.boot
			r.live.SysTS, r.live.Sys = ts, *row
			r.live.CPUs = append([]store.CPUSample(nil), b.CPUs[firstCPU:]...)
			r.live.Disks = append([]store.DiskSample(nil), b.Disks[firstDisk:]...)
			r.live.Links = make([]store.LinkRow, 0, len(s.linkLast))
			for _, l := range s.linkLast {
				r.live.Links = append(r.live.Links, l)
			}
			r.live.Press = press
			r.publishMetrics()
		}()
	}
	if s.sysfs { // rtnetlink describes this machine, not a --proc-root fixture
		if links, err := rtnl.Dump(); !fail("rtnetlink links", err) {
			s.addLinks(ts, links, b)
		}
		if ns, err := rtnl.DumpNeighs(); !fail("rtnetlink neighbours", err) {
			s.addNeighs(ts, ns, b)
		}
	}
	if c, err := r.fs.ReadNetCounters(); !fail("net/snmp", err) {
		full := s.netLast == nil || ts-s.netFull >= store.NetCountersFullMS
		if full {
			s.netLast, s.netFull = map[string]int64{}, ts
		}
		for i, n := range c {
			if v, ok := s.netLast[n.Name]; full || !ok || v != n.Value {
				b.NetCounters = append(b.NetCounters, store.NetCounter{TS: ts, Pos: i, Section: n.Section, Name: n.Name, Value: n.Value})
				s.netLast[n.Name] = n.Value
			}
		}
	}
	r.sampleSnapshots(ts, b, fail)
	if s.sysfs && s.blockDue(ts) {
		if devs, err := readBlockDevs(); !fail("/sys/block", err) {
			s.addBlockDevs(ts, devs, b)
		}
	}
	disks, err := r.fs.ReadDiskStats()
	if fail("diskstats", err) {
		return
	}
	for i := range disks {
		d := &disks[i]
		if !d.Used() {
			continue
		}
		ds := store.DiskSample{TS: ts, Major: d.Major, Minor: d.Minor, Name: d.Name, Part: s.isPart(d.Name), Pos: d.Pos}
		if !ds.Part && s.sysfs {
			ds.Virtual = s.isVirtual(d.Name)
		}
		for j := 0; j < 4; j++ {
			ds.V[j], ds.V[4+j], ds.V[8+j] = int64(d.Rd[j]), int64(d.Wr[j]), int64(d.Dc[j])
		}
		ds.V[12], ds.V[13], ds.V[14], ds.V[15], ds.V[16] = int64(d.InFlight), int64(d.IOTicks), int64(d.TimeInQueue), int64(d.FlIOs), int64(d.FlTicks)
		b.Disks = append(b.Disks, ds)
	}
}

// addLinks writes the interfaces that changed (counters included), all of
// them every NetCountersFullMS, and a Gone row for each that went away.
func (s *sysSampler) addLinks(ts int64, links []rtnl.Link, b *store.Batch) {
	full := s.linkLast == nil || ts-s.linkFull >= store.NetCountersFullMS
	if full {
		s.linkFull = ts
	}
	seen := map[int]store.LinkRow{}
	for i := range links {
		row := linkRow(&links[i])
		seen[row.Index] = row
		if old, ok := s.linkLast[row.Index]; full || !ok || !reflect.DeepEqual(old, row) {
			row.TS = ts
			b.Links = append(b.Links, row)
		}
	}
	for idx, old := range s.linkLast {
		if _, ok := seen[idx]; !ok {
			b.Links = append(b.Links, store.LinkRow{TS: ts, Index: idx, Name: old.Name, Gone: true})
		}
	}
	s.linkLast = seen
}

func linkRow(l *rtnl.Link) store.LinkRow {
	r := store.LinkRow{Index: l.Index, Type: l.Type, Flags: int64(l.Flags), Name: l.Name, Qdisc: l.Qdisc, Alias: l.Alias,
		Kind: l.Kind, SlaveKind: l.SlaveKind, PhysPortName: l.PhysPortName, ParentBus: l.ParentBus, ParentDev: l.ParentDev,
		AltNames: strings.Join(l.AltNames, "\n"), MTU: l.MTU, Master: l.Master, Link: l.Link, LinkNetnsID: l.LinkNetnsID,
		OperState: l.OperState, LinkMode: l.LinkMode, Group: l.Group, TxQLen: l.TxQLen, Promiscuity: l.Promiscuity,
		Allmulti: l.Allmulti, MinMTU: l.MinMTU, MaxMTU: l.MaxMTU, NetnsImmutable: l.NetnsImmutable, AddrGenMode: l.AddrGenMode,
		NumTxQueues: l.NumTxQueues, NumRxQueues: l.NumRxQueues, GSOMaxSize: l.GSOMaxSize, GSOMaxSegs: l.GSOMaxSegs,
		TSOMaxSize: l.TSOMaxSize, TSOMaxSegs: l.TSOMaxSegs, GROMaxSize: l.GROMaxSize, GSOIPv4MaxSize: l.GSOIPv4MaxSize,
		GROIPv4MaxSize: l.GROIPv4MaxSize, ProtoDown: l.ProtoDown, CarrierChanges: l.CarrierChanges,
		Address: l.Address, Broadcast: l.Broadcast, PermAddress: l.PermAddress, PhysPortID: l.PhysPortID,
		PhysSwitchID: l.PhysSwitchID, InfoData: l.InfoData, SlaveData: l.SlaveData, XDP: l.XDP, HasStats: l.Stats != nil}
	for i, v := range l.Stats {
		if i < len(r.Stats) {
			r.Stats[i] = int64(v)
		}
	}
	r.Speed, r.Duplex = linkSpeed(l.Name)
	return r
}

// linkSpeed is an interface's speed (Mb/s) and duplex (1 full, 0 half) as
// sysfs gives them (ethtool's), -1 where it does not (virtual, down,
// wireless).
func linkSpeed(name string) (speed, duplex int64) {
	speed, duplex = -1, -1
	if name == "" || strings.ContainsAny(name, "/") {
		return
	}
	if b, err := os.ReadFile("/sys/class/net/" + name + "/speed"); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && v > 0 {
			speed = v
		}
	}
	if b, err := os.ReadFile("/sys/class/net/" + name + "/duplex"); err == nil {
		switch strings.TrimSpace(string(b)) {
		case "full":
			duplex = 1
		case "half":
			duplex = 0
		}
	}
	return
}

// zswapEnabled reports whether zswap is on, as atop decides whether to show
// its zswap counters.
func zswapEnabled() bool {
	b, err := os.ReadFile("/sys/module/zswap/parameters/enabled")
	return err == nil && len(b) > 0 && b[0] == 'Y'
}

// isVirtual: a whole block device without /sys/block/NAME/device (loop, dm,
// md, zram...), as sysstat's is_device tells them (sar -b counts only the
// others); kept per name.
func (s *sysSampler) isVirtual(name string) bool {
	if v, ok := s.virtual[name]; ok {
		return v
	}
	_, err := os.Stat(filepath.Join("/sys/block", strings.ReplaceAll(name, "/", "!"), "device"))
	v := err != nil
	if s.virtual == nil {
		s.virtual = map[string]bool{}
	}
	s.virtual[name] = v
	return v
}
