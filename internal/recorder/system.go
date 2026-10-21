package recorder

import (
	"os"
	"reflect"
	"strings"

	"clifr/internal/rtnl"
	"clifr/internal/store"
)

// sysSampler reads the system-wide counters behind uptime, vmstat, mpstat and
// iostat once per sample.
type sysSampler struct {
	warned map[string]bool
	part   map[string]bool // disk name -> is a partition
	sysfs  bool            // /sys describes the recorded machine
	// Protocol counters as last written, and when all of them were.
	netLast map[string]int64
	netFull int64
	// Network interfaces likewise (by ifindex; the row without TS).
	linkLast map[int]store.LinkRow
	linkFull int64
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
	row := &store.SysSample{TS: ts, UptimeMS: ts - r.boot, ProcsRunning: st.ProcsRunning, ProcsBlocked: st.ProcsBlocked,
		Intr: int64(st.Intr), Ctxt: int64(st.Ctxt), Forks: int64(st.Forks), SoftIRQ: int64(st.SoftIRQ)}
	for _, c := range st.CPUs {
		cs := store.CPUSample{TS: ts, CPU: c.CPU}
		for i, v := range c.T {
			cs.T[i] = int64(v)
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
	}
	if v, err := r.fs.ReadVMStat(); !fail("vmstat", err) {
		row.PgpgIn, row.PgpgOut, row.PswpIn, row.PswpOut = int64(v.PgpgIn), int64(v.PgpgOut), int64(v.PswpIn), int64(v.PswpOut)
		row.PgFault, row.PgMajFault = int64(v.PgFault), int64(v.PgMajFault)
	}
	if k, err := r.fs.ReadSockStat(); !fail("net/sockstat", err) {
		row.SockUsed, row.TCPInUse, row.TCPOrphan, row.TCPTW, row.TCPAlloc, row.TCPMem = int64(k.Used), int64(k.TCPInUse), int64(k.TCPOrphan), int64(k.TCPTW), int64(k.TCPAlloc), int64(k.TCPMem)
		row.UDPInUse, row.UDPMem, row.UDPLiteInUse, row.RawInUse, row.FragInUse = int64(k.UDPInUse), int64(k.UDPMem), int64(k.UDPLiteInUse), int64(k.RawInUse), int64(k.FragInUse)
		row.FragMemory, row.TCP6InUse, row.UDP6InUse, row.UDPLite6InUse = int64(k.FragMemory), int64(k.TCP6InUse), int64(k.UDP6InUse), int64(k.UDPLite6InUse)
		row.Raw6InUse, row.Frag6InUse, row.Frag6Memory = int64(k.Raw6InUse), int64(k.Frag6InUse), int64(k.Frag6Memory)
	}
	b.Sys = append(b.Sys, *row)
	if s.sysfs { // rtnetlink describes this machine, not a --proc-root fixture
		if links, err := rtnl.Dump(); !fail("rtnetlink links", err) {
			s.addLinks(ts, links, b)
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
	disks, err := r.fs.ReadDiskStats()
	if fail("diskstats", err) {
		return
	}
	for i := range disks {
		d := &disks[i]
		if !d.Used() {
			continue
		}
		ds := store.DiskSample{TS: ts, Major: d.Major, Minor: d.Minor, Name: d.Name, Part: s.isPart(d.Name)}
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
	return r
}
