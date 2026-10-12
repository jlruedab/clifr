package recorder

import (
	"os"
	"strings"

	"sosv/internal/store"
)

// sysSampler reads the system-wide counters behind uptime, vmstat, mpstat and
// iostat once per sample.
type sysSampler struct {
	warned map[string]bool
	part   map[string]bool // disk name -> is a partition
	sysfs  bool            // /sys describes the recorded machine
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
			r.log.Printf("system counters: %s: %v", what, err)
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
	b.Sys = row
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
