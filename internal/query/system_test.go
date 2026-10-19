package query

import (
	"path/filepath"
	"strings"
	"testing"

	"clifr/internal/store"
)

// Two samples 10 s apart on a machine that booted 100 s before the first.
func sysDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "s.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	base := int64(1_790_000_000_000)
	batch := func(ts, up int64, sys store.SysSample, all, cpu0 [10]int64, disk [17]int64) *store.Batch {
		sys.TS, sys.UptimeMS = ts, up
		return &store.Batch{Sample: store.Sample{TS: ts}, Sys: []store.SysSample{sys},
			CPUs: []store.CPUSample{{TS: ts, CPU: -1, T: all}, {TS: ts, CPU: 0, T: cpu0}},
			Disks: []store.DiskSample{{TS: ts, Name: "sda", V: disk},
				{TS: ts, Name: "sda1", Part: true, V: disk}}}
	}
	mem := store.SysSample{MemFree: 5000, Buffers: 300, Cached: 2000, SReclaimable: 500, SwapTotal: 1000, SwapFree: 900}
	a := mem
	a.Load1, a.Load5, a.Load15, a.ProcsRunning = 150, 75, 5, 3
	a.Intr, a.Ctxt, a.PgpgIn, a.PgpgOut, a.PswpIn = 10_000, 20_000, 1000, 2000, 100
	b := a
	b.ProcsBlocked, b.Intr, b.Ctxt, b.PgpgIn, b.PgpgOut, b.PswpIn = 2, 15_000, 50_000, 1500, 2100, 150
	for _, x := range []*store.Batch{
		batch(base, 100_000, a, [10]int64{1000, 0, 500, 8000, 500}, [10]int64{1000, 0, 500, 8000, 500},
			[17]int64{100, 0, 2000, 400, 50, 50, 4000, 1000, 0, 0, 0, 0, 0, 5000, 2000, 10, 20}),
		// in 10 s: 400 ticks user (100 of them guest), 100 system, 400 idle, 50 iowait, 30 irq, 20 softirq
		batch(base+10_000, 110_000, b, [10]int64{1400, 0, 600, 8400, 550, 30, 20, 0, 100}, [10]int64{1400, 0, 600, 8400, 550, 30, 20, 0, 100},
			[17]int64{300, 0, 6000, 800, 150, 150, 8000, 3000, 0, 0, 0, 0, 0, 7000, 5000, 20, 60}),
	} {
		if err := db.Write(x); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func out(print func(sb *strings.Builder)) string {
	var sb strings.Builder
	print(&sb)
	return sb.String()
}

func TestSystemReports(t *testing.T) {
	db := sysDB(t)
	base := int64(1_790_000_000_000)

	boot, err := SysSpans(db, Window{At: base + 5000}, 0)
	if err != nil || len(boot) != 1 || boot[0] != (Span{0, base}) {
		t.Fatalf("spans at = %v %v", boot, err)
	}
	rng, err := SysSpans(db, Window{From: base, To: base + 60_000}, 0)
	if err != nil || len(rng) != 1 || rng[0] != (Span{base, base + 10_000}) {
		t.Fatalf("spans range = %v %v", rng, err)
	}
	if _, err := SysSpans(db, Window{From: base, To: base + 60_000}, 20_000); err == nil {
		t.Error("a step longer than the recording should leave no interval")
	}

	up, _ := Uptime(db, boot)
	if got := out(func(sb *strings.Builder) { PrintUptime(sb, up) }); !strings.HasSuffix(got, " up 1 min,  load average: 1.50, 0.75, 0.05\n") {
		t.Errorf("uptime = %q", got)
	}

	// Since boot (100 s): rates are the counters over the uptime.
	vm, _ := VMStat(db, boot)
	want := VMStatRow{TS: base, Time: FormatMS(base), SinceBoot: true, R: 2, Swpd: 100, Free: 5000, Buff: 300, Cache: 2500,
		SI: 4, BI: 10, BO: 20, In: 100, CS: 200, US: 10, SY: 5, ID: 80, WA: 5}
	if len(vm) != 1 || vm[0] != want {
		t.Errorf("vmstat since boot = %+v", vm)
	}
	// The 10 s interval. vmstat's shares leave guest time out of the total.
	vm, _ = VMStat(db, rng)
	want = VMStatRow{TS: base + 10_000, Time: FormatMS(base + 10_000), R: 2, B: 2, Swpd: 100, Free: 5000, Buff: 300, Cache: 2500,
		SI: 20, BI: 50, BO: 10, In: 500, CS: 3000, US: 40, SY: 15, ID: 40, WA: 5, GU: 10}
	if len(vm) != 1 || vm[0] != want {
		t.Errorf("vmstat interval = %+v", vm)
	}
	line := strings.Split(out(func(sb *strings.Builder) { PrintVMStat(sb, vm) }), "\n")[2]
	if line != " 2  2    100   5000    300   2500   20    0    50    10  500 3000 40 15 40  5  0 10" {
		t.Errorf("vmstat line = %q", line)
	}

	mp, err := MPStat(db, rng, "ALL")
	if err != nil || len(mp) != 2 || mp[0].CPU != "all" || mp[1].CPU != "0" {
		t.Fatalf("mpstat = %+v %v", mp, err)
	}
	// 1000 ticks: 300 user without guest, 100 guest, 100 system, 50 iowait, 30 irq, 20 softirq, 400 idle
	if m := mp[0]; m.Usr != 30 || m.Guest != 10 || m.Sys != 10 || m.IOWait != 5 || m.IRQ != 3 || m.Soft != 2 || m.Idle != 40 {
		t.Errorf("mpstat all = %+v", m)
	}
	if only, _ := MPStat(db, rng, ""); len(only) != 1 {
		t.Errorf("mpstat default = %+v", only)
	}
	if _, err := MPStat(db, rng, "x"); err == nil {
		t.Error("bad CPU list should fail")
	}
	head := strings.Split(out(func(sb *strings.Builder) { PrintMPStat(sb, mp) }), "\n")[1]
	if !strings.HasSuffix(head, "     all   30.00    0.00   10.00    5.00    3.00    2.00    0.00   10.00    0.00   40.00") {
		t.Errorf("mpstat line = %q", head)
	}

	io, err := IOStat(db, rng, false)
	if err != nil || len(io) != 1 || len(io[0].Devices) != 1 {
		t.Fatalf("iostat = %+v %v", io, err)
	}
	d := io[0].Devices[0]
	// 200 reads of 4000 sectors in 400 ms; 100 writes (100 merged) of 4000 sectors in 2000 ms; busy 2 of 10 s
	if d.Device != "sda" || d.TPS != 30 || d.RS != 20 || d.RKBS != 200 || d.RAwait != 2 || d.RAreqSz != 10 || d.KBRead != 2000 ||
		d.WS != 10 || d.WKBS != 200 || d.WRQMS != 10 || d.WRQMPct != 50 || d.WAwait != 20 || d.WAreqSz != 20 ||
		d.FS != 1 || d.FAwait != 4 || d.AquSz != 0.3 || d.Util != 20 {
		t.Errorf("iostat sda = %+v", d)
	}
	if c := io[0].CPU; c.User != 40 || c.System != 15 || c.IOWait != 5 || c.Idle != 40 {
		t.Errorf("iostat avg-cpu = %+v", c)
	}
	if withParts, _ := IOStat(db, rng, true); len(withParts[0].Devices) != 2 {
		t.Errorf("iostat -p = %+v", withParts[0].Devices)
	}
	ext := strings.Split(out(func(sb *strings.Builder) { PrintIOStat(sb, io, true, true) }), "\n")[1]
	if !strings.HasPrefix(ext, "sda             20.00    200.00     0.00   0.00    2.00    10.00   10.00    200.00    10.00  50.00   20.00    20.00") ||
		!strings.HasSuffix(ext, "    1.00    4.00    0.30  20.00") {
		t.Errorf("iostat -x line = %q", ext)
	}
}
