package query

import (
	"flag"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

var updateAtop = flag.Bool("update-atop", false, "rewrite testdata/atop/*.golden")

// TestAtopScreen: atop's screen since boot, 2.12.1's and 2.7.1's, from a
// small recording. The golden files were checked against the real atop's
// formats (bench/results/atop-captures-20261121); clifr verify compares
// with the real tool on recorded hosts.
func TestAtopScreen(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.UTC
	base := int64(1_790_000_000_000)
	boot := base - 3*3600_000 - 61_500 // up 3h1m1.5s at base
	tk := func(sec int64) int64 { return sec * 100 }
	all := [10]int64{tk(2000), tk(100), tk(1500), tk(38000), tk(300), tk(40), tk(60), 0, tk(500), 0}
	cpu0 := [10]int64{tk(1500), tk(80), tk(1000), tk(17000), tk(200), tk(30), tk(40), 0, tk(500), 0}
	cpu1 := [10]int64{tk(500), tk(20), tk(500), tk(21000), tk(100), tk(10), tk(20), 0, 0, 0}
	proc := func(id int64, pid int, comm string, start int64) store.ProcRow {
		return store.ProcRow{ID: id, PID: pid, StartTime: start, PPID: 1, Comm: comm, Cmdline: "/usr/bin/" + comm, FirstSeen: start, Source: "sample"}
	}
	db := testrec.Open(t, []string{"hostname", "web01.example.com", "boot_ms", itoa(boot), "boot_id", "b1"},
		&store.Batch{Sample: store.Sample{TS: base},
			Sys: []store.SysSample{{TS: base, UptimeMS: base - boot, Load1: 152, Load5: 98, Load15: 61, Intr: 98_765_432, Ctxt: 1_234_567_890,
				MemTotal: 16_303_604, MemFree: 9_123_456, MemAvailable: 13_000_000, Buffers: 210_000, Cached: 3_500_000,
				SwapTotal: 4_194_300, SwapFree: 4_100_000, SwapCached: 1024, Dirty: 300, Shmem: 450_000, Slab: 600_000,
				SReclaimable: 400_000, PgpgIn: 1_234_567, PgpgOut: 7_654_321, PswpIn: 12, PswpOut: 345,
				CommittedAS: 7_000_000, CommitLimit: 12_345_678, PageTables: 45_000, AnonHugePages: 204_800, OOMKill: 1,
				PSI: true, PSICPUSome: 3_000_000_000, PSIMemSome: 10_000_000, PSIIOSome: 900_000_000, PSIIOFull: 500_000_000,
				PSICPUAvg: [3]int64{120, 80, 40}}},
			CPUs: []store.CPUSample{{TS: base, CPU: -1, T: all}, {TS: base, CPU: 0, T: cpu0}, {TS: base, CPU: 1, T: cpu1}},
			Disks: []store.DiskSample{
				{TS: base, Major: 8, Minor: 0, Name: "sda", V: [17]int64{0: 123_456, 4: 654_321, 13: 1_800_000}},
				{TS: base, Major: 8, Minor: 1, Name: "sda1", Part: true, V: [17]int64{0: 1000, 4: 2000, 13: 900}},
				{TS: base, Major: 253, Minor: 0, Name: "dm-0", V: [17]int64{0: 100_000, 4: 600_000, 13: 1_700_000}},
				{TS: base, Major: 7, Minor: 0, Name: "loop0", V: [17]int64{0: 50, 13: 10}}},
			BlockDevs: []store.BlockDevRow{{TS: base, Name: "dm-0", Maj: 253, DMName: "vg_system-lv_root"}},
			NetCounters: []store.NetCounter{
				{TS: base, Name: "TcpInSegs", Value: 9_876_543}, {TS: base, Name: "TcpOutSegs", Value: 8_765_432},
				{TS: base, Name: "UdpInDatagrams", Value: 4321}, {TS: base, Name: "UdpOutDatagrams", Value: 1234},
				{TS: base, Name: "IpInReceives", Value: 9_990_000}, {TS: base, Name: "IpOutRequests", Value: 8_880_000},
				{TS: base, Name: "IpInDelivers", Value: 9_980_000}},
			Links: []store.LinkRow{
				{TS: base, Index: 1, Name: "lo", HasStats: true, Speed: -1, Duplex: -1, Stats: [25]int64{0: 5000, 1: 5000, 2: 900_000, 3: 900_000}},
				{TS: base, Index: 2, Name: "enp1s0", HasStats: true, Speed: 1000, Duplex: 1, Stats: [25]int64{0: 9_000_000, 1: 7_000_000, 2: 12_000_000_000, 3: 3_000_000_000}},
				{TS: base, Index: 3, Name: "docker0", HasStats: true, Speed: -1, Duplex: -1}},
			Snapshots: []store.SnapshotRow{{TS: base, Source: "sysctl", Key: "kernel.pid_max", Pos: 0, Full: true, Line: "kernel.pid_max = 4194304"},
				{TS: base, Source: "hostname", Key: "web01.example.com", Pos: 0, Full: true, Line: "web01.example.com"}},
			ProcInserts: []store.ProcRow{proc(1, 1, "systemd", boot+500), proc(2, 812, "postgres", boot+20_000),
				proc(3, 2045, "a-very-long-command-name", boot+60_000), proc(4, 15, "kworker/1:0-events", boot+100)},
			ProcSamples: []store.ProcSample{
				{ProcID: 1, TS: base, State: "S", Threads: 1, CPUTicks: tk(95), STimeTicks: tk(60), RSSKB: 13_000, RSSStatKB: 12_800,
					VSZKB: 171_000, ReadBytes: 300_000_000, WriteBytes: 90_000_000, CancelledWrite: 10_000_000, WaitNS: 2_500_000_000, RunDelayNS: 2_500_000_000,
					ThrSleepI: 1, VolCtx: 900, NonVolCtx: 30, VolCtxAll: 900, NonVolCtxAll: 30},
				{ProcID: 2, TS: base, State: "S", Threads: 8, CPUTicks: tk(6100), STimeTicks: tk(1700), RSSKB: 2_100_000, RSSStatKB: 2_000_000,
					VSZKB: 9_000_000, ReadBytes: 5_000_000_000, WriteBytes: 7_000_000_000, BlkioTicks: tk(42), WaitNS: 1_000_000_000, RunDelayNS: 9_870_000_000,
					BlkioAllTicks: tk(55), ThrSleepI: 6, ThrSleepU: 1, ThrIdle: 1, VolCtx: 5000, NonVolCtx: 70, VolCtxAll: 40_000, NonVolCtxAll: 900},
				{ProcID: 3, TS: base, State: "R", Threads: 1, CPUTicks: tk(6100), STimeTicks: tk(100), RSSStatKB: 900, VSZKB: 4000, CPU: 1, ThrRun: 1},
				{ProcID: 4, TS: base, State: "I", Threads: 1, CPUTicks: 7, STimeTicks: 7, ThrIdle: 1}}},
		// 10 s later: postgres busy and growing, the long command gone.
		&store.Batch{Sample: store.Sample{TS: base + 10_000},
			Sys: []store.SysSample{{TS: base + 10_000, UptimeMS: base + 10_000 - boot, Load1: 160, Load5: 99, Load15: 61,
				Intr: 98_775_432, Ctxt: 1_234_667_890, MemTotal: 16_303_604, MemFree: 9_000_000, MemAvailable: 12_900_000,
				Buffers: 210_000, Cached: 3_500_100, SwapTotal: 4_194_300, SwapFree: 4_100_000, SwapCached: 1024, Dirty: 500,
				Shmem: 450_000, Slab: 600_000, SReclaimable: 400_000, PgpgIn: 1_234_667, PgpgOut: 7_655_321, PswpIn: 12,
				PswpOut: 345, CommittedAS: 7_100_000, CommitLimit: 12_345_678, PageTables: 45_100, AnonHugePages: 204_800,
				OOMKill: 1, PSI: true, PSICPUSome: 3_002_000_000, PSIMemSome: 10_000_000, PSIIOSome: 900_100_000,
				PSIIOFull: 500_050_000, PSICPUAvg: [3]int64{150, 90, 41}}},
			CPUs: []store.CPUSample{
				{TS: base + 10_000, CPU: -1, T: [10]int64{tk(2006), tk(100), tk(1504), tk(38009), tk(301), tk(40), tk(60), 0, tk(500), 0}},
				{TS: base + 10_000, CPU: 0, T: [10]int64{tk(1506), tk(80), tk(1004), tk(17000), tk(201), tk(30), tk(40), 0, tk(500), 0}},
				{TS: base + 10_000, CPU: 1, T: [10]int64{tk(500), tk(20), tk(500), tk(21009), tk(100), tk(10), tk(20), 0, 0, 0}}},
			Disks: []store.DiskSample{
				{TS: base + 10_000, Major: 8, Minor: 0, Name: "sda", V: [17]int64{0: 123_456, 4: 654_521, 13: 1_800_400}},
				{TS: base + 10_000, Major: 253, Minor: 0, Name: "dm-0", V: [17]int64{0: 100_000, 4: 600_190, 13: 1_700_380}}},
			NetCounters: []store.NetCounter{
				{TS: base + 10_000, Name: "TcpInSegs", Value: 9_877_543}, {TS: base + 10_000, Name: "TcpOutSegs", Value: 8_766_032},
				{TS: base + 10_000, Name: "IpInReceives", Value: 9_991_000}, {TS: base + 10_000, Name: "IpOutRequests", Value: 8_880_600},
				{TS: base + 10_000, Name: "IpInDelivers", Value: 9_981_000}},
			Links: []store.LinkRow{
				{TS: base + 10_000, Index: 1, Name: "lo", HasStats: true, Speed: -1, Duplex: -1, Stats: [25]int64{0: 5000, 1: 5000, 2: 900_000, 3: 900_000}},
				{TS: base + 10_000, Index: 2, Name: "enp1s0", HasStats: true, Speed: 1000, Duplex: 1,
					Stats: [25]int64{0: 9_001_000, 1: 7_000_600, 2: 12_100_000_000, 3: 3_001_000_000}},
				{TS: base + 10_000, Index: 3, Name: "docker0", HasStats: true, Speed: -1, Duplex: -1}},
			ProcCloses: []store.Close{{ID: 3, LastSeen: base + 5000, Ended: &[]int64{base + 5000}[0]}},
			ProcSamples: []store.ProcSample{
				{ProcID: 2, TS: base + 10_000, State: "R", Threads: 8, CPUTicks: tk(6112), STimeTicks: tk(1703), RSSKB: 2_110_000,
					RSSStatKB: 2_010_240, VSZKB: 9_000_000, ReadBytes: 5_000_000_000, WriteBytes: 7_010_000_000, BlkioTicks: tk(42),
					WaitNS: 1_000_000_000, RunDelayNS: 9_920_000_000,
					BlkioAllTicks: tk(57), ThrRun: 2, ThrSleepI: 5, ThrIdle: 1, VolCtx: 5100, NonVolCtx: 75, VolCtxAll: 41_500, NonVolCtxAll: 960}}})
	for _, v := range []struct {
		name     string
		v271     bool
		interval bool
	}{{"atop-2.12.1", false, false}, {"atop-2.7.1", true, false}, {"atop-2.12.1-interval", false, true}} {
		a, err := AtopSysAt(db, base+1500)
		if v.interval {
			a, err = AtopIntervalAt(db, base+1500, base+11_500)
		}
		if err != nil {
			t.Fatal(err)
		}
		a.V271 = v.v271
		var b strings.Builder
		PrintAtopSys(&b, a)
		PrintAtopProcs(&b, a)
		path := "testdata/atop/" + v.name + ".golden"
		if *updateAtop {
			os.MkdirAll("testdata/atop", 0o755)
			if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if b.String() != string(want) {
			t.Errorf("%s:\n got:\n%s\nwant:\n%s", v.name, b.String(), want)
		}
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
