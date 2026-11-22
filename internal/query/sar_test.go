package query

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

var updateSar = flag.Bool("update-sar", false, "rewrite testdata/sar/*.golden")

// TestSarScreens: sar -f's layout from a small recording: a boot inside
// the window (LINUX RESTART, its first record at the next multiple), two
// CPUs, counters, interfaces (one re-created), the sysctl and NFS
// snapshots; per release (golden files; -update-sar rewrites them).
func TestSarScreens(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.UTC
	base := int64(1_790_000_400_000) // 2026-09-21 13:00:00 UTC, a multiple of 5 min
	boot1 := base - 3600_000
	boot2 := base + 7*60_000 + 30_000 // a reboot between 13:07 and 13:08
	var batches []*store.Batch
	for m := 0; m <= 16; m++ {
		ts := base + int64(m)*60_000 + 1000 // samples a second after each minute
		boot := boot1
		if ts > boot2 {
			boot = boot2
		}
		k := ts - boot // ms since boot: counters grow with it
		up := k / 1000
		b := &store.Batch{Sample: store.Sample{TS: ts}}
		b.Sys = []store.SysSample{{TS: ts, UptimeMS: k, Load1: int(20 + m), Load5: 15, Load15: 10, Runnable: 3, Threads: 300 + m,
			ProcsBlocked: m % 2, Intr: up * 250, Ctxt: up * 900, Forks: up * 3, MemTotal: 8126784, MemFree: 7000000 - int64(m)*1000,
			MemAvailable: 7300000, Buffers: 4184, Cached: 400000 + int64(m)*500, SwapCached: 100, Active: 290000, Inactive: 260000,
			SwapTotal: 2097148, SwapFree: 2090000, Dirty: int64(m * 8), Slab: 90000, PswpIn: up / 50, PswpOut: up / 40,
			SockUsed: 180, TCPInUse: 5, TCPTW: int64(m % 3), UDPInUse: 4, RawInUse: 0, TCP6InUse: 2, UDP6InUse: 3}}
		for c := 0; c < 2; c++ {
			u := up * int64(10+c*5)
			b.CPUs = append(b.CPUs, store.CPUSample{TS: ts, CPU: c, T: [10]int64{u, up, up * 3, up*100 - u - up*4, up / 2, 0, up / 4, 0, 0, 0}})
		}
		b.CPUs = append(b.CPUs, store.CPUSample{TS: ts, CPU: -1, T: [10]int64{up * 25, up * 2, up * 6, up*200 - up*33, up, 0, up / 2, 0, 0, 0}})
		for i, n := range []string{"IpInReceives", "IpInDelivers", "IpOutRequests", "TcpActiveOpens", "TcpPassiveOpens", "TcpInSegs",
			"TcpOutSegs", "TcpRetransSegs", "UdpInDatagrams", "UdpOutDatagrams", "Ip6InReceives", "Icmp6InMsgs"} {
			b.NetCounters = append(b.NetCounters, store.NetCounter{TS: ts, Pos: i, Name: n, Value: up * int64(i+1)})
		}
		lo := store.LinkRow{TS: ts, Index: 1, Name: "lo", HasStats: true}
		lo.Stats[0], lo.Stats[1], lo.Stats[2], lo.Stats[3] = up*5, up*5, up*600, up*600
		eth := store.LinkRow{TS: ts, Index: 2, Name: "eth0", HasStats: true, Speed: 1000, Duplex: 1}
		eth.Stats[0], eth.Stats[1], eth.Stats[2], eth.Stats[3], eth.Stats[6] = up*40, up*30, up*60000, up*9000, up/30
		vnet := store.LinkRow{TS: ts, Index: 7, Name: "vnet0", HasStats: true}
		if m >= 12 { // re-created: a new index, counting from zero
			vnet.Index = 9
			vnet.Stats[0], vnet.Stats[1] = int64(m-12)*100, int64(m-12)*50
		} else {
			vnet.Stats[0], vnet.Stats[1] = up*8, up*4
		}
		b.Links = []store.LinkRow{lo, eth, vnet}
		if m%5 == 0 || m == 8 {
			b.Snapshots = append(b.Snapshots,
				store.SnapshotRow{TS: ts, Source: "sysctl", Key: "fs.dentry-state", Pos: 0, Full: true, Line: "fs.dentry-state = 40000\t" + itoa(int64(17000+m*10)) + "\t45\t0\t1000\t0"},
				store.SnapshotRow{TS: ts, Source: "sysctl", Key: "fs.file-nr", Pos: 1, Full: true, Line: "fs.file-nr = " + itoa(int64(1800+m)) + "\t0\t9223372036854775807"},
				store.SnapshotRow{TS: ts, Source: "sysctl", Key: "fs.inode-state", Pos: 2, Full: true, Line: "fs.inode-state = 40000\t200\t0\t0\t0\t0\t0"},
				store.SnapshotRow{TS: ts, Source: "sysctl", Key: "kernel.pty.nr", Pos: 3, Full: true, Line: "kernel.pty.nr = 2"},
				store.SnapshotRow{TS: ts, Source: "rpc/nfs", Key: "rpc", Pos: 0, Full: true, Line: "rpc " + itoa(int64(m*100)) + " 1 " + itoa(int64(m*100))},
				store.SnapshotRow{TS: ts, Source: "rpc/nfs", Key: "proc4", Pos: 1, Full: true,
					Line: "proc4 59 0 " + itoa(int64(m*7)) + " " + itoa(int64(m*3)) + " 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 " + itoa(int64(m*20)) + " " + itoa(int64(m*40))})
		}
		batches = append(batches, b)
	}
	rec := testrec.Open(t, []string{"hostname", "web01", "uname_sysname", "Linux", "uname_release", "5.14.0-687.el9.x86_64",
		"uname_machine", "x86_64", "boot_ms", itoa(boot1), "boot_id", "b1"}, batches...)
	all := []SarAct{{Key: "cpu", All: true, CPUs: []int{SarAllCPU}}}
	for _, k := range []string{"pcsw", "irq", "swap", "mem", "swapmem", "ktables", "queue", "netdev", "netedev", "nfs", "sock",
		"ip", "tcp", "etcp", "udp", "sock6", "ip6", "icmp6"} {
		all = append(all, SarAct{Key: k})
	}
	for _, c := range []struct {
		name string
		o    SarOpts
	}{
		{"12.7-u", SarOpts{Acts: []SarAct{{Key: "cpu"}}, StepMS: 300_000}},
		{"12.7-all-60", SarOpts{Acts: all, StepMS: 60_000}},
		{"11.7-all-300", SarOpts{Acts: all, StepMS: 300_000, Version: "11.7"}},
		{"12.7-P1", SarOpts{Acts: []SarAct{{Key: "cpu", CPUs: []int{1}}}, StepMS: 120_000}},
	} {
		d, err := Sar(rec, base, base+16*60_000+5000, c.o)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		PrintSar(&b, d, c.o)
		golden := filepath.Join("testdata", "sar", c.name+".golden")
		if *updateSar {
			os.MkdirAll(filepath.Dir(golden), 0o755)
			if err := os.WriteFile(golden, b.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if b.String() != string(want) {
			t.Errorf("%s:\n%s\nwant:\n%s", c.name, b.String(), want)
		}
	}
}
