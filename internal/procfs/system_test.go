package procfs

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestSystemCounters(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"stat": "cpu  100 20 30 4000 50 6 7 8 9 10\ncpu0 60 10 20 2000 25 3 4 4 5 6\ncpu1 40 10 10 2000 25 3 3 4 4 4\n" +
			"intr 12345 0 8 0 0 0 0 0 0 0 350797 0 0 139 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n" +
			"ctxt 6519277388\nbtime 1790000000\nprocesses 1619393\nprocs_running 3\nprocs_blocked 1\nsoftirq 429280711 499684 30742721\n",
		"loadavg": "0.58 0.56 11.4 3/2232 1619373\n",
		"meminfo": "MemTotal:       63964024 kB\nMemFree:        34922868 kB\nMemAvailable:   49646160 kB\nBuffers:          721900 kB\n" +
			"Cached:         12812108 kB\nSwapCached:            0 kB\nSwapTotal:       8388604 kB\nSwapFree:        8388000 kB\n" +
			"Shmem:           1200424 kB\nSReclaimable:    1474496 kB\nHugePages_Total:       0\n",
		"vmstat": "nr_free_pages 8730717\npgpgin 9966704\npgpgout 17804165\npswpin 5\npswpout 6\npgfault 734874843\npgmajfault 32135\n" +
			"allocstall_dma 1\nallocstall_normal 2\npgsteal_kswapd 7\npgscan_kswapd 10\npgscan_kswapd_normal 5\npgscan_direct 3\n" +
			"pgscan_direct_throttle 99\npgscan_anon 50\npgscan_proactive 4\noom_kill 2\ncompact_stall 8\n",
		"diskstats": "   7       2 loop2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n" +
			" 259       0 nvme0n1 934 1 5498 15 20 2 300 40 3 13 55 7 8 900 10 11 12\n" +
			"   8       0 sda 10 0 80 5 0 0 0 0 0 5 5\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	os.WriteFile(filepath.Join(dir, "net", "sockstat"), []byte("sockets: used 1417\nTCP: inuse 41 orphan 1 tw 2 alloc 46 mem 1015\n"+
		"UDP: inuse 13 mem 884\nUDPLITE: inuse 0\nRAW: inuse 0\nFRAG: inuse 3 memory 4096\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "net", "sockstat6"), []byte("TCP6: inuse 4\nUDP6: inuse 4\nUDPLITE6: inuse 0\nRAW6: inuse 1\nFRAG6: inuse 0 memory 0\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "net", "snmp"), []byte("Ip: Forwarding DefaultTTL InReceives\nIp: 1 64 3850274\n"+
		"Tcp: RtoAlgorithm MaxConn CurrEstab\nTcp: 1 -1 36\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "net", "netstat"), []byte("TcpExt: SyncookiesSent ListenDrops\nTcpExt: 0 5\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "net", "snmp6"), []byte("Ip6InReceives                   	241\nIcmp6InMsgs  7\n"), 0o644)
	fs := New(dir)
	if c, err := fs.ReadNetCounters(); err != nil || fmt.Sprint(c) != "[{Ip IpForwarding 1} {Ip IpDefaultTTL 64} {Ip IpInReceives 3850274} "+
		"{Tcp TcpRtoAlgorithm 1} {Tcp TcpMaxConn -1} {Tcp TcpCurrEstab 36} {TcpExt TcpExtSyncookiesSent 0} {TcpExt TcpExtListenDrops 5} { Ip6InReceives 241} { Icmp6InMsgs 7}]" {
		t.Errorf("net counters = %v %v", c, err)
	}
	if s, err := fs.ReadSockStat(); err != nil || s != (SockStat{Used: 1417, TCPInUse: 41, TCPOrphan: 1, TCPTW: 2, TCPAlloc: 46, TCPMem: 1015,
		UDPInUse: 13, UDPMem: 884, FragInUse: 3, FragMemory: 4096, TCP6InUse: 4, UDP6InUse: 4, Raw6InUse: 1}) {
		t.Errorf("sockstat = %+v %v", s, err)
	}
	st, err := fs.ReadSysStat()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.CPUs) != 3 || st.CPUs[0].CPU != -1 || st.CPUs[2].CPU != 1 || st.CPUs[0].T != [10]uint64{100, 20, 30, 4000, 50, 6, 7, 8, 9, 10} {
		t.Errorf("cpus = %+v", st.CPUs)
	}
	if st.Intr != 12345 || st.Ctxt != 6519277388 || st.Forks != 1619393 || st.ProcsRunning != 3 || st.ProcsBlocked != 1 || st.SoftIRQ != 429280711 {
		t.Errorf("stat = %+v", st)
	}
	if l, err := fs.ReadLoadAvg(); err != nil || l != (LoadAvg{58, 56, 1140, 3, 2232}) {
		t.Errorf("loadavg = %+v %v", l, err)
	}
	m, err := fs.ReadMemInfo()
	if err != nil || m.Total != 63964024 || m.Free != 34922868 || m.Available != 49646160 || m.Cached != 12812108 ||
		m.SwapFree != 8388000 || m.Shmem != 1200424 || m.SReclaimable != 1474496 {
		t.Errorf("meminfo = %+v %v", m, err)
	}
	vmWant := VMStat{PgpgIn: 9966704, PgpgOut: 17804165, PswpIn: 5, PswpOut: 6, PgFault: 734874843, PgMajFault: 32135,
		AllocStall: 3, PgstealKswapd: 7, PgscanKswapd: 15, PgscanDirect: 3, PgscanProactive: 4, OOMKill: 2, CompactStall: 8,
		PgscanDirectThrottle: 99}
	if v, err := fs.ReadVMStat(); err != nil || v != vmWant {
		t.Errorf("vmstat = %+v %v", v, err)
	}
	ds, err := fs.ReadDiskStats()
	if err != nil || len(ds) != 3 {
		t.Fatalf("diskstats = %+v %v", ds, err)
	}
	want := DiskStat{Pos: 1, Major: 259, Minor: 0, Name: "nvme0n1", Rd: [4]uint64{934, 1, 5498, 15}, Wr: [4]uint64{20, 2, 300, 40},
		InFlight: 3, IOTicks: 13, TimeInQueue: 55, Dc: [4]uint64{7, 8, 900, 10}, FlIOs: 11, FlTicks: 12}
	if ds[1] != want {
		t.Errorf("nvme0n1 = %+v", ds[1])
	}
	if ds[0].Used() || !ds[1].Used() || !ds[2].Used() || ds[2].Rd[2] != 80 || ds[2].Dc[0] != 0 { // sda: an old kernel's 11 fields
		t.Errorf("used/short line: %+v", ds)
	}
	if _, err := New(t.TempDir()).ReadLoadAvg(); err == nil {
		t.Error("missing loadavg should fail")
	}
}

// The cost of one sample's system-wide reads on this machine.
func BenchmarkSystemCounters(b *testing.B) {
	fs := New("")
	if _, err := fs.ReadLoadAvg(); err != nil {
		b.Skip(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fs.ReadSysStat()
		fs.ReadLoadAvg()
		fs.ReadMemInfo()
		fs.ReadVMStat()
		fs.ReadDiskStats()
	}
}

func TestReadPressure(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "pressure"), 0o755)
	os.WriteFile(filepath.Join(dir, "pressure", "memory"), []byte("some avg10=0.00 avg60=0.00 avg300=0.00 total=432\n"+
		"full avg10=0.12 avg60=0.00 avg300=0.00 total=426\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "pressure", "cpu"), []byte("some avg10=1.50 avg60=0.40 avg300=0.10 total=354079129\n"), 0o644)
	f := FS{Root: dir}
	if p, err := f.ReadPressure("memory"); err != nil || p != (Pressure{Some: 432, Full: 426, HasFull: true, FullAvg: [3]int64{12, 0, 0}}) {
		t.Errorf("memory: %+v %v", p, err)
	}
	if p, err := f.ReadPressure("cpu"); err != nil || p != (Pressure{Some: 354079129, SomeAvg: [3]int64{150, 40, 10}}) {
		t.Errorf("cpu (no full line, before 5.13): %+v %v", p, err)
	}
	if _, err := f.ReadPressure("io"); !os.IsNotExist(err) {
		t.Errorf("a resource without a file: %v", err)
	}
}

// TestReadThreads: what atop adds up over the threads.
func TestReadThreads(t *testing.T) {
	dir := t.TempDir()
	stat := func(state byte, blkio int, nice, policy int) string {
		// pid (comm) state, then fields 4..41 and 42 (delayacct_blkio_ticks).
		f := make([]string, 49)
		for i := range f {
			f[i] = "0"
		}
		f[38] = strconv.Itoa(blkio)
		f[15], f[37] = strconv.Itoa(nice), strconv.Itoa(policy) // fields 19 and 41
		return "40 (worker) " + string(state) + " " + strings.Join(f, " ") + "\n"
	}
	for tid, v := range map[string][3]string{
		"40": {"100 2000 3\n", stat('S', 5, 0, 0), "voluntary_ctxt_switches:\t10\nnonvoluntary_ctxt_switches:\t2\n"},
		"41": {"50 500 1\n", stat('D', 7, -5, 0), "voluntary_ctxt_switches:\t4\nnonvoluntary_ctxt_switches:\t1\n"},
		"42": {"1 1 1\n", stat('I', 0, 0, 2), "voluntary_ctxt_switches:\t1\nnonvoluntary_ctxt_switches:\t0\n"},
	} {
		d := filepath.Join(dir, "40", "task", tid)
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "schedstat"), []byte(v[0]), 0o644)
		os.WriteFile(filepath.Join(d, "stat"), []byte(v[1]), 0o644)
		os.WriteFile(filepath.Join(d, "status"), []byte("Uid:\t0\t0\t0\t0\n"+v[2]), 0o644)
		if tid != "42" { // a thread without an io file (gone) is left out
			os.WriteFile(filepath.Join(d, "io"), []byte("rchar: 10\nwchar: 20\nsyscr: 1\nsyscw: 2\nread_bytes: 4096\nwrite_bytes: 8192\ncancelled_write_bytes: 512\n"), 0o644)
		}
	}
	f := FS{Root: dir}
	got, err := f.ReadThreads(40)
	want := Threads{RunDelayNS: 2501, BlkioTicks: 12, VolCtx: 15, NonVolCtx: 3, SleepI: 1, SleepU: 1, Idle: 1,
		IO: IO{RChar: 20, WChar: 40, ReadBytes: 8192, WriteBytes: 16384, CancelledWrite: 1024}, IOThreads: 2}
	prio := got.Prio
	sort.Slice(prio, func(i, j int) bool { return prio[i].TID < prio[j].TID })
	got.Prio = nil
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("threads: %+v %v, want %+v", got, err, want)
	}
	if fmt.Sprint(prio) != "[{40 0 0 false} {41 -5 0 false} {42 0 2 false}]" {
		t.Errorf("thread priorities: %v", prio)
	}
	// With a cache: a thread whose schedstat is unchanged keeps its values
	// (its stat and status are not read again), one that ran is re-read,
	// one gone is dropped.
	c := ThreadCache{}
	if _, err := f.ReadThreadsCached(40, c); err != nil || len(c) != 3 {
		t.Fatalf("first cached walk: %v, %d threads", err, len(c))
	}
	t41 := filepath.Join(dir, "40", "task", "41")
	os.WriteFile(filepath.Join(t41, "stat"), []byte(stat('R', 99, 0, 0)), 0o644)
	t40 := filepath.Join(dir, "40", "task", "40")
	os.WriteFile(filepath.Join(t40, "schedstat"), []byte("200 2100 4\n"), 0o644)
	os.WriteFile(filepath.Join(t40, "stat"), []byte(stat('R', 6, 0, 0)), 0o644)
	os.RemoveAll(filepath.Join(dir, "40", "task", "42"))
	got, err = f.ReadThreadsCached(40, c)
	if err != nil || got.Run != 1 || got.SleepU != 1 || got.SleepI != 0 || got.Idle != 0 || got.BlkioTicks != 13 ||
		got.RunDelayNS != 2600 || len(c) != 2 {
		t.Errorf("cached walk: %+v %v, %d threads cached", got, err, len(c))
	}
	sort.Slice(got.Prio, func(i, j int) bool { return got.Prio[i].TID < got.Prio[j].TID })
	if fmt.Sprint(got.Prio) != "[{40 0 0 false} {41 -5 0 true}]" {
		t.Errorf("cached thread priorities: %v", got.Prio)
	}
	// SkipIO: a thread that ran keeps its io values; without it they are read.
	os.WriteFile(filepath.Join(t40, "schedstat"), []byte("300 2200 5\n"), 0o644)
	os.WriteFile(filepath.Join(t40, "io"), []byte("rchar: 10\nwchar: 20\nread_bytes: 1\nwrite_bytes: 1\ncancelled_write_bytes: 0\n"), 0o644)
	c.SkipIO(true)
	if got, err = f.ReadThreadsCached(40, c); err != nil || got.IO.ReadBytes != 8192 || len(c) != 2 {
		t.Errorf("SkipIO: %+v %v, %d cached", got.IO, err, len(c))
	}
	os.WriteFile(filepath.Join(t40, "schedstat"), []byte("400 2300 6\n"), 0o644)
	if got, err = f.ReadThreadsCached(40, c); err != nil || got.IO.ReadBytes != 4097 {
		t.Errorf("after SkipIO: %+v %v", got.IO, err)
	}
	os.WriteFile(filepath.Join(t40, "io"), []byte("rchar: 10\nwchar: 20\nsyscr: 1\nsyscw: 2\nread_bytes: 4096\nwrite_bytes: 8192\ncancelled_write_bytes: 512\n"), 0o644)
	if _, err := f.ReadThreads(41); err == nil {
		t.Error("no such process: no error")
	}
	if io, err := f.ReadThreadIO(40); err != nil || io.WriteBytes != 8192 || io.CancelledWrite != 512 {
		t.Errorf("main thread's io: %+v %v", io, err)
	}
}

// TestParseStatusSegments: atop -m's segment sizes and the real gid.
func TestParseStatusSegments(t *testing.T) {
	s, err := ParseStatus([]byte("Uid:\t1000\t1000\t1000\t1000\nGid:\t100\t101\t101\t101\nVmData:\t  4096 kB\n" +
		"VmStk:\t   132 kB\nVmExe:\t    24 kB\nVmLib:\t  2048 kB\nVmSwap:\t     8 kB\n"))
	if err != nil || s.RGID != 100 || s.VmDataK != 4096 || s.VmStkK != 132 || s.VmExeK != 24 || s.VmLibK != 2048 || s.VmSwapK != 8 {
		t.Errorf("%+v %v", s, err)
	}
}

// TestSarInputs: schema 14's softnet_stat and cpuinfo readers.
func TestSarInputs(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	// 13 fields (Linux 6.x: backlog and the CPU), then an old kernel's 11.
	os.WriteFile(filepath.Join(dir, "net", "softnet_stat"), []byte(
		"0001e240 00000002 0000000a 00000000 00000000 00000000 00000000 00000000 00000000 00000005 00000001 00000003 00000004\n"+
			"000000ff 00000000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "cpuinfo"), []byte("processor\t: 0\ncpu MHz\t\t: 2995.200\n\nprocessor\t: 1\ncpu MHz\t\t: 800.057\n"), 0o644)
	f := FS{Root: dir}
	sn, err := f.ReadSoftnet()
	if err != nil || len(sn) != 2 || sn[0] != (Softnet{CPU: 4, Processed: 123456, Dropped: 2, Squeezed: 10, RPS: 5, Flow: 1, Backlog: 3, HasCPU: true}) ||
		sn[1] != (Softnet{CPU: 1, Processed: 255, Squeezed: 1}) {
		t.Errorf("softnet: %+v %v", sn, err)
	}
	mhz, err := f.ReadCPUFreq()
	if err != nil || mhz[0] != 299520 || mhz[1] != 80005 { // sadc: whole*100 + the fraction's digits / 10
		t.Errorf("cpu MHz: %v %v", mhz, err)
	}
}

// TestParseCtxSwitches: the per-thread walk's two status lines, as
// ParseStatus reads them.
func TestParseCtxSwitches(t *testing.T) {
	b := []byte("Name:\tworker\nState:\tS (sleeping)\nUid:\t0\t0\t0\t0\nvoluntary_ctxt_switches:\t1234\nnonvoluntary_ctxt_switches:\t56\n")
	st, _ := ParseStatus(b)
	if v, n := parseCtxSwitches(b); v != 1234 || n != 56 || v != st.VolCtx || n != st.NonVolCtx {
		t.Errorf("parseCtxSwitches: %d %d, ParseStatus %d %d", v, n, st.VolCtx, st.NonVolCtx)
	}
	if v, n := parseCtxSwitches([]byte("Name:\tx\n")); v != 0 || n != 0 {
		t.Errorf("no such lines: %d %d", v, n)
	}
}
