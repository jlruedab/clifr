package procfs

import (
	"fmt"
	"os"
	"path/filepath"
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
		"vmstat": "nr_free_pages 8730717\npgpgin 9966704\npgpgout 17804165\npswpin 5\npswpout 6\npgfault 734874843\npgmajfault 32135\n",
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
	if c, err := fs.ReadNetCounters(); err != nil || fmt.Sprint(c) != "[{IpForwarding 1} {IpDefaultTTL 64} {IpInReceives 3850274} "+
		"{TcpRtoAlgorithm 1} {TcpMaxConn -1} {TcpCurrEstab 36} {TcpExtSyncookiesSent 0} {TcpExtListenDrops 5} {Ip6InReceives 241} {Icmp6InMsgs 7}]" {
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
	if v, err := fs.ReadVMStat(); err != nil || v != (VMStat{9966704, 17804165, 5, 6, 734874843, 32135}) {
		t.Errorf("vmstat = %+v %v", v, err)
	}
	ds, err := fs.ReadDiskStats()
	if err != nil || len(ds) != 3 {
		t.Fatalf("diskstats = %+v %v", ds, err)
	}
	want := DiskStat{Major: 259, Minor: 0, Name: "nvme0n1", Rd: [4]uint64{934, 1, 5498, 15}, Wr: [4]uint64{20, 2, 300, 40},
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
