package metrics

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

func testSnapshot() *Snapshot {
	return &Snapshot{
		Version: "0.1.0-test",
		BootMS:  1_790_000_000_500,
		SysTS:   1_790_000_100_000,
		Sys: store.SysSample{Load1: 123, Load5: 45, Load15: 6, MemTotal: 1000, MemAvailable: 600,
			Ctxt: 77, Forks: 5, Intr: 9, ProcsRunning: 2, ProcsBlocked: 1, PgMajFault: 3},
		CPUs: []store.CPUSample{
			{CPU: -1, T: [10]int64{999}}, // the total: left out
			{CPU: 1, T: [10]int64{250, 0, 50, 1000, 0, 0, 0, 0, 20, 0}},
			{CPU: 0, T: [10]int64{150, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
		},
		Sample:  store.Sample{TS: 1_790_000_099_000, CPUUS: 2_500_000, RSSKB: 2048, DBBytes: 4096, NProc: 300, FDIntervalS: 120},
		Samples: 7,
		Stats: map[string][2]int64{"ebpf_exec": {10, 0}, "tcp_state": {500, 3},
			"bpf_runs:handle_exec": {40, 0}, "bpf_ns:handle_exec": {2_000_000_000, 0}},
		Guard: map[string]int64{"budget_exceeded": 2},
	}
}

// parse checks the text format the way a scraper reads it (every sample
// after its family's HELP and TYPE, each family once, numeric values) and
// returns the samples by their full name with labels.
func parse(t *testing.T, text string) map[string]float64 {
	t.Helper()
	got := map[string]float64{}
	typed := map[string]bool{}
	var family string
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "# HELP "):
			name := strings.Fields(line)[2]
			if typed[name] {
				t.Errorf("family %s twice", name)
			}
			family = name
		case strings.HasPrefix(line, "# TYPE "):
			f := strings.Fields(line)
			if f[2] != family || len(f) != 4 {
				t.Errorf("TYPE line %q not after its HELP", line)
			}
			switch f[3] {
			case "counter", "gauge", "untyped":
			default:
				t.Errorf("type %q", f[3])
			}
			typed[f[2]] = true
		default:
			i := strings.LastIndexByte(line, ' ')
			key, val := line[:i], line[i+1:]
			name := key
			if j := strings.IndexByte(key, '{'); j >= 0 {
				name = key[:j]
			}
			if name != family || !typed[name] {
				t.Errorf("sample %q outside its family %q", line, family)
			}
			v, err := strconv.ParseFloat(val, 64)
			if err != nil {
				t.Errorf("value in %q: %v", line, err)
			}
			got[key] = v
		}
	}
	return got
}

func TestWrite(t *testing.T) {
	var b strings.Builder
	if err := Write(&b, testSnapshot()); err != nil {
		t.Fatal(err)
	}
	got := parse(t, b.String())
	for key, want := range map[string]float64{
		`node_cpu_seconds_total{cpu="0",mode="user"}`:       1.5, // ticks / 100
		`node_cpu_seconds_total{cpu="1",mode="idle"}`:       10,
		`node_cpu_seconds_total{cpu="0",mode="steal"}`:      0.07,
		`node_cpu_guest_seconds_total{cpu="1",mode="user"}`: 0.2,
		`node_cpu_guest_seconds_total{cpu="0",mode="nice"}`: 0.09,
		"node_load1":                                              1.23, // hundredths
		"node_load15":                                             0.06,
		"node_memory_MemTotal_bytes":                              1000 * 1024, // kB
		"node_memory_MemAvailable_bytes":                          600 * 1024,
		"node_boot_time_seconds":                                  1_790_000_000,
		"node_context_switches_total":                             77,
		"node_procs_blocked":                                      1,
		"node_vmstat_pgmajfault":                                  3,
		`clifr_build_info{version="0.1.0-test"}`:                  1,
		"clifr_recorder_cpu_seconds_total":                        2.5,
		"clifr_recorder_resident_memory_bytes":                    2048 * 1024,
		"clifr_samples_total":                                     7,
		`clifr_events_total{source="tcp_state"}`:                  500,
		`clifr_events_dropped_total{source="tcp_state"}`:          3,
		`clifr_ebpf_program_runs_total{program="handle_exec"}`:    40,
		`clifr_ebpf_program_seconds_total{program="handle_exec"}`: 2,
		`clifr_guard_events_total{kind="budget_exceeded"}`:        2,
	} {
		if v, ok := got[key]; !ok || v != want {
			t.Errorf("%s = %v (present %v), want %v", key, v, ok, want)
		}
	}
	for key := range got {
		if strings.Contains(key, `cpu="-1"`) || strings.Contains(key, "bpf_runs:") || strings.Contains(key, "bpf_ns:") {
			t.Errorf("should not be served: %s", key)
		}
	}
	if !strings.Contains(b.String(), `node_cpu_seconds_total{cpu="0",mode="user"} 1.5`+"\n"+
		`node_cpu_seconds_total{cpu="0",mode="nice"} 0.01`) {
		t.Error("CPUs not in order, or modes not in Node Exporter's order")
	}

	// Before the first system sample: only clifr_*.
	s := testSnapshot()
	s.SysTS = 0
	b.Reset()
	Write(&b, s)
	if got := parse(t, b.String()); len(got) == 0 || strings.Contains(b.String(), "node_") {
		t.Errorf("without a system sample: %q", b.String())
	}
}

func TestEscape(t *testing.T) {
	if got := escape("a\"b\\c\nd"); got != `a\"b\\c\nd` {
		t.Errorf("escape: %q", got)
	}
}

func TestListenLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":9100", "10.1.2.3:9100", "example.com:9100", "[::]:0", "9100"} {
		if ln, err := Listen(addr); err == nil {
			ln.Close()
			t.Errorf("%s: accepted", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:0", "localhost:0"} {
		ln, err := Listen(addr)
		if err != nil {
			t.Errorf("%s: %v", addr, err)
			continue
		}
		if !strings.HasPrefix(ln.Addr().String(), "127.0.0.1:") {
			t.Errorf("%s: listening on %s", addr, ln.Addr())
		}
		ln.Close()
	}
}

func TestHandler(t *testing.T) {
	var snap *Snapshot
	srv := httptest.NewServer(Handler(func() *Snapshot { return snap }))
	defer srv.Close()
	get := func(method, path string) (*http.Response, string) {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b strings.Builder
		bufio.NewReader(resp.Body).WriteTo(&b)
		return resp, b.String()
	}
	if resp, _ := get("GET", "/metrics"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("before a sample: %d", resp.StatusCode)
	}
	snap = testSnapshot()
	resp, body := get("GET", "/metrics")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" ||
		!strings.Contains(body, "node_load1 1.23\n") {
		t.Errorf("GET /metrics: %d %q %.200q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	if resp, body := get("HEAD", "/metrics"); resp.StatusCode != 200 || body != "" {
		t.Errorf("HEAD: %d %q", resp.StatusCode, body)
	}
	if resp, _ := get("POST", "/metrics"); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", resp.StatusCode)
	}
	if resp, _ := get("GET", "/other"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("other path: %d", resp.StatusCode)
	}
}

// Disks, interfaces, file systems and pressure: Node Exporter's names,
// units, sums and default filters.
func TestWriteDevices(t *testing.T) {
	s := testSnapshot()
	disk := func(name string, v ...int64) store.DiskSample {
		d := store.DiskSample{Name: name}
		copy(d.V[:], v)
		return d
	}
	s.Disks = []store.DiskSample{
		disk("nvme0n1", 10, 1, 2048, 1500, 20, 2, 4096, 2500, 3, 0, 8, 7, 4, 3000, 3500, 5, 60),
		disk("nvme0n1p1", 9), disk("loop0", 9), disk("sda1", 9), disk("dm-0", 1),
	}
	var stats [25]int64
	for i := range stats {
		stats[i] = int64(100 + i)
	}
	s.Links = []store.LinkRow{
		{Name: "lo", Index: 1, Link: -1, MTU: 65536, OperState: 0, HasStats: true, Stats: stats, TxQLen: 1000, Type: 772},
		{Name: "eth0", Index: 2, Link: 2, MTU: 1500, OperState: 6, HasStats: true, Stats: stats, CarrierChanges: 4, Flags: 0x11043},
		{Name: "tun0", Index: 7, Link: -1, MTU: 1400, OperState: 6}, // no statistics
	}
	s.FS = []FSUsage{{Device: "/dev/sda1", FSType: "ext4", MountPoint: "/", ReadOnly: true, Size: 4096, Free: 1024, Avail: 512, Files: 10, FilesFree: 3}}
	s.Press = map[string]procfs.Pressure{"cpu": {Some: 2_500_000, Full: 1, HasFull: true}, "memory": {Some: 1_000_000, Full: 500_000, HasFull: true},
		"io": {Some: 3_000_000}, "irq": {Full: 7_000_000, HasFull: true}}
	var b strings.Builder
	if err := Write(&b, s); err != nil {
		t.Fatal(err)
	}
	got := parse(t, b.String())
	fs := `{device="/dev/sda1",device_error="",fstype="ext4",mountpoint="/"}`
	for key, want := range map[string]float64{
		`node_disk_reads_completed_total{device="nvme0n1"}`:             10,
		`node_disk_read_bytes_total{device="nvme0n1"}`:                  2048 * 512,
		`node_disk_read_time_seconds_total{device="nvme0n1"}`:           1.5,
		`node_disk_written_bytes_total{device="nvme0n1"}`:               4096 * 512,
		`node_disk_discarded_sectors_total{device="nvme0n1"}`:           8,
		`node_disk_io_now{device="nvme0n1"}`:                            4,
		`node_disk_io_time_weighted_seconds_total{device="nvme0n1"}`:    3.5,
		`node_disk_flush_requests_time_seconds_total{device="nvme0n1"}`: 0.06,
		`node_disk_reads_completed_total{device="dm-0"}`:                1,
		`node_network_receive_bytes_total{device="eth0"}`:               102,
		`node_network_receive_drop_total{device="eth0"}`:                106 + 115,             // dropped + missed
		`node_network_receive_frame_total{device="eth0"}`:               113 + 110 + 111 + 112, // frame + length + over + crc
		`node_network_transmit_carrier_total{device="lo"}`:              117 + 116 + 119 + 120,
		`node_network_transmit_colls_total{device="lo"}`:                109,
		`node_network_receive_nohandler_total{device="lo"}`:             123,
		`node_network_up{device="eth0"}`:                                1,
		`node_network_up{device="lo"}`:                                  0,
		`node_network_up{device="tun0"}`:                                1,
		`node_network_iface_link{device="lo"}`:                          1, // no IFLA_LINK: the device itself
		`node_network_iface_link{device="eth0"}`:                        2,
		`node_network_mtu_bytes{device="tun0"}`:                         1400,
		`node_network_carrier_changes_total{device="eth0"}`:             4,
		`node_network_protocol_type{device="lo"}`:                       772,
		`node_network_flags{device="eth0"}`:                             0x1003, // sysfs's: without RUNNING and LOWER_UP
		"node_filesystem_size_bytes" + fs:                               4096,
		"node_filesystem_avail_bytes" + fs:                              512,
		"node_filesystem_files_free" + fs:                               3,
		"node_filesystem_readonly" + fs:                                 1,
		"node_filesystem_device_error" + fs:                             0,
		"node_pressure_cpu_waiting_seconds_total":                       2.5,
		"node_pressure_memory_waiting_seconds_total":                    1,
		"node_pressure_memory_stalled_seconds_total":                    0.5,
		"node_pressure_io_waiting_seconds_total":                        3,
		"node_pressure_irq_stalled_seconds_total":                       7,
	} {
		if v, ok := got[key]; !ok || v != want {
			t.Errorf("%s = %v (present %v), want %v", key, v, ok, want)
		}
	}
	for key := range got {
		for _, bad := range []string{`"nvme0n1p1"`, `"loop0"`, `"sda1"`, "node_pressure_cpu_stalled", "node_pressure_io_stalled",
			`node_network_receive_bytes_total{device="tun0"}`} {
			if strings.Contains(key, bad) {
				t.Errorf("should not be served: %s", key)
			}
		}
	}
}

func TestServedFS(t *testing.T) {
	for _, c := range []struct {
		point, fstype string
		want          bool
	}{
		{"/", "ext4", true}, {"/boot/efi", "vfat", true}, {"/tmp", "tmpfs", true}, {"/home/a/x", "fuse.sshfs", true},
		{"/run", "tmpfs", false}, {"/run/user/1000", "tmpfs", false}, {"/dev/shm", "tmpfs", false}, {"/sys/fs/cgroup", "cgroup2", false},
		{"/snap/core/1", "squashfs", false}, {"/var/lib/docker/overlay2/x/merged", "overlay", false}, {"/media/usb", "vfat", false},
		{"/data", "overlay", false}, {"/proc", "proc", false},
	} {
		if got := ServedFS(c.point, c.fstype); got != c.want {
			t.Errorf("ServedFS(%q, %q) = %v", c.point, c.fstype, got)
		}
	}
}
