package query

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

var updateHtop = flag.Bool("update-htop", false, "rewrite testdata/htop/*.golden")

// TestHtopFormats: the number formats, against values seen in the captures
// (bench/results/htop-captures-20261122) and htop's code's boundaries.
func TestHtopFormats(t *testing.T) {
	for _, c := range []struct {
		got, want string
	}{
		{htopKBytes(999), "  999 "}, {htopKBytes(76344), "76344 "}, {htopKBytes(100000), "97.6M "},
		{htopKBytes(353280), " 345M "}, {htopKBytes(1683456), "1644M "}, {htopKBytes(13212057), "12.5G "},
		{htopKBytes(1566572544), "1494G "}, {htopKBytes(-1), "  N/A "},
		{htopKBytes32(100352), "  98M "}, {htopKBytes32(491520), " 480M "}, {htopKBytes32(1307648), "1277M "},
		{htopKBytes32(13212057), "12.9G "}, {htopKBytes32(76344), "76344 "},
		{htopTime(0), " 0:00.00 "}, {htopTime(37352), " 6:13.52 "}, {htopTime(360000), " 1h00:00 "},
		{htopTime(2 * 86400 * 100), "2d00h00m "}, {htopTime(20 * 86400 * 100), "  20d00h "},
		{htopTime32(37352), " 6:13.52 "}, {htopTime32(360000), " 1h00:00 "}, {htopTime32(100 * 360000), "  100h0m "},
		{htopTime32(2 * 86400 * 100), "48h00:00 "},
		{htopHumanUnit(0, false), "0K"}, {htopHumanUnit(8388608, false), "8.00G"}, {htopHumanUnit(63963136, false), "61.0G"},
		{htopHumanUnit(9.10*1024*1024, false), "9.10G"}, {htopHumanUnit(1023.9*1024, false), "1024M"},
		{htopHumanUnit(373652, true), "365M"}, {htopHumanUnit(8126784, true), "7.75G"}, {htopHumanUnit(0, true), "0K"},
		{htopPercent(4.6, 5), "  4.6 "}, {htopPercent(100, 4), " 100 "}, {htopPercent(1234.5, 6), "1234.5 "},
		{htop30CPU(200), "200. "}, {htop30CPU(0.7), " 0.7 "}, {htop30CPU(99.94), "99.9 "},
		{htopUptime(19169), "05:19:29"}, {htopUptime(86400 + 61), "1 day, 00:01:01"}, {htopUptime(3 * 86400), "3 days, 00:00:00"},
	} {
		if c.got != c.want {
			t.Errorf("%q, want %q", c.got, c.want)
		}
	}
}

// TestHtopHeaderLayout draws the header for each captured CPU count and
// width (testdata/htop/headers: VERSION-NcpuS-COLS[-host].txt, the real
// header lines) and compares where each meter's [ and ] and each text
// meter are: the layout, not the values.
func TestHtopHeaderLayout(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "htop", "headers", "*.txt"))
	if len(files) == 0 {
		t.Fatal("no header fixtures")
	}
	name := regexp.MustCompile(`^(\d\.\d)-(\d+)cpu-(\d+)`)
	pos := func(l string) string {
		var b strings.Builder
		rs := []rune(l)
		for i, r := range rs {
			rest := string(rs[i:])
			switch {
			case r == '[' || r == ']':
				b.WriteString(strconv.Itoa(i) + string(r) + " ")
			case i == 0 || rs[i-1] == ' ':
				for _, w := range []string{"Tasks", "Load", "Uptime", "Mem", "Swp"} {
					if strings.HasPrefix(rest, w) {
						b.WriteString(strconv.Itoa(i) + w + " ")
					}
				}
			}
		}
		return b.String()
	}
	for _, f := range files {
		m := name.FindStringSubmatch(filepath.Base(f))
		ver := m[1]
		if ver == "3.4" {
			ver = ""
		}
		ncpu, _ := strconv.Atoi(m[2])
		cols, _ := strconv.Atoi(m[3])
		sc := HtopScreen{CPUs: make([]HtopCPU, ncpu), MemTotal: 8126784, MemFree: 7338032, Buffers: 24032, Cached: 358044,
			SReclaimable: 45748, Shmem: 12724, ProcsRunning: 1, UptimeS: 409, PIDDigits: 7,
			Procs: []HtopProc{{PID: 1, User: "root", Command: "/sbin/init", Sampled: true, Threads: 1}}}
		var b bytes.Buffer
		PrintHtop(&b, sc, HtopOpts{Width: cols, Version: ver})
		got := strings.Split(b.String(), "\n")
		want, _ := os.ReadFile(f)
		wl := strings.Split(strings.TrimRight(string(want), "\n"), "\n")
		for i, l := range wl {
			if i >= len(got) {
				t.Errorf("%s: %d lines, want %d", f, len(got), len(wl))
				break
			}
			if pos(got[i]) != pos(l) {
				t.Errorf("%s line %d:\n got  %q\n want %q\n got  %s\n want %s", filepath.Base(f), i+1, got[i], l, pos(got[i]), pos(l))
			}
		}
	}
}

// TestHtopScreens: whole screens from a small recording, per release and
// option (golden files; -update-htop rewrites them).
func TestHtopScreens(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.UTC
	base := int64(1_790_000_000_000)
	boot := base - 2*86400_000 - 3723_000
	proc := func(id int64, pid, ppid, uid int, comm, cmd string) store.ProcRow {
		return store.ProcRow{ID: id, PID: pid, StartTime: boot + 1000, PPID: ppid, UID: uid, Comm: comm, Cmdline: cmd,
			FirstSeen: base, Source: "sample", CmdlinePad: 1}
	}
	samp := func(id, ts int64, state string, ticks, vsz, rss, shr int64, prio, nice, thr int) store.ProcSample {
		return store.ProcSample{ProcID: id, TS: ts, State: state, CPUTicks: ticks, VSZKB: vsz, RSSKB: rss, ShrKB: shr,
			Priority: prio, Nice: nice, Threads: thr}
	}
	cpus := func(ts int64, busy int64) []store.CPUSample {
		var out []store.CPUSample
		tot := [10]int64{}
		for c := 0; c < 6; c++ {
			v := [10]int64{100 * busy * int64(c+1), 10 * busy, 30 * busy, 1000 * ts / 10_000, 5, 1, 1, 0, 0, 0}
			out = append(out, store.CPUSample{TS: ts, CPU: c, T: v})
			for i := range v {
				tot[i] += v[i]
			}
		}
		return append(out, store.CPUSample{TS: ts, CPU: -1, T: tot})
	}
	sys := func(ts int64) store.SysSample {
		return store.SysSample{TS: ts, UptimeMS: ts - boot, MemTotal: 8126784, MemFree: 6338032, MemAvailable: 7000000,
			Buffers: 24032, Cached: 958044, SReclaimable: 45748, Shmem: 12724, SwapTotal: 2097148, SwapFree: 2000000,
			SwapCached: 1024, ProcsRunning: 2, Load1: 75, Load5: 41, Load15: 23}
	}
	procs := []store.ProcRow{
		proc(1, 1, 0, 0, "systemd", "/sbin/init splash"),
		proc(2, 2, 0, 0, "kthreadd", ""),
		proc(3, 9, 2, 0, "kworker/0:1", ""),
		proc(4, 700, 1, 0, "sshd", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"),
		proc(5, 1267, 700, 0, "sshd", "sshd: tester [priv]"),
		proc(6, 1313, 1267, 1000, "bash", "-bash"),
		proc(7, 1400, 1313, 1000, "xz", "xz -T2 -c /dev/urandom"),
		proc(8, 1401, 1313, 1000, "sleep", "sleep 1000"),
		proc(9, 800, 1, 101, "systemd-timesyn", "/lib/systemd/systemd-timesyncd"),
		proc(10, 900, 1, 0, "multipathd", "/sbin/multipathd -d -s"),
		proc(11, 3000, 2, 0, "modprobe", "/sbin/modprobe -q -- net-pf-10"),
	}
	s1, s2 := base, base+5000
	first := []store.ProcSample{
		samp(1, s1, "S", 112, 162*1024, 12012, 8336, 20, 0, 1), samp(2, s1, "S", 0, 0, 0, 0, 20, 0, 1),
		samp(3, s1, "I", 5, 0, 0, 0, 20, 0, 1), samp(4, s1, "S", 3, 15444, 9112, 7480, 20, 0, 1),
		samp(5, s1, "S", 1, 17228, 10912, 8736, 20, 0, 1), samp(6, s1, "S", 2, 7764, 3252, 3012, 20, 0, 1),
		samp(7, s1, "R", 5000, 480*1024, 331*1024, 2188, 20, 0, 3), samp(8, s1, "S", 0, 5000, 900, 800, 20, 0, 1),
		samp(9, s1, "S", 2, 89372, 6508, 5704, 20, 0, 2), samp(10, s1, "S", 1, 282*1024, 27108, 9080, -100, 0, 7),
		samp(11, s1, "S", 0, 2000, 1000, 900, 20, 0, 1),
	}
	second := []store.ProcSample{
		samp(1, s2, "S", 113, 162*1024, 12012, 8336, 20, 0, 1), samp(2, s2, "S", 0, 0, 0, 0, 20, 0, 1),
		samp(3, s2, "I", 5, 0, 0, 0, 20, 0, 1), samp(4, s2, "S", 3, 15444, 9112, 7480, 20, 0, 1),
		samp(5, s2, "S", 1, 17228, 10912, 8736, 20, 0, 1), samp(6, s2, "S", 2, 7764, 3252, 3012, 20, 0, 1),
		samp(7, s2, "R", 6000, 480*1024, 331*1024, 2188, 20, 0, 3), samp(8, s2, "S", 0, 5000, 900, 800, 30, 10, 1),
		samp(9, s2, "S", 2, 89372, 6508, 5704, 20, 0, 2), samp(10, s2, "S", 1, 282*1024, 27108, 9080, -100, 0, 7),
		samp(11, s2, "S", 0, 2000, 1000, 900, 20, 0, 1),
	}
	rec := testrec.Open(t, []string{"hostname", "web01", "boot_ms", itoa(boot), "boot_id", "b1"},
		&store.Batch{Sample: store.Sample{TS: s1}, Sys: []store.SysSample{sys(s1)}, CPUs: cpus(s1, 1),
			Snapshots: []store.SnapshotRow{
				{TS: s1, Source: "sysctl", Key: "kernel.pid_max", Pos: 0, Full: true, Line: "kernel.pid_max = 4194304"},
				{TS: s1, Source: "passwd", Key: "0", Pos: 0, Full: true, Line: "0 root"},
				{TS: s1, Source: "passwd", Key: "101", Pos: 1, Full: true, Line: "101 systemd-timesync"},
				{TS: s1, Source: "passwd", Key: "1000", Pos: 2, Full: true, Line: "1000 tester"}},
			ProcInserts: procs, ProcSamples: first},
		&store.Batch{Sample: store.Sample{TS: s2}, Sys: []store.SysSample{sys(s2)}, CPUs: cpus(s2, 3), ProcSamples: second})
	sc, err := HtopAt(rec, s2+1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUsers(rec, s2); err != nil {
		t.Fatal(err)
	}
	for i := range sc.Procs {
		sc.Procs[i].User = UserName(sc.Procs[i].UID, false)
	}
	for _, c := range []struct {
		name string
		o    HtopOpts
	}{
		{"3.4-120", HtopOpts{Width: 120}},
		{"3.4-80-tree", HtopOpts{Width: 80, Tree: true}},
		{"3.4-100-mem-mono", HtopOpts{Width: 100, SortKey: "PERCENT_MEM", NoColor: true}},
		{"3.4-100-user-pid", HtopOpts{Width: 100, UIDs: []int{1000}, PIDs: []int{1313, 1400, 1}}},
		{"3.4-100-tree-user", HtopOpts{Width: 100, Tree: true, UIDs: []int{1000}}},
		{"3.3-100", HtopOpts{Width: 100, Version: "3.3"}},
		{"3.2-100", HtopOpts{Width: 100, Version: "3.2"}},
		{"3.0-100", HtopOpts{Width: 100, Version: "3.0"}},
		{"3.0-81-tree", HtopOpts{Width: 81, Version: "3.0", Tree: true}},
	} {
		var b bytes.Buffer
		PrintHtop(&b, sc, c.o)
		golden := filepath.Join("testdata", "htop", c.name+".golden")
		if *updateHtop {
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
