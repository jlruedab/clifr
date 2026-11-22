package query

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

var updateIotop = flag.Bool("update-iotop", false, "rewrite testdata/iotop/*.golden")

// TestIotopLine: lines as the real iotop printed them
// (bench/results/iotop-captures-20261122), rebuilt from their values.
func TestIotopLine(t *testing.T) {
	o := IotopOpts{Processes: true}
	for _, c := range []struct {
		name  string
		p     IotopProc
		style string
		delay bool
		want  string
	}{
		{"0.6-42 (desktop)", IotopProc{PID: 713, Prio: "be/3", User: "root", Read: 44987, Write: 1290000, rawWrite: 1290000, Seconds: 30, Command: "systemd-journald"},
			"", false, "    713 be/3 root     1499.57 B/s   41.99 K/s ?unavailable?  systemd-journald"},
		{"0.6-24 (Ubuntu 22.04)", IotopProc{PID: 349, Prio: "be/3", User: "root", Write: 16343, rawWrite: 16343, Seconds: 2, Command: "[jbd2/vda1-8]"},
			"0.6-24", false, "    349 be/3 root        0.00 B/s    7.98 K/s  ?unavailable?  [jbd2/vda1-8]"},
		{"rhel, delay accounting (Rocky 8)", IotopProc{PID: 881, Prio: "be/4", User: "postgres", Write: 4091, rawWrite: 4091, Seconds: 30,
			Command: "postgres: stats collector process"},
			"rhel", true, "b'    881 be/4 postgres    0.00 B/s  136.37 B/s       ?  0.00 % postgres: stats collector process'"},
		{"rhel, a quote", IotopProc{PID: 1, Prio: "be/4", User: "root", Seconds: 1, Command: "sh -c 'x'"},
			"rhel", false, `b"      1 be/4 root        0.00 B/s    0.00 B/s ?unavailable?  sh -c 'x'"`},
		{"user cut to 8, IO %", IotopProc{PID: 42, Prio: "idle", User: "systemd-timesync", Read: 3 << 20, BlkioNS: 1.5e9, Seconds: 10, Command: "x"},
			"", true, "     42 idle systemd-  307.20 K/s    0.00 B/s       ? 15.00 % x"},
	} {
		l := iotopLine(c.p, o, c.style, c.delay, 7)
		if c.style == "rhel" {
			l = pyBytesRepr(l)
		}
		if l != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, l, c.want)
		}
	}
}

// TestIotopSize: iotop's human_size and -k.
func TestIotopSize(t *testing.T) {
	for _, c := range []struct {
		v    float64
		kb   bool
		want string
	}{
		{0, false, "0.00 B"}, {1499.57, false, "1499.57 B"}, {2047.9, false, "2047.90 B"}, {2048, false, "2.00 K"},
		{136.54, false, "136.54 B"}, {185.2 * 1024 * 1024, false, "185.20 M"}, {2 << 30, false, "2.00 G"},
		{203059.81 * 1024, true, "203059.81 K"}, {0, true, "0.00 K"},
	} {
		if got := iotopSize(c.kb, c.v); got != c.want {
			t.Errorf("iotopSize(%v, %v) = %q, want %q", c.v, c.kb, got, c.want)
		}
	}
}

// TestIotopCmdline: iotop's COMMAND from the recorded command line.
func TestIotopCmdline(t *testing.T) {
	for _, c := range []struct {
		v    iotopVals
		want string
	}{
		{iotopVals{comm: "jbd2/dm-0-8"}, "[jbd2/dm-0-8]"},
		{iotopVals{cmdline: "/usr/lib/systemd/systemd-journald", argv0: 33}, "systemd-journald"},
		{iotopVals{cmdline: "/usr/bin/python3 /usr/sbin/iotop-py -b", argv0: 16}, "python3 /usr/sbin/iotop-py -b"},
		{iotopVals{cmdline: "postgres: stats collector process   ", argv0: 36}, "postgres: stats collector process"},
		{iotopVals{cmdline: "rsyslogd -n -iNONE", argv0: 8}, "rsyslogd -n -iNONE"},
		{iotopVals{cmdline: "/opt/x/bin/app --dir /var/lib/app"}, "app --dir /var/lib/app"}, // argv0 length not recorded
	} {
		if got := iotopCmdline(c.v); got != c.want {
			t.Errorf("%+v: %q, want %q", c.v, got, c.want)
		}
	}
}

// TestIotopScreens: whole screens from a small recording, in the three
// builds' styles.
func TestIotopScreens(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.UTC
	base := int64(1_790_000_000_000)
	boot := base - 3600_000
	proc := func(id int64, pid, uid int, comm, cmd string) store.ProcRow {
		return store.ProcRow{ID: id, PID: pid, StartTime: boot + 1000, PPID: 1, UID: uid, Comm: comm, Cmdline: cmd,
			Argv0Len: len(strings.Fields(cmd + " x")[0]), FirstSeen: base, Source: "sample", CmdlinePad: 1}
	}
	samp := func(id, ts int64, rb, wb, cw, blkio int64, thr, ioprio, dif int) store.ProcSample {
		return store.ProcSample{ProcID: id, TS: ts, State: "S", Threads: thr, ReadBytes: rb * 3, WriteBytes: wb * 3, // whole-process: not used
			ThrReadBytes: rb, ThrWriteBytes: wb, ThrCancelledWrite: cw, BlkioAllTicks: blkio, IOPrio: ioprio, IOPrioDif: dif}
	}
	sys := func(ts, pgin, pgout int64) store.SysSample {
		return store.SysSample{TS: ts, UptimeMS: ts - boot, PgpgIn: pgin, PgpgOut: pgout}
	}
	kw := proc(1, 650, 0, "jbd2/dm-0-8", "")
	pg := proc(2, 881, 26, "postgres", "postgres: stats collector process")
	db := proc(3, 1200, 1000, "app", "/opt/app/bin/app --data /srv/it's")
	cl := proc(4, 2860, 0, "clifrd", "/usr/bin/clifrd --config /etc/clifr/clifrd.yml")
	late := proc(5, 3000, 1000, "late", "/usr/bin/late")
	late.FirstSeen = base + 10_000
	rec := testrec.Open(t, []string{"hostname", "web01", "boot_ms", itoa(boot), "boot_id", "b1"},
		&store.Batch{Sample: store.Sample{TS: base}, Sys: []store.SysSample{sys(base, 1000, 5000)},
			Snapshots: []store.SnapshotRow{
				{TS: base, Source: "sysctl", Key: "kernel.pid_max", Pos: 0, Full: true, Line: "kernel.pid_max = 4194304"},
				{TS: base, Source: "passwd", Key: "0", Pos: 0, Full: true, Line: "0 root"},
				{TS: base, Source: "passwd", Key: "26", Pos: 1, Full: true, Line: "26 postgres"},
				{TS: base, Source: "passwd", Key: "1000", Pos: 2, Full: true, Line: "1000 appuser-with-long-name"}},
			ProcInserts: []store.ProcRow{kw, pg, db, cl},
			ProcSamples: []store.ProcSample{samp(1, base, 0, 1<<20, 0, 0, 1, 2<<13|3, 0), samp(2, base, 0, 4096, 0, 0, 1, 2<<13|4, 0),
				samp(3, base, 1<<20, 1<<20, 0, 100, 12, 2<<13|4, 1), samp(4, base, 0, 0, 0, 0, 17, 3<<13, 0)}},
		&store.Batch{Sample: store.Sample{TS: base + 10_000}, Sys: []store.SysSample{sys(base+10_000, 1500, 25_000)},
			ProcInserts: []store.ProcRow{late},
			ProcSamples: []store.ProcSample{samp(1, base+10_000, 0, 1<<20+30<<20, 0, 0, 1, 2<<13|3, 0),
				samp(2, base+10_000, 0, 4096+40960, 0, 0, 1, 2<<13|4, 0),
				samp(3, base+10_000, 1<<20+512<<10, 1<<20+8<<20, 1<<20, 150, 12, 2<<13|4, 1),
				samp(4, base+10_000, 0, 0, 0, 0, 17, 3<<13, 0), samp(5, base+10_000, 0, 0, 0, 0, 1, 2<<13|4, 0)}},
		&store.Batch{Sample: store.Sample{TS: base + 20_000}, Sys: []store.SysSample{sys(base+20_000, 1500, 30_000)},
			ProcSamples: []store.ProcSample{samp(1, base+20_000, 0, 1<<20+30<<20+4096, 0, 0, 1, 2<<13|3, 0),
				samp(3, base+20_000, 1<<20+512<<10, 1<<20+8<<20, 1<<20, 150, 12, 2<<13|4, 1),
				samp(4, base+20_000, 0, 466944, 0, 0, 17, 3<<13, 0), samp(5, base+20_000, 2<<20, 0, 0, 0, 1, 2<<13|4, 0)}})
	if _, err := LoadUsers(rec, base+20_000); err != nil {
		t.Fatal(err)
	}
	ts := []int64{base, base + 10_000, base + 20_000}
	clk := func(ts int64) string { return time.UnixMilli(ts).Format("15:04:05") }
	for _, c := range []struct {
		name  string
		o     IotopOpts
		style string
		delay bool
	}{
		{"0.6-42-Po", IotopOpts{Processes: true, Only: true}, "", false},
		{"0.6-42-P", IotopOpts{Processes: true}, "", false},
		{"0.6-42-akt", IotopOpts{Processes: true, Only: true, Accumulated: true, Kilobytes: true, Time: true}, "", false},
		{"0.6-42-q-tid", IotopOpts{Only: true, Quiet: 1}, "", false},
		{"0.6-42-qqq-user", IotopOpts{Processes: true, Quiet: 3, UIDs: []int{1000}}, "", false},
		{"0.6-24-Po", IotopOpts{Processes: true, Only: true}, "0.6-24", false},
		{"rhel-Po-delay", IotopOpts{Processes: true, Only: true}, "rhel", true},
		{"rhel-Po-pid", IotopOpts{Processes: true, PIDs: []int{881, 1200}}, "rhel", false},
	} {
		screens, err := Iotop(rec, ts, c.o)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		PrintIotop(&b, screens, c.o, ToolStyle{Iotop: c.style}, c.delay, 7, clk)
		if c.o.Processes && !c.o.Time {
			var pids []int
			for _, sc := range IotopShown(screens, c.o, ToolStyle{Iotop: c.style}, c.delay) {
				for _, p := range sc.Procs {
					pids = append(pids, p.PID)
				}
			}
			checkPIDs(t, c.name, b.String(), iotopPIDLine, pids)
		}
		golden := filepath.Join("testdata", "iotop", c.name+".golden")
		if *updateIotop {
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
			t.Errorf("%s differs from %s:\n%s", c.name, golden, b.String())
		}
	}
}

// TestIotopTimes: -d snaps to the process samples (with 10% slack), -n
// limits the screens, --at takes the two samples at or before it.
func TestIotopTimes(t *testing.T) {
	base := int64(1_790_000_000_000)
	var batches []*store.Batch
	for i := int64(0); i < 7; i++ {
		ts := base + i*10_000 - i%2*5 // a few ms early every other sample
		batches = append(batches, &store.Batch{Sample: store.Sample{TS: ts},
			Sys: []store.SysSample{{TS: ts, UptimeMS: ts - base + 100_000}}})
	}
	db := testrec.Open(t, []string{"boot_ms", itoa(base - 100_000)}, batches...)
	got := func(w Window, step int64, n int) string {
		ts, err := IotopTimes(db, w, step, n)
		if err != nil {
			return err.Error()
		}
		var s []string
		for _, v := range ts {
			s = append(s, itoa((v-base+5)/1000))
		}
		return strings.Join(s, " ")
	}
	r := Window{From: base, To: base + 60_000}
	for _, c := range []struct{ got, want string }{
		{got(r, 0, 0), "0 10 20 30 40 50 60"},
		{got(r, 10_000, 0), "0 10 20 30 40 50 60"},
		{got(r, 20_000, 0), "0 20 40 60"},
		{got(r, 10_000, 3), "0 10 20"},
		{got(Window{At: base + 35_000}, 0, 0), "20 30"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}
