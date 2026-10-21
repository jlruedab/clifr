package query

import (
	"strings"
	"testing"

	"clifr/internal/procfs"
	"clifr/internal/store"
	"clifr/internal/testrec"
)

func TestPidstat(t *testing.T) {
	base := int64(1_790_000_000_000)
	tk := func(s int64) int64 { return s * procfs.ClockTicks }
	sys := func(ts, up int64) []store.SysSample { return []store.SysSample{{TS: ts, UptimeMS: up, MemTotal: 1_000_000}} }
	proc := store.ProcRow{ID: 1, PID: 100, StartTime: base - 60_000, PPID: 1, UID: 0, RUID: 1000, Comm: "sudo",
		Cmdline: "sudo -i", FirstSeen: base, Source: "sample"}
	idle := store.ProcRow{ID: 2, PID: 200, StartTime: base - 60_000, PPID: 1, Comm: "idle", FirstSeen: base, Source: "sample"}
	db := testrec.Open(t, []string{"mem_total_kb", "1000000"},
		// Since boot at the first sample: 1000 s of uptime.
		&store.Batch{Sample: store.Sample{TS: base}, Sys: sys(base, 1_000_000),
			ProcInserts: []store.ProcRow{proc, idle},
			ProcSamples: []store.ProcSample{
				{ProcID: 1, TS: base, State: "S", CPUTicks: tk(30), STimeTicks: tk(10), GuestTicks: tk(5), WaitNS: 2e9,
					MinFlt: 5000, MajFlt: 10, VSZKB: 4000, RSSKB: 2100, RSSStatKB: 2000, CPU: 3,
					ReadBytes: 1024 * 1000, VolCtx: 300, NonVolCtx: 20, Priority: 20},
				{ProcID: 2, TS: base, State: "S", Priority: 20}}},
		// 10 s later: 2 s more of user time.
		&store.Batch{Sample: store.Sample{TS: base + 10_000}, Sys: sys(base+10_000, 1_010_000),
			ProcSamples: []store.ProcSample{
				{ProcID: 1, TS: base + 10_000, State: "S", CPUTicks: tk(32), STimeTicks: tk(10), GuestTicks: tk(5), WaitNS: 2e9,
					MinFlt: 5100, MajFlt: 10, VSZKB: 4000, RSSKB: 2100, RSSStatKB: 2000, CPU: 4,
					ReadBytes: 1024 * 1000, VolCtx: 310, NonVolCtx: 20, Priority: 20}}})
	all := []int{PidCPU, PidMem, PidIO, PidCtx}

	spans, err := ProcSpans(db, Window{At: base + 5_000}, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := Pidstat(db, spans, all, PidstatSelect{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 { // idle had no activity at all
		t.Fatalf("rows %+v", rows)
	}
	r := rows[0]
	// 1000 s: usr = (30 - 10 - 5) s = 1.5%, system 1%, guest 0.5%, CPU 3%,
	// wait 2 s = 0.2%; 5 minor faults/s, 1 kB read/s, 0.3 switches/s.
	if r.UID != 1000 || r.Usr != 1.5 || r.System != 1 || r.Guest != 0.5 || r.CPU != 3 || r.Wait != 0.2 ||
		r.MinFlt != 5 || r.RSS != 2000 || r.Mem != 0.2 || r.KBRd != 1 || r.Cswch != 0.3 || r.Proc != 3 {
		t.Errorf("since boot: %+v", r)
	}
	var b strings.Builder
	PrintPidstat(&b, rows, all, true)
	want := "# Time        UID       PID    %usr %system  %guest   %wait    %CPU   CPU  minflt/s  majflt/s     VSZ     RSS   %MEM   kB_rd/s   kB_wr/s kB_ccwr/s iodelay   cswch/s nvcswch/s  Command\n" +
		clock(base) + "     1000       100    1.50    1.00    0.50    0.20    3.00     3      5.00      0.01    4000    2000   0.20      1.00      0.00      0.00       0      0.30      0.02  sudo\n"
	if b.String() != want {
		t.Errorf("pidstat -h:\n%s\nwant:\n%s", b.String(), want)
	}

	// One interval: 2 s of user time in 10 s = 20%; idle listed with -p ALL.
	spans, err = ProcSpans(db, Window{From: base, To: base + 10_000}, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows, err = Pidstat(db, spans, []int{PidCPU}, PidstatSelect{All: true, CmdLine: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Usr != 20 || rows[0].CPU != 20 || rows[0].Command != "sudo -i" || rows[1].CPU != 0 {
		t.Errorf("interval: %+v", rows)
	}
	b.Reset()
	PrintPidstat(&b, rows, []int{PidCPU}, false)
	if lines := strings.Split(b.String(), "\n"); lines[0] != clock(base+10_000)+"      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command" {
		t.Errorf("header %q", lines[0])
	}
}
