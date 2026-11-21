package query

import (
	"testing"
	"time"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// TestClockStep: the clock was stepped 950 ms forward 40 s after clifrd
// started (the first NTP sync at boot). clifrd keeps the boot time it
// measured at start for process start times; sys_samples.boot_ms has the
// boot time on the clock at each sample. A moment after the step shows
// every start on the new clock, as ps run then would; life shows a start on
// the clock in force when the process started.
func TestClockStep(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.UTC
	boot := int64(1_790_000_000_300) // the run's boot time (meta boot_ms)
	run := int64(1_790_000_100)      // the run's start, in seconds
	base := run * 1000
	sys := func(ts, bootMS int64) store.SysSample {
		return store.SysSample{TS: ts, UptimeMS: ts - bootMS, BootMS: bootMS, MemTotal: 1000}
	}
	before := store.ProcRow{ID: run*1_000_000_000 + 1, PID: 10, StartTime: boot + 5_000, PPID: 1, Comm: "early",
		Cmdline: "early", FirstSeen: base, Source: "sample"}
	// Started at 50 s on the new clock: clifrd records boot + its ticks,
	// 950 ms early.
	after := store.ProcRow{ID: run*1_000_000_000 + 2, PID: 20, StartTime: base + 50_000 - 950, PPID: 1, Comm: "late",
		Cmdline: "late", FirstSeen: base + 50_000, Source: "sample"}
	db := testrec.Open(t, []string{"boot_ms", itoa(boot), "boot_time", itoa(boot / 1000), "boot_id", "b1"},
		&store.Batch{Sample: store.Sample{TS: base}, Sys: []store.SysSample{sys(base, boot)},
			ProcInserts: []store.ProcRow{before},
			ProcSamples: []store.ProcSample{{ProcID: before.ID, TS: base, State: "S", Threads: 1}}},
		&store.Batch{Sample: store.Sample{TS: base + 40_000}, Sys: []store.SysSample{sys(base+40_000, boot+950)},
			Guard: []store.GuardEvent{{TS: base + 40_000, Kind: "clock_step", Detail: "the clock moved +0.950 s"}}},
		&store.Batch{Sample: store.Sample{TS: base + 60_000}, Sys: []store.SysSample{sys(base+60_000, boot+950)},
			ProcInserts: []store.ProcRow{after},
			ProcSamples: []store.ProcSample{{ProcID: before.ID, TS: base + 60_000, State: "S", Threads: 1},
				{ProcID: after.ID, TS: base + 60_000, State: "S", Threads: 1}}})

	if got := StartShiftAt(db, base+20_000); got != 0 {
		t.Errorf("before the step: shift %d, want 0", got)
	}
	if got := StartShiftAt(db, base+60_000); got != 950 {
		t.Errorf("after the step: shift %d, want 950", got)
	}
	rows, _, err := PSAt(db, base+60_000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		want := map[int]int64{10: boot + 5_000 + 950, 20: base + 50_000}[r.PID]
		if r.StartMS != want {
			t.Errorf("ps pid %d: start %d, want %d (on the clock after the step)", r.PID, r.StartMS, want)
		}
	}
	life, err := Life(db, base, base+60_000, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range life {
		// early started before the step: as recorded; late after it.
		want := map[int]int64{10: boot + 5_000, 20: base + 50_000}[r.PID]
		if r.Start != want {
			t.Errorf("life pid %d: start %d, want %d", r.PID, r.Start, want)
		}
	}
	a, err := AtopSysAt(db, base+60_000)
	if err != nil {
		t.Fatal(err)
	}
	if want := (boot + 950) / 1000; a.BTime != want {
		t.Errorf("atop btime %d, want %d", a.BTime, want)
	}
}
