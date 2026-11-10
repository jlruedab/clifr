package query

import (
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// TestLogOOMKills: without an OOM event (clifrd without eBPF), clifr oom and
// life take the kill from the kernel log's "Killed process" line; a kill
// recorded as an event is not listed twice.
func TestLogOOMKills(t *testing.T) {
	end, sig := int64(2600), 9
	line := func(pid string, mono, seq, read int64) store.KmsgRow {
		return store.KmsgRow{TS: read, BootID: "b1", Kind: "msg", Seq: seq, MonoUS: mono, Prio: 3,
			Msg: "Memory cgroup out of memory: Killed process " + pid + " (hog) total-vm:1000kB, anon-rss:100kB, file-rss:20kB, shmem-rss:3kB, UID:0 pgtables:4kB oom_score_adj:0"}
	}
	db := testrec.Open(t, nil, &store.Batch{Sample: store.Sample{TS: 1000},
		ProcInserts: []store.ProcRow{
			{ID: 1, PID: 4242, StartTime: 900, PPID: 1, Comm: "hog", Cmdline: "/usr/bin/hog --big", FirstSeen: 900,
				LastSeen: &end, Ended: &end, ExitTS: &end, Signal: &sig, Source: "proc_connector"},
			{ID: 2, PID: 5151, StartTime: 900, PPID: 1, Comm: "hog2", Cmdline: "/usr/bin/hog2", FirstSeen: 900,
				LastSeen: &end, Ended: &end, ExitTS: &end, Signal: &sig, OOMKilled: true, Source: "ebpf"}},
		OOMEvents: []store.OOMEvent{{TS: 2550, PID: 5151, StartTime: 900, Comm: "hog2", RSSKB: 999}},
		Kmsg: []store.KmsgRow{
			{TS: 1000, BootID: "b1", Kind: "ring", Seq: 1}, // boot clocks: 0
			// Read 3 ms after it was written; dmesg -T's formula 400 ms early
			// (the wall clock adjusted since boot): the read time counts.
			line("4242", 2_100_000, 7, 2503),
			line("5151", 2_551_000, 8, 2552), // also an OOM event
			// Read at a later start of clifrd: the formula's time.
			line("6161", 1_200_000, 9, 9000),
		},
	}, &store.Batch{Sample: store.Sample{TS: 3000}})
	kills, err := OOMKills(db, 0, 5000, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(kills) != 3 {
		t.Fatalf("%d kills, want 3 (two from the log, one event): %+v", len(kills), kills)
	}
	if k := kills[0]; k.PID != 6161 || k.TS != 1200 || !k.FromLog || k.Command != "hog" {
		t.Errorf("kill read later, from the log: %+v", k)
	}
	if k := kills[1]; k.PID != 4242 || k.TS != 2503 || k.RSSKB != 123 || !k.FromLog || k.Command != "/usr/bin/hog --big" {
		t.Errorf("kill read as written, from the log: %+v", k)
	}
	if k := kills[2]; k.PID != 5151 || k.FromLog || k.RSSKB != 999 {
		t.Errorf("kill from the event: %+v", k)
	}
	rows, err := Life(db, 0, 5000, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if !r.OOMKilled || r.Exit() != "OOM" {
			t.Errorf("pid %d: not marked as an OOM kill: %+v", r.PID, r)
		}
	}
}
