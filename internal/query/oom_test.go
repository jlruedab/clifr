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

// TestOOMCgroupReport: a kill at a memory cgroup's limit (the kernel's
// report: "memory: usage" and "oom-kill:" lines) lists that cgroup's
// largest processes, not the machine's.
func TestOOMCgroupReport(t *testing.T) {
	end, sig := int64(2600), 9
	cg := "/user.slice/app.slice/run-1.scope"
	proc := func(id int64, pid int, cgroup string) store.ProcRow {
		return store.ProcRow{ID: id, PID: pid, StartTime: 900, PPID: 400, UID: 1000, Comm: "p", Cmdline: "p" + itoa(int64(pid)),
			FirstSeen: 900, Cgroup: cgroup, Source: "sample"}
	}
	victim := proc(1, 500, "0::"+cg)
	victim.LastSeen, victim.Ended, victim.ExitTS, victim.Signal, victim.OOMKilled = &end, &end, &end, &sig, true
	msg := func(seq int64, s string) store.KmsgRow {
		return store.KmsgRow{TS: 2551, BootID: "b1", Kind: "msg", Seq: seq, MonoUS: 2_550_000, Prio: 4, Msg: s}
	}
	db := testrec.Open(t, nil, &store.Batch{Sample: store.Sample{TS: 1000},
		ProcInserts: []store.ProcRow{victim, proc(2, 600, "0::"+cg+"/sub"), proc(3, 700, "0::/user.slice/app.slice/run-12.scope"),
			proc(4, 800, "0::/system.slice/big.service")},
		ProcSamples: []store.ProcSample{{ProcID: 2, TS: 1000, State: "S", Threads: 1, RSSKB: 50_000},
			{ProcID: 3, TS: 1000, State: "S", Threads: 1, RSSKB: 90_000}, {ProcID: 4, TS: 1000, State: "S", Threads: 1, RSSKB: 999_999}},
		OOMEvents: []store.OOMEvent{{TS: 2550, PID: 500, StartTime: 900, Comm: "p", RSSKB: 102_000}},
		Kmsg: []store.KmsgRow{
			{TS: 1000, BootID: "b1", Kind: "ring", Seq: 1},
			msg(2, "p invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=0"),
			msg(3, "memory: usage 102400kB, limit 102400kB, failcnt 20"),
			msg(4, "oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=user.slice,mems_allowed=0,oom_memcg="+cg+
				",task_memcg="+cg+",task=p,pid=500,uid=1000"),
			msg(5, "Memory cgroup out of memory: Killed process 500 (p) total-vm:1000kB, anon-rss:100kB, file-rss:20kB, shmem-rss:3kB, UID:1000 pgtables:4kB oom_score_adj:0"),
		},
	}, &store.Batch{Sample: store.Sample{TS: 3000}})
	kills, err := OOMKills(db, 0, 5000, 10)
	if err != nil || len(kills) != 1 {
		t.Fatalf("kills = %+v %v", kills, err)
	}
	k := kills[0]
	if k.Constraint != "cgroup" || k.Cgroup != cg || k.LimitKB != 102400 || k.UsageKB != 102400 || k.PPID != 400 {
		t.Errorf("kill = %+v", k)
	}
	if len(k.Top) != 1 || k.Top[0].PID != 600 {
		t.Errorf("top = %+v, want only pid 600 (in the cgroup, below it)", k.Top)
	}
	if !inCgroup("12:memory:/a/b\n0::/x", "/a") || inCgroup("12:cpu:/a/b", "/a") || inCgroup("0::/ab", "/a") {
		t.Error("inCgroup: v1 memory controller, other controllers, prefix of a name")
	}
}
