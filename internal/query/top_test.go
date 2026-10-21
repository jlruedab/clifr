package query

import (
	"strings"
	"testing"

	"clifr/internal/procfs"
	"clifr/internal/store"
	"clifr/internal/testrec"
)

// Two samples 30 s apart: a busy process (6 s of CPU in the interval), an
// idle one, a zombie, one started between the samples, and one only seen
// through events after the second sample.
func topDB(t *testing.T) *store.DB {
	t.Helper()
	base := int64(1_790_000_000_000)
	tk := func(secs int64) int64 { return secs * procfs.ClockTicks }
	sys := func(ts int64, all [10]int64) ([]store.SysSample, []store.CPUSample) {
		return []store.SysSample{{TS: ts, UptimeMS: 3_600_000 + ts - base, Load1: 150, Load5: 75, Load15: 5,
				MemTotal: 1_048_576, MemFree: 524_288, MemAvailable: 786_432, Buffers: 10_240, Cached: 102_400,
				SReclaimable: 2048, SwapTotal: 2_097_152, SwapFree: 2_097_152}},
			[]store.CPUSample{{TS: ts, CPU: -1, T: all}}
	}
	s1, c1 := sys(base, [10]int64{1000, 0, 500, 8000, 500})
	s2, c2 := sys(base+30_000, [10]int64{1300, 0, 600, 8500, 600})
	p := func(id int64, pid int, comm string, start int64) store.ProcRow {
		return store.ProcRow{ID: id, PID: pid, StartTime: start, PPID: 1, UID: 0, Comm: comm, Cmdline: "/bin/" + comm + "\x00-x",
			FirstSeen: start, Source: "sample"}
	}
	return testrec.Open(t, []string{"mem_total_kb", "1048576"},
		&store.Batch{Sample: store.Sample{TS: base}, Sys: s1, CPUs: c1,
			ProcInserts: []store.ProcRow{p(1, 100, "busy", base-60_000), p(2, 200, "idle", base-60_000), p(3, 300, "dead", base-60_000)},
			ProcSamples: []store.ProcSample{
				{ProcID: 1, TS: base, State: "R", CPUTicks: tk(10), RSSKB: 102_400, VSZKB: 20_000_000},
				{ProcID: 2, TS: base, State: "S", Nice: 5, CPUTicks: tk(1), RSSKB: 1024, VSZKB: 4096},
				{ProcID: 3, TS: base, State: "Z"}}},
		&store.Batch{Sample: store.Sample{TS: base + 30_000}, Sys: s2, CPUs: c2,
			ProcInserts: []store.ProcRow{p(4, 400, "new", base+20_000)},
			ProcSamples: []store.ProcSample{
				{ProcID: 1, TS: base + 30_000, State: "R", CPUTicks: tk(16), RSSKB: 102_400, VSZKB: 20_000_000},
				{ProcID: 4, TS: base + 30_000, State: "S", CPUTicks: tk(1), RSSKB: 2048, VSZKB: 8192}}},
		&store.Batch{Sample: store.Sample{TS: base + 40_000},
			ProcInserts: []store.ProcRow{{ID: 5, PID: 500, StartTime: base + 35_000, PPID: 1, Comm: "brief",
				FirstSeen: base + 35_000, Source: "ebpf"}}})
}

func TestTopAt(t *testing.T) {
	db := topDB(t)
	base := int64(1_790_000_000_000)
	rep, err := TopAt(db, base+38_000) // after the second sample; "brief" started at +35 s
	if err != nil {
		t.Fatal(err)
	}
	if rep.SampleTS != base+30_000 || rep.PrevTS != base {
		t.Errorf("samples %d, %d", rep.SampleTS, rep.PrevTS)
	}
	if want := (TopTasks{Total: 5, Running: 1, Sleeping: 3, Zombie: 1}); rep.Tasks != want {
		t.Errorf("tasks %+v, want %+v", rep.Tasks, want)
	}
	// 300 user, 100 system, 500 idle, 100 iowait ticks of 1000.
	if c := rep.CPU; c.Us != 30 || c.Sy != 10 || c.Id != 50 || c.Wa != 10 || c.FromTS != base {
		t.Errorf("cpu %+v", c)
	}
	if m := rep.Mem; m.Used != 262_144 || m.BuffCache != 114_688 || m.Available != 786_432 {
		t.Errorf("mem %+v", m)
	}
	var order []string
	byPID := map[int]TopRow{}
	for _, r := range rep.Procs {
		order = append(order, r.Comm)
		byPID[r.PID] = r
	}
	if got := strings.Join(order, " "); got != "busy new idle dead brief" {
		t.Errorf("order %q, want by %%CPU then PID, unsampled last", got)
	}
	if r := byPID[100]; r.CPU != 20 || r.Mem < 9.7 || r.Mem > 9.8 || r.TimeCS != 1600 || r.PR != 20 {
		t.Errorf("busy: %+v (6 s of CPU in 30 s = 20%%)", r)
	}
	if r := byPID[400]; r.CPU != 10 { // started 10 s before the sample, 1 s of CPU
		t.Errorf("new: %%CPU %v, want 10 (since its start)", r.CPU)
	}
	if r := byPID[200]; r.PR != 25 || r.NI != 5 || r.CPU != 0 {
		t.Errorf("idle: %+v", r)
	}
	if r := byPID[500]; r.Sampled {
		t.Errorf("brief: sampled %+v", r)
	}

	var sb strings.Builder
	PrintTop(&sb, rep, TopFormat{Width: 80})
	lines := strings.Split(sb.String(), "\n")
	for i, want := range []string{
		"top - ",
		"Tasks:   5 total,   1 running,   3 sleeping,   0 stopped,   1 zombie",
		"%Cpu(s): 30.0 us, 10.0 sy,  0.0 ni, 50.0 id, 10.0 wa,  0.0 hi,  0.0 si,  0.0 st",
		"MiB Mem :   1024.0 total,    512.0 free,    256.0 used,    112.0 buff/cache",
		"MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.    768.0 avail Mem",
		"",
		"    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND",
		"    100 root      20   0   19.1g 102400      - R  20.0   9.8   0:16.00 busy",
	} {
		if !strings.HasPrefix(lines[i], want) {
			t.Errorf("line %d: %q, want %q", i, lines[i], want)
		}
	}
	if !strings.Contains(sb.String(), "    500 root       -   -       -      -      - -     -     -         - brief") {
		t.Errorf("unsampled process line:\n%s", sb.String())
	}
}

func TestTopFormats(t *testing.T) {
	for _, c := range []struct {
		kb   int64
		w    int
		want string
	}{{810620, 6, "810620"}, {1_363_148, 6, "1.3g"}, {56_070_000, 7, "53.5g"}, {12_478_000, 7, "11.9g"},
		{1_523_000_000, 7, "1452.4g"}, {4208704, 7, "4208704"}} {
		if got := topMem(c.kb, c.w); got != c.want {
			t.Errorf("topMem(%d, %d) = %q, want %q", c.kb, c.w, got, c.want)
		}
	}
	for cs, want := range map[int64]string{35228: "5:52.28", 12345678: "2057:36"} {
		if got := topTime(cs); got != want {
			t.Errorf("topTime(%d) = %q, want %q", cs, got, want)
		}
	}
	rep := TopReport{Procs: []TopRow{{PID: 1, User: "someverylonguser", Comm: "x", Command: "/usr/bin/" + strings.Repeat("y", 40),
		Sampled: true, S: "S"}}}
	var sb strings.Builder
	PrintTop(&sb, rep, TopFormat{Width: 80, CmdLine: true})
	last := strings.Split(strings.TrimSpace(sb.String()), "\n")
	l := last[len(last)-1]
	if len(l) != 79 || !strings.HasSuffix(l, "+") || !strings.Contains(l, " somever+ ") {
		t.Errorf("cut line (%d): %q", len(l), l)
	}
}
