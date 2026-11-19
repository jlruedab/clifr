package recorder

import (
	"net/netip"
	"strings"
	"testing"
	"time"
	"unsafe"

	"clifr/internal/bpfproc"
	"clifr/internal/bpftcp"
	"clifr/internal/store"
)

// TestBudgetTiers: within a window the first events are full, then lite (no
// /proc reads, cut command lines), then only counted; the command-line
// bytes limit makes events lite early; a new window starts over.
func TestBudgetTiers(t *testing.T) {
	b := newBudget("process events (fork, exec)", 2, 5, 100) // per second: 20 full, 50 at most, 1000 bytes per window
	t0 := time.Unix(1_790_000_000, 0)
	count := map[tier]int{}
	for i := 0; i < 60; i++ {
		count[b.decide(t0.Add(time.Duration(i)*time.Millisecond), 10)]++
	}
	if count[tierFull] != 20 || count[tierLite] != 30 || count[tierShed] != 10 {
		t.Fatalf("tiers = %v, want 20 full, 30 lite, 10 counted", count)
	}
	// A new window: full again; then the bytes limit (1000 per window).
	t1 := t0.Add(budgetWindow)
	if got := b.decide(t1, 900); got != tierFull {
		t.Fatalf("new window: %v, want full", got)
	}
	if got := b.decide(t1, 200); got != tierLite {
		t.Fatalf("over the bytes limit: %v, want lite", got)
	}
	if got := b.decide(t1, 50); got != tierFull {
		t.Fatalf("small one within the bytes left: %v, want full", got)
	}

	// TCP: no middle tier.
	c := newBudget("new TCP connections", 1, 0, 0)
	c.noLite = true
	n := map[tier]int{}
	for i := 0; i < 15; i++ {
		n[c.decide(t0, 0)]++
	}
	if n[tierFull] != 10 || n[tierShed] != 5 || n[tierLite] != 0 {
		t.Fatalf("tcp tiers = %v, want 10 recorded, 5 counted", n)
	}

	// No limits: always full.
	u := newBudget("x", 0, 0, 0)
	for i := 0; i < 1000; i++ {
		if u.decide(t0, 1<<20) != tierFull {
			t.Fatal("no limit: not full")
		}
	}
	if g := u.report(t0.UnixMilli(), "processes"); g != nil {
		t.Fatalf("no events above a budget: report %v", g)
	}
}

// TestBudgetReport: one events_shed guard event with the counts, the limits
// and who caused them, then nothing until events go above the budget again;
// processes born while only counted are recognized for an hour.
func TestBudgetReport(t *testing.T) {
	b := newBudget("process events (fork, exec)", 1, 2, 0)
	t0 := time.Unix(1_790_000_000, 0)
	for i := 0; i < 25; i++ {
		if tr := b.decide(t0, 0); tr != tierFull {
			b.note(map[bool]string{true: "uid 1000 true", false: "uid 0 make"}[i%5 != 0])
		}
	}
	g := b.report(t0.Add(time.Second).UnixMilli(), "processes")
	if len(g) != 1 || g[0].Kind != "events_shed" {
		t.Fatalf("report = %+v", g)
	}
	for _, want := range []string{"processes: 5 only counted, 10 without /proc reads, command lines cut to 256 bytes of 25 process events",
		"budget: 1/s in full, 2/s at most", "most from: uid 1000 true 12, uid 0 make 3"} {
		if !strings.Contains(g[0].Detail, want) {
			t.Errorf("detail %q lacks %q", g[0].Detail, want)
		}
	}
	if g := b.report(t0.Add(2*time.Second).UnixMilli(), "processes"); g != nil {
		t.Errorf("second report without new events: %+v", g)
	}
	ms := t0.UnixMilli()
	if !b.shedBorn(ms) || !b.shedBorn(ms-10) || b.shedBorn(ms-11) || b.shedBorn(ms+1) {
		t.Error("shedBorn: want only the counted moment (10 ms ticks)")
	}
	b.report(ms+shedMemory.Milliseconds()+1, "processes")
	if b.shedBorn(ms) {
		t.Error("shed ranges kept beyond shedMemory")
	}
	if rows := b.statRows(ms, "process_events"); len(rows) != 2 || rows[0].Source != "process_events_lite" || rows[0].Events != 10 ||
		rows[1].Source != "process_events_shed" || rows[1].Events != 5 {
		t.Errorf("stat rows = %+v", rows)
	}
	if rows := b.statRows(ms, "process_events"); len(rows) != 0 {
		t.Errorf("stat rows again = %+v, want none", rows)
	}
}

// TestBudgetProcessWhole: eBPF events above the budget: lite execs keep 256
// bytes of the command line; a process born while events were only counted
// loses its exec and exit too; a process recorded at its fork keeps its
// exec even while others are only counted.
func TestBudgetProcessWhole(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	r.procBudget = newBudget("process events (fork, exec)", 1, 2, 0) // 10 full, 20 at most a window
	now := time.Now()
	ev := func(kind bpfproc.Kind, pid int, startNS uint64) bpfproc.Event {
		return bpfproc.Event{Kind: kind, PID: pid, PPID: 1, UID: 1000, Comm: "flood", StartNS: startNS, MonoNS: startNS,
			Cmdline: strings.Repeat("a", 1000), Argv0Len: 1000, HaveTTY: true}
	}
	// pid 100: recorded in full before the flood.
	if _, ok := r.fromBPF(ev(bpfproc.Fork, 100, 1e9), now); !ok {
		t.Fatal("first fork dropped")
	}
	for i := 0; i < 9; i++ {
		r.fromBPF(ev(bpfproc.Fork, 200+i, 1e9), now)
	}
	pe, ok := r.fromBPF(ev(bpfproc.Exec, 300, 1e9), now) // the 11th: lite
	if !ok || !pe.lite || len(pe.attrs.Cmdline) != liteCmdline {
		t.Fatalf("lite exec: ok %v lite %v cmdline %d bytes", ok, pe.lite, len(pe.attrs.Cmdline))
	}
	for i := 0; i < 9; i++ {
		r.fromBPF(ev(bpfproc.Fork, 400+i, 1e9), now)
	}
	// Above 20: only counted. A fork now is born in a counted range.
	shedEv := ev(bpfproc.Fork, 500, 0)
	if _, ok := r.fromBPF(shedEv, now); ok {
		t.Fatal("fork above the maximum recorded")
	}
	born := uint64(now.UnixMilli()-r.boot) * 1e6 // ns since boot of "now"
	if _, ok := r.fromBPF(ev(bpfproc.Exit, 501, born), now); ok {
		t.Error("exit of a process born while only counted: recorded")
	}
	if _, ok := r.fromBPF(ev(bpfproc.Exec, 502, born), now); ok {
		t.Error("exec of a process born while only counted: recorded")
	}
	pe, ok = r.fromBPF(ev(bpfproc.Exec, 100, 1e9), now) // born before: kept whole, lite
	if !ok || !pe.lite {
		t.Errorf("exec of a process recorded at its fork: ok %v lite %v", ok, pe.lite)
	}
	if _, ok := r.fromBPF(ev(bpfproc.Exit, 100, 1e9), now); !ok {
		t.Error("exit of a process recorded at its fork: dropped")
	}
	_, shed, drop := r.procBudget.totLite, r.procBudget.totShed, r.procBudget.drop
	if shed != 1 || drop != 2 {
		t.Errorf("counted %d, dropped %d; want 1, 2", shed, drop)
	}
}

// TestBudgetTCP: new connections above the budget are only counted, with
// every later event of them (until their close frees the pointer); a
// listener is always kept.
func TestBudgetTCP(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	r.tcpBudget = newBudget("new TCP connections", 1, 0, 0) // 10 a window
	r.tcpBudget.noLite = true
	lo := netip.MustParseAddr("127.0.0.1")
	st := func(sk uint64, old, new int) bpftcp.Event {
		return bpftcp.Event{Kind: bpftcp.State, SK: sk, Old: old, New: new, Family: 2, SAddr: lo, DAddr: lo, SPort: 40000, DPort: 8080,
			Owner: bpftcp.Owner{PID: 77}}
	}
	var batch []bpftcp.Event
	for sk := uint64(1); sk <= 12; sk++ {
		batch = append(batch, st(sk, bpftcp.Close, bpftcp.SynSent), st(sk, bpftcp.SynSent, bpftcp.Established),
			bpftcp.Event{Kind: bpftcp.AppClose, SK: sk}, st(sk, bpftcp.Established, bpftcp.Close))
	}
	batch = append(batch, st(99, bpftcp.Close, bpftcp.Listen))
	shed := map[uint64]bool{}
	kept := r.tcpBudgetFilter(batch, shed)
	if len(kept) != 10*4+1 {
		t.Fatalf("kept %d events, want 41 (10 connections of 4 events and the listener)", len(kept))
	}
	for _, e := range kept {
		if e.SK == 11 || e.SK == 12 {
			t.Fatalf("an event of a counted connection kept: %+v", e)
		}
	}
	if len(shed) != 0 {
		t.Errorf("pointers left after their close: %v", shed)
	}
	if r.tcpBudget.totShed != 2 || r.tcpBudget.drop != 6 {
		t.Errorf("counted %d, dropped %d; want 2, 6", r.tcpBudget.totShed, r.tcpBudget.drop)
	}
	g := r.tcpBudget.report(time.Now().UnixMilli(), "tcp")
	if len(g) != 1 || !strings.Contains(g[0].Detail, "tcp: 2 only counted of 12 new TCP connections") ||
		!strings.Contains(g[0].Detail, "pid 77 to 127.0.0.1:8080 2") {
		t.Errorf("report = %+v", g)
	}
}

// TestBudgetTCPBatches: within the budget a batch comes back as it is (the
// fast path); a connection counted only in one batch has its later events
// dropped in the next; decideN decides as many single decisions would.
func TestBudgetTCPBatches(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	r.tcpBudget = newBudget("new TCP connections", 1, 0, 0) // 10 a window
	r.tcpBudget.noLite = true
	st := func(sk uint64, old, new int) bpftcp.Event {
		return bpftcp.Event{Kind: bpftcp.State, SK: sk, Old: old, New: new, Owner: bpftcp.Owner{PID: 77}}
	}
	shed := map[uint64]bool{}
	var b1 []bpftcp.Event
	for sk := uint64(1); sk <= 9; sk++ {
		b1 = append(b1, st(sk, bpftcp.Close, bpftcp.SynSent), st(sk, bpftcp.SynSent, bpftcp.Established))
	}
	kept := r.tcpBudgetFilter(b1, shed)
	if len(kept) != len(b1) || &kept[0] != &b1[0] {
		t.Fatalf("within the budget: kept %d of %d, same array %v", len(kept), len(b1), &kept[0] == &b1[0])
	}
	// The 10th connection fits, the 11th and 12th are only counted.
	b2 := []bpftcp.Event{st(10, bpftcp.Close, bpftcp.SynSent), st(11, bpftcp.Close, bpftcp.SynSent),
		st(12, bpftcp.Close, bpftcp.SynSent)}
	if kept = r.tcpBudgetFilter(b2, shed); len(kept) != 1 || kept[0].SK != 10 || !shed[11] || !shed[12] {
		t.Fatalf("second batch: kept %+v, shed %v", kept, shed)
	}
	b3 := []bpftcp.Event{st(11, bpftcp.SynSent, bpftcp.Established), st(10, bpftcp.SynSent, bpftcp.Established),
		st(11, bpftcp.Established, bpftcp.Close)}
	if kept = r.tcpBudgetFilter(b3, shed); len(kept) != 1 || kept[0].SK != 10 || shed[11] || !shed[12] {
		t.Fatalf("third batch: kept %+v, shed %v", kept, shed)
	}
	if r.tcpBudget.totShed != 2 || r.tcpBudget.drop != 2 {
		t.Errorf("counted %d, dropped %d; want 2, 2", r.tcpBudget.totShed, r.tcpBudget.drop)
	}

	one, many := newBudget("x", 1, 2, 0), newBudget("x", 1, 2, 0) // full 10, then lite to 20, then shed
	now := time.Now()
	want := 0
	for range 25 {
		if one.decide(now, 0) != tierShed {
			want++
		}
	}
	if got := many.decideN(now, 25); got != want || many.nFull != one.nFull || many.nLite != one.nLite || many.nShed != one.nShed {
		t.Errorf("decideN kept %d (full %d lite %d shed %d), decide %d (%d %d %d)", got,
			many.nFull, many.nLite, many.nShed, want, one.nFull, one.nLite, one.nShed)
	}
}

// TestCutCmdlineCopies: a cut command line does not keep the original's
// memory (a substring would).
func TestCutCmdlineCopies(t *testing.T) {
	long := strings.Repeat("x", 1000)
	cut, argv0 := cutCmdline(long, 900)
	if len(cut) != liteCmdline || argv0 != liteCmdline {
		t.Fatalf("cut %d bytes, argv0 %d", len(cut), argv0)
	}
	if unsafe.StringData(cut) == unsafe.StringData(long) {
		t.Error("the cut shares the original's memory")
	}
}

// TestBudgetPressure: while the heap is above the memory guard, new events
// are only counted whatever the rate; an exec of a recorded process stays
// (lite); the report says why.
func TestBudgetPressure(t *testing.T) {
	b := newBudget("process events (fork, exec)", 100, 1000, 0)
	high := true
	b.pressure = func() bool { return high }
	t0 := time.Unix(1_790_000_000, 0)
	if got := b.decide(t0, 0); got != tierShed {
		t.Fatalf("under pressure: %v, want only counted", got)
	}
	if got := b.decide(t0, 0, true); got != tierLite {
		t.Fatalf("under pressure, whole: %v, want lite", got)
	}
	high = false
	if got := b.decide(t0.Add(50*time.Millisecond), 0); got != tierShed {
		t.Fatalf("within pressureEvery: %v, want the cached state", got)
	}
	if got := b.decide(t0.Add(pressureEvery), 0); got != tierFull {
		t.Fatalf("pressure gone: %v, want full", got)
	}
	g := b.report(t0.UnixMilli(), "processes")
	if len(g) != 1 || !strings.Contains(g[0].Detail, "2 of those only counted because the recorder's heap was above the memory guard") {
		t.Errorf("report = %+v", g)
	}
}

// TestAfterFlood: memory is returned once, at the first report without
// events above the budget after a flood, and not while either kind floods.
func TestAfterFlood(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	freed := 0
	old := freeOSMemory
	freeOSMemory = func() { freed++ }
	defer func() { freeOSMemory = old }()
	var b store.Batch
	ev := []store.GuardEvent{{Kind: "events_shed"}}
	r.afterFlood("processes", ev, &b)
	r.afterFlood("tcp", nil, &b)
	r.afterFlood("processes", ev, &b)
	r.afterFlood("tcp", nil, &b)
	if freed != 0 {
		t.Fatalf("freed %d times during a process flood", freed)
	}
	r.afterFlood("processes", nil, &b)
	r.afterFlood("tcp", nil, &b)
	r.afterFlood("processes", nil, &b)
	if freed != 1 || len(b.Guard) != 2 {
		t.Errorf("freed %d times, %d guard events; want 1, 2", freed, len(b.Guard))
	}
}
