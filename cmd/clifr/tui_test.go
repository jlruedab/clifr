package main

import (
	"slices"
	"strings"
	"testing"
	"time"

	"clifr/internal/query"
)

func TestSplitKeys(t *testing.T) {
	in := "\x1b[C\x1b[C\x1b[1;2Dq\x1bOA\tä\x1b"
	var got []string
	for _, k := range splitKeys([]byte(in)) {
		got = append(got, keyName(k))
	}
	want := []string{"Right", "Right", "S-Left", "q", "Up", "\t", "ä", "Esc"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// testTUI is a 10-minute window with a sample every 10 s, 80 columns wide.
func testTUI() *tui {
	from := time.Date(2026, 11, 23, 2, 40, 0, 0, time.Local).UnixMilli()
	u := &tui{from: from, to: from + 600_000, width: 80, height: 30, cache: map[tuiKey][]string{}, markA: -1, markB: -1}
	for ts := from; ts <= u.to; ts += 10_000 {
		u.points = append(u.points, tuiPoint{ts: ts, cpu: 50, mem: 100, load: 1, io: -1})
	}
	u.render = func(pane int, ts int64, width int) []string { return []string{tuiPanes[pane].name} }
	return u
}

func TestTUILayout(t *testing.T) {
	u := testTUI()
	if n := u.cols(); n != 80-tuiLabelW-tuiValueW {
		t.Fatalf("cols %d", n)
	}
	if u.col(u.from) != 0 || u.col(u.to) != u.cols()-1 {
		t.Errorf("col: %d %d", u.col(u.from), u.col(u.to))
	}
	cpu := strings.Join(u.spark(func(p tuiPoint) float64 { return p.cpu }, 100), "")
	if strings.Trim(cpu, "▅ ") != "" || !strings.Contains(cpu, "▅") {
		t.Errorf("cpu 50%%: %q", cpu)
	}
	mem := strings.Join(u.spark(func(p tuiPoint) float64 { return p.mem }, 100), "")
	if strings.Trim(mem, "█ ") != "" {
		t.Errorf("mem 100%%: %q", mem)
	}
	io := strings.Join(u.spark(func(p tuiPoint) float64 { return p.io }, 100), "")
	if strings.TrimSpace(io) != "" {
		t.Errorf("io unknown: %q", io)
	}
	ax := u.axis()
	if !strings.HasPrefix(ax, "02:40") || !strings.Contains(ax, "02:48") {
		t.Errorf("axis %q", ax)
	}
	if lines := strings.Split(u.screen(), "\r\n"); len(lines) != u.height {
		t.Errorf("%d lines for a %d-line terminal", len(lines), u.height)
	}
}

func TestTUIKeys(t *testing.T) {
	u := testTUI()
	u.marks = []tuiMark{{ts: u.from + 125_000, sym: "✕", text: "OOM kill"}}
	last := len(u.points) - 1
	u.cur = last
	steps := []struct {
		key  string
		want int
	}{{"Home", 0}, {"Right", 1}, {"S-Right", 7}, {"Left", 6}, {"n", 12}, {"n", 12}, {"Home", 0}, {"n", 12}, {"End", last}, {"S-Left", last - 6}, {"N", 12}, {"N", 12}}
	for _, s := range steps {
		u.key(s.key)
		if u.cur != s.want {
			t.Fatalf("after %s: sample %d, want %d", s.key, u.cur, s.want)
		}
	}
	u.key("\t")
	u.key("S-Tab")
	u.key("S-Tab")
	if u.pane != len(tuiPanes)-1 {
		t.Errorf("pane %d", u.pane)
	}
	u.key("3")
	if u.pane != 2 {
		t.Errorf("pane %d after 3", u.pane)
	}
	if !u.key("q") {
		t.Error("q does not quit")
	}
	if !strings.Contains(u.screen(), "✕") {
		t.Error("no OOM mark")
	}
}

func TestTUIMarkRow(t *testing.T) {
	u := testTUI()
	// A gap: no samples from 02:43 to 02:46.
	var pts []tuiPoint
	for _, p := range u.points {
		if p.ts <= u.from+180_000 || p.ts >= u.from+360_000 {
			pts = append(pts, p)
		}
	}
	u.points = pts
	u.marks = []tuiMark{
		{ts: u.from + 60_000, sym: "●", text: "login"},
		{ts: u.from + 60_000, sym: "✕", text: "OOM kill: \x1b[31mred"}, // the same column: ✕ wins
		{ts: u.from + 400_000, sym: "↻", text: "boot", after: true},
	}
	row := string(u.markRow())
	if c := []rune(row)[u.col(u.from+60_000)]; c != '✕' {
		t.Errorf("column of the kill and the login: %q", c)
	}
	for _, ts := range []int64{u.from + 240_000, u.from + 300_000} {
		if c := []rune(row)[u.col(ts)]; c != '░' {
			t.Errorf("gap at %d: %q (%q)", ts-u.from, c, row)
		}
	}
	if c := []rune(row)[u.col(u.from+120_000)]; c != ' ' {
		t.Errorf("no event at 02:42: %q", c)
	}
	// n goes to the sample before the kill, then the first after the boot.
	u.cur = 0
	u.key("n")
	if ts := u.points[u.cur].ts - u.from; ts != 60_000 {
		t.Errorf("n: %d", ts)
	}
	u.key("n")
	if ts := u.points[u.cur].ts - u.from; ts != 400_000 {
		t.Errorf("n to the boot: %d", ts)
	}
	// Recorded text is filtered on the event line.
	if l := u.nearMark(u.from + 60_000); strings.Contains(l, "\x1b") || !strings.Contains(l, "+1 nearby") {
		t.Errorf("event line %q", l)
	}
}

func TestTUIEventsPane(t *testing.T) {
	// Events every 4 minutes from 0 to 40 minutes; the window is an hour.
	min := int64(60_000)
	var all []query.Event
	for i := int64(0); i <= 10; i++ {
		all = append(all, query.Event{TS: 4 * i * min, Kind: "start", Exact: true, PID: int(i), Detail: "x"})
	}
	reads := 0
	e := &tuiEvents{from: 0, to: 60 * min, read: func(from, to int64) ([]query.Event, error) {
		reads++
		var out []query.Event
		for _, ev := range all {
			if ev.TS >= from && ev.TS <= to {
				out = append(out, ev)
			}
		}
		return out, nil
	}}
	pids := func(l []string) (s []string) {
		for _, x := range l[1:] {
			f := strings.Fields(x)
			if f[0] == "▸" {
				f = f[1:]
				s = append(s, "▸"+f[3])
			} else {
				s = append(s, f[3])
			}
		}
		return
	}
	// The cursor at 21 minutes: 3 events before (8, 12, 16 minutes: across
	// a span boundary at 20), ▸ on 24, then whole spans up to at least 3 rows.
	got := pids(e.at(21*min, 3))
	if want := []string{"3", "4", "5", "▸6", "7", "8", "9"}; !slices.Equal(got, want) {
		t.Errorf("at 21 min: %q, want %q", got, want)
	}
	n := reads
	e.at(21*min, 3)
	if reads != n {
		t.Errorf("read again: %d reads, then %d", n, reads)
	}
	if got := e.at(50*min, 3); !strings.Contains(got[len(got)-1], "no events") {
		t.Errorf("after the last: %q", got)
	}

	// Between marks: 12 to 24 minutes inclusive, across a span boundary.
	got = pids(e.between(12*min, 24*min, 100)[1:])
	if want := []string{"3", "4", "5", "6"}; !slices.Equal(got, want) {
		t.Errorf("between 12 and 24 min: %q, want %q", got, want)
	}
	if l := e.between(0, 60*min, 2); len(l) != 4 || !strings.Contains(l[0], "the first 2") {
		t.Errorf("limited: %q", l)
	}
	if l := e.between(41*min, 43*min, 100); len(l) != 1 || !strings.HasSuffix(l[0], ": 0") {
		t.Errorf("none: %q", l)
	}
}

func TestTUICompare(t *testing.T) {
	u := testTUI()
	var asked [2]int64
	u.diff = func(pane int, a, b int64, width int) []string {
		asked = [2]int64{a, b}
		return []string{"diff of " + tuiPanes[pane].name}
	}
	u.cur = 30
	u.key("d")
	if u.compare || !strings.Contains(u.msg, "m on one sample") {
		t.Fatalf("d without marks: compare %v, %q", u.compare, u.msg)
	}
	u.key("m")
	u.key("m") // the same sample: not B
	if u.markB >= 0 || !strings.Contains(u.msg, "another sample") {
		t.Fatalf("B on A: %d, %q", u.markB, u.msg)
	}
	u.cur = 12
	u.key("m") // B before A: the later one is B
	if u.markA != 12 || u.markB != 30 {
		t.Fatalf("marks %d %d", u.markA, u.markB)
	}
	u.key("d")
	u.cur = 0 // the cursor's ▼ covers a mark under it
	scr := u.screen()
	if !u.compare || asked != [2]int64{u.points[12].ts, u.points[30].ts} || !strings.Contains(scr, "diff of top") {
		t.Fatalf("compare %v, asked %v", u.compare, asked)
	}
	ruler := []rune(strings.Split(scr, "\r\n")[1])
	if a, b := ruler[tuiLabelW+u.col(u.points[12].ts)], ruler[tuiLabelW+u.col(u.points[30].ts)]; a != 'A' || b != 'B' {
		t.Errorf("ruler %q", string(ruler))
	}
	u.cur = 0
	u.key("b")
	if u.cur != 30 {
		t.Errorf("b: %d", u.cur)
	}
	u.key("a")
	if u.cur != 12 {
		t.Errorf("a: %d", u.cur)
	}
	u.key("d")
	if u.compare || !strings.Contains(u.screen(), "top") {
		t.Error("d does not go back")
	}
	u.key("d")
	u.key("m") // a third m starts again at A
	if u.markA != 12 || u.markB != -1 || u.compare {
		t.Errorf("third m: %d %d %v", u.markA, u.markB, u.compare)
	}
	u.key("M")
	if u.markA != -1 || u.markB != -1 {
		t.Errorf("M: %d %d", u.markA, u.markB)
	}
	if lines := strings.Split(u.screen(), "\r\n"); len(lines) != u.height {
		t.Errorf("%d lines", len(lines))
	}
}
