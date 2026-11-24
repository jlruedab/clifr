package main

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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
	u.diff = func(pane int, a, b int64, width int) ([]string, []string) {
		asked = [2]int64{a, b}
		if pane == 4 { // free: two outputs to lay out
			return []string{"free at A"}, []string{"free at B"}
		}
		return []string{"diff of " + tuiPanes[pane].name}, nil
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
	u.key("5")
	if l := u.paneAB(); len(l) != 2 || !strings.HasPrefix(l[1], "free at A") || !strings.HasSuffix(l[1], "│ free at B") {
		t.Errorf("side by side: %q", l)
	}
	u.key("v")
	if l := u.paneAB(); len(l) != 5 || l[1] != "free at A" || l[4] != "free at B" {
		t.Errorf("stacked: %q", l)
	}
	u.key("v")
	u.key("1")
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

func TestTUISideBySide(t *testing.T) {
	from := time.Date(2026, 11, 23, 2, 40, 0, 0, time.Local).UnixMilli()
	got := tuiSideBySide([]string{"Mem: 100", "Swap: 1", "a line longer than half the pane"}, []string{"Mem: 90"}, from, from+60_000, 43)
	if len(got) != 4 {
		t.Fatalf("%d lines: %q", len(got), got)
	}
	for i, l := range got[1:] {
		if p := strings.Index(l, "│"); utf8.RuneCountInString(l[:p]) != 21 {
			t.Errorf("line %d: divider at %d: %q", i+1, utf8.RuneCountInString(l[:p]), l)
		}
	}
	if !strings.HasPrefix(got[1], "Mem: 100 ") || !strings.HasSuffix(got[1], "│ Mem: 90") || !strings.HasPrefix(got[3], "a line longer than h") {
		t.Errorf("%q", got)
	}
}

func TestTUIPlay(t *testing.T) {
	u := testTUI()
	last := len(u.points) - 1
	u.cur = last
	if u.tick() != 0 {
		t.Fatal("ticks while paused")
	}
	u.key(" ") // at the end: plays from the start
	if !u.playing || u.cur != 0 || u.tick() != tuiSpeeds[0] {
		t.Fatalf("play: %v at %d, tick %v", u.playing, u.cur, u.tick())
	}
	u.key("+")
	u.key("+")
	if u.tick() != tuiSpeeds[2] {
		t.Errorf("faster: %v", u.tick())
	}
	u.key("Tick")
	u.key("Tick")
	if u.cur != 2 {
		t.Errorf("two ticks: %d", u.cur)
	}
	u.cur = last - 1
	u.key("Tick")
	if u.cur != last || u.playing {
		t.Errorf("at the end: %d, playing %v", u.cur, u.playing)
	}
	u.key("Tick")
	if u.cur != last {
		t.Errorf("tick after the end: %d", u.cur)
	}
}

func TestTUIFilterKeys(t *testing.T) {
	u := testTUI()
	u.render = func(pane int, ts int64, width int) []string {
		return []string{"USER PID COMMAND", "root 1 systemd", "alice 2 Firefox", "bob 3 bash"}
	}
	for _, k := range []string{"/", "f", "I", "x", "Backspace", "R", "e", "Enter"} {
		u.key(k)
	}
	if u.filter != "fIRe" || u.prompt != nil {
		t.Fatalf("filter %q, prompt %v", u.filter, u.prompt)
	}
	scr := u.screen()
	if !strings.Contains(scr, "alice 2 Firefox") || strings.Contains(scr, "bob 3") || !strings.Contains(scr, "USER PID") {
		t.Errorf("filtered pane:\n%s", scr)
	}
	u.key("/")
	u.key("q") // typed, not quit
	if u.prompt == nil || *u.prompt != "fIReq" {
		t.Fatalf("prompt %v", u.prompt)
	}
	u.key("Esc")
	if u.filter != "fIRe" || u.prompt != nil {
		t.Errorf("Esc: %q", u.filter)
	}
	// A bad pattern keeps the prompt open and says why.
	u.key("/")
	u.key("(")
	u.key("Enter")
	if u.prompt == nil || u.filter != "fIRe" || !strings.Contains(u.screen(), "bad pattern") {
		t.Fatalf("bad pattern: prompt %v, filter %q", u.prompt, u.filter)
	}
	u.key("Backspace")
	u.key("Enter")
	if u.prompt != nil || u.filter != "fIRe" {
		t.Errorf("fixed: prompt %v, filter %q", u.prompt, u.filter)
	}
	u.key("/")
	for range 5 {
		u.key("Backspace")
	}
	u.key("Enter")
	if u.filter != "" || !strings.Contains(u.screen(), "bob 3") {
		t.Errorf("cleared: %q", u.filter)
	}
}

func TestTUIFilter(t *testing.T) {
	top := []string{"top - 10:00", "Tasks: 3", "", "  PID USER COMMAND", "  1 root systemd", "  2 alice firefox"}
	re := func(s string) *regexp.Regexp {
		r, err := tuiFilterRE(s)
		if err != nil {
			panic(err)
		}
		return r
	}
	if got := tuiFilter(top, re("FIRE"), "FIRE"); !slices.Equal(got, []string{"top - 10:00", "Tasks: 3", "", "  PID USER COMMAND", "  2 alice firefox"}) {
		t.Errorf("top: %q", got)
	}
	diff := []string{"# ps, A -> B: 1 appeared", "## appeared", "USER PID", "alice 2 firefox", "## gone", "USER PID", "bob 3 bash"}
	if got := tuiFilter(diff, re("bash$"), "bash$"); !slices.Equal(got, []string{"# ps, A -> B: 1 appeared", "## appeared", "## gone", "bob 3 bash"}) {
		t.Errorf("diff: %q", got)
	}
	if got := tuiFilter([]string{"H", "a"}, re("zz"), "zz"); len(got) != 2 || !strings.Contains(got[1], "no line") {
		t.Errorf("none: %q", got)
	}
	// A regular expression: alternatives, anchors; a dot matches itself too.
	ps := []string{"USER PID", "root 1 /sbin/init", "alice 2 nginx", "bob 3 postgres", "carol 4 10.0.0.1:443"}
	if got := tuiFilter(ps, re("nginx|postgres"), ""); !slices.Equal(got, []string{"USER PID", "alice 2 nginx", "bob 3 postgres"}) {
		t.Errorf("alternatives: %q", got)
	}
	if got := tuiFilter(ps, re("^root"), ""); !slices.Equal(got, []string{"USER PID", "root 1 /sbin/init"}) {
		t.Errorf("anchor: %q", got)
	}
	if got := tuiFilter(ps, re(`10.0.0.1:(80|443)\b`), ""); !slices.Equal(got, []string{"USER PID", "carol 4 10.0.0.1:443"}) {
		t.Errorf("address: %q", got)
	}
	if r, err := tuiFilterRE("(nginx"); r != nil || err == nil || !strings.Contains(err.Error(), "missing closing )") || strings.Contains(err.Error(), "(?i)") {
		t.Errorf("bad pattern: %v", err)
	}
	if r, err := tuiFilterRE(""); r != nil || err != nil {
		t.Errorf("empty: %v %v", r, err)
	}
}

func TestTUIUnwritten(t *testing.T) {
	u := testTUI()
	u.points = u.points[:len(u.points)-12] // the last 2 minutes not on disk
	if r := []rune(string(u.markRow())); r[u.cols()-1] != '░' {
		t.Errorf("a past window's end without samples: %q", r[u.cols()-1])
	}
	u.unwritten = true
	r := []rune(string(u.markRow()))
	if r[u.cols()-1] != '┈' || r[u.col(u.points[len(u.points)-1].ts)] == '┈' {
		t.Errorf("not on disk yet: %q", string(r))
	}
}

func TestTUITabRow(t *testing.T) {
	u := testTUI()
	ansi := regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")
	for _, width := range []int{40, 80, 200} {
		u.width = width
		u.compare, u.playing, u.filter = width == 80, true, "firefox"
		for i := range tuiPanes {
			u.setPane(i)
			row := u.tabRow()
			plain := ansi.ReplaceAllString(row, "")
			if n := utf8.RuneCountInString(plain); n > width {
				t.Errorf("width %d, pane %s: %d columns: %q", width, tuiPanes[i].name, n, plain)
			}
			if !strings.Contains(row, tuiRev+" "+tuiPanes[i].name+" ") {
				t.Errorf("width %d: pane %s not shown: %q", width, tuiPanes[i].name, plain)
			}
		}
	}
	if u.width = 200; strings.ContainsAny(ansi.ReplaceAllString(u.tabRow(), ""), "‹›") {
		t.Error("‹ › when every pane fits")
	}
	// dmesg opens at its end; 0 is the tenth pane.
	u.render = func(pane int, ts int64, width int) []string {
		l := make([]string, 100)
		for i := range l {
			l[i] = fmt.Sprintf("line %d", i)
		}
		return l
	}
	u.filter, u.compare, u.playing = "", false, false
	u.setPane(slices.IndexFunc(tuiPanes, func(p tuiPane) bool { return p.name == "dmesg" }))
	if scr := u.screen(); !strings.Contains(scr, "line 99") || strings.Contains(scr, "line 0\x1b") {
		t.Errorf("dmesg not at its end")
	}
	u.key("0")
	if u.pane != 9 || u.scroll != 0 {
		t.Errorf("0: pane %d, scroll %d", u.pane, u.scroll)
	}
}

func TestTUISpanPane(t *testing.T) {
	u := testTUI()
	oom := slices.IndexFunc(tuiPanes, func(p tuiPane) bool { return p.name == "oom" })
	if oom < 0 || !tuiPanes[oom].span {
		t.Fatal("no oom pane over the window")
	}
	renders := 0
	u.render = func(pane int, ts int64, width int) []string { renders++; return []string{"kills"} }
	u.setPane(oom)
	for _, k := range []string{"Left", "Left", "Home", "End"} {
		u.key(k)
		u.screen()
	}
	if renders != 1 {
		t.Errorf("rendered %d times: the window's kills do not move with the cursor", renders)
	}
}

func TestTUIZoom(t *testing.T) {
	// A recording of 6 hours, a sample every 10 s; the clock at its end.
	start := time.Date(2026, 11, 23, 10, 0, 0, 0, time.Local).UnixMilli()
	end := start + 6*3600_000
	loads := 0
	u := &tui{width: 100, height: 30, cache: map[tuiKey][]string{}, markA: -1, markB: -1,
		now: func() int64 { return end }}
	u.load = func(from, to int64) error {
		loads++
		u.from, u.to, u.points = from, to, nil
		for ts := start; ts <= end; ts += 10_000 {
			if ts >= from && ts <= to {
				u.points = append(u.points, tuiPoint{ts: ts})
			}
		}
		u.render = func(pane int, ts int64, width int) []string { return []string{"x"} }
		return nil
	}
	// The last hour, the cursor at 15:30.
	u.load(end-3600_000, end)
	u.cur = u.at(start+5*3600_000+1800_000, -1)
	c := u.points[u.cur].ts
	u.key("m")
	u.key("Left")
	u.key("m") // A 15:29:50, B 15:30:00
	u.key("Right")
	u.key("z") // 15 minutes around 15:30
	if u.to-u.from != 900_000 || u.points[u.cur].ts != c || u.from > c || u.to < c {
		t.Errorf("z: %s .. %s, cursor %s", query.FormatMS(u.from), query.FormatMS(u.to), query.FormatMS(u.points[u.cur].ts))
	}
	if u.markA < 0 || u.markB < 0 || u.points[u.markB].ts != c {
		t.Errorf("marks after z: %d %d", u.markA, u.markB)
	}
	for range 3 {
		u.key("z")
	}
	if u.to-u.from != tuiMinSpan || !strings.Contains(u.msg, "narrowest") {
		t.Errorf("narrowest: %d ms, %q", u.to-u.from, u.msg)
	}
	// Out: 20 minutes, 80, then 5h20 (up to now), then the recording's start.
	for _, want := range []int64{20 * 60_000, 80 * 60_000, 320 * 60_000} {
		u.key("Z")
		if u.to-u.from != want {
			t.Errorf("Z: %d min, want %d", (u.to-u.from)/60_000, want/60_000)
		}
		if u.to > end {
			t.Errorf("Z past now: %s", query.FormatMS(u.to))
		}
	}
	if u.to != end {
		t.Errorf("a window up to now stays up to now: %s", query.FormatMS(u.to))
	}
	u.key("Z")
	if u.from != start || u.to != end || u.points[u.cur].ts != c {
		t.Errorf("whole recording: %s .. %s, cursor %s", query.FormatMS(u.from), query.FormatMS(u.to), query.FormatMS(u.points[u.cur].ts))
	}
	u.key("Z")
	if u.from != start || !strings.Contains(u.msg, "whole recording") {
		t.Errorf("past the start: %s, %q", query.FormatMS(u.from), u.msg)
	}
	// A mark outside the new window goes; B alone becomes A.
	u.key("Home")
	u.key("m")
	u.key("End")
	u.key("m")
	u.cur = u.at(end-60_000, -1)
	u.key("z")
	if u.markA != -1 && u.points[u.markA].ts != end || u.markB != -1 || u.compare {
		t.Errorf("marks out of the window: %d %d %v", u.markA, u.markB, u.compare)
	}
}
