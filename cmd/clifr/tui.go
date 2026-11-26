package main

// clifr tui: a recording's window in the terminal. A timeline of the system
// (CPU, memory, load, I/O pressure as sparklines; OOM kills as marks), a
// cursor moved sample by sample, and a pane with a command's reconstruction
// at the cursor. The recording is opened once and every pane is rendered
// in this process by the same code as the command line (runCtx, the tools'
// prepare), written through the same terminal filter.

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"clifr/internal/duck"
	"clifr/internal/query"
	"clifr/internal/store"
)

// tuiPanes are the commands the pane shows, in tab order. %W is the pane's
// width.
var tuiPanes = []tuiPane{
	{name: "top", cmd: "top -b -n 1 -w %W"},
	{name: "ps", cmd: "ps aux"},
	{name: "ss", cmd: "ss -tanp"},
	{name: "lsof", cmd: "lsof -i"},
	{name: "free", cmd: "free -m"},
	{name: "vmstat", cmd: "vmstat"},
	{name: "iostat", cmd: "iostat -x"},
	{name: "events"}, // clifr events over the window, from the cursor on
	{name: "oom", cmd: "oom", span: true},
	{name: "df", cmd: "df -h"},
	{name: "mpstat", cmd: "mpstat -P ALL"},
	{name: "iotop", cmd: "iotop -b -o"},
	{name: "pstree", cmd: "pstree -p"},
	{name: "dmesg", cmd: "dmesg -T", tail: true},
	{name: "w", cmd: "w"},
	{name: "containers", cmd: "containers"},
	{name: "systemctl", cmd: "systemctl list-units --type=service"},
}

// tuiPane is a pane: cmd run at the cursor's sample (%W: the pane's width).
// tail: it opens at its end (dmesg: the messages nearest the cursor); span:
// cmd runs over the whole window instead, and over A to B in a comparison
// (oom: at a moment it looks only a minute either side).
type tuiPane struct {
	name, cmd  string
	tail, span bool
}

// tuiDefaultSpan is the window without --since: the last hour.
const tuiDefaultSpan = time.Hour

// tuiPoint is one system sample of the timeline. CPU and PSI are over the
// interval since the previous sample (-1: unknown, the first one).
type tuiPoint struct {
	ts                 int64
	cpu, mem, load, io float64 // percent, percent, load average, percent
}

// tuiMark is an event on the timeline.
type tuiMark struct {
	ts    int64
	sym   string
	text  string
	after bool // n/N go to the first sample after it (a boot), not the last before
}

// sample is the sample n/N go to for the mark: the last before it (the
// state the event hit), for a boot the first after it.
func (u *tui) sample(m tuiMark) int {
	if m.after {
		return u.at(m.ts, 1)
	}
	return u.at(m.ts, -1)
}

// tui is the state of the view; it knows nothing of the terminal, so it can
// be tested (render is the only part that reads the recording).
type tui struct {
	host     string
	from, to int64
	points   []tuiPoint
	marks    []tuiMark
	cur      int // index into points
	pane     int
	scroll   int
	width    int
	height   int
	help     bool // ? shows the keys and the symbols in the pane
	color    bool // ANSI colors (not with NO_COLOR)
	render   func(pane int, ts int64, width int) []string
	cache    map[tuiKey][]string
	// Marks A and B (sample indexes, -1: not set); with compare the pane
	// shows what changed from A to B instead of the cursor's moment.
	markA, markB int
	compare      bool
	stacked      bool // v: A above B, not side by side
	// diff renders a comparison: one list (right nil), or A's and B's
	// output to lay out.
	diff  func(pane int, a, b int64, width int) (left, right []string)
	pairs map[tuiKey][2][]string
	msg   string // a note for the event line until the next key
	// Space plays: the cursor moves one sample every tuiSpeeds[speed].
	playing bool
	speed   int
	// / filters the pane: its header and the lines filterRE (filter, a
	// regular expression, any case) matches; prompt is the text being typed
	// (nil: not typing), promptErr why Enter did not take it.
	filter    string
	filterRE  *regexp.Regexp
	prompt    *string
	promptErr string
	// unwritten: the window runs on past the last sample on disk by less
	// than clifrd's flush interval: shaded as not on disk yet.
	unwritten bool
	// load reads the window [from, to] (z, Z); now is the clock.
	load func(from, to int64) error
	now  func() int64
}

// tuiSpeeds are the play speeds, slowest first.
var tuiSpeeds = []time.Duration{2 * time.Second, time.Second, 500 * time.Millisecond, 250 * time.Millisecond, 100 * time.Millisecond}

type tuiKey struct {
	pane, width int
	ts, a, b    int64 // a, b: a comparison's marks
}

func cmdTUI(g *globals) error {
	if len(g.ats) > 0 {
		return usageError{errors.New("tui: give a window with --since/--until (default: the last hour), not --at")}
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) || !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("tui: needs a terminal")
	}
	saved := query.HeaderOut
	query.HeaderOut = io.Discard // resolve's "time:" line
	if g.since == "" {
		g.since = "-1h"
	}
	w, err := resolve(g, true)
	query.HeaderOut = saved
	if err != nil {
		return err
	}
	g.plain = true // the tools print, they do not page
	u := &tui{cache: map[tuiKey][]string{}, color: os.Getenv("NO_COLOR") == "", markA: -1, markB: -1, speed: 2,
		now: func() int64 { return time.Now().UnixMilli() }}
	var db *store.DB
	var loaded duck.Window
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	// load shows [from, to]: a window inside the one loaded reuses it (z),
	// another is read (Z). Nothing changes on an error.
	u.load = func(from, to int64) error {
		d, win := db, loaded
		if d == nil || from < win.From || to > win.To {
			nd, err := openWindow(g, duck.Window{From: from, To: to})
			if err != nil {
				return err
			}
			d, win = nd, duck.Window{From: from, To: to}
		}
		pts, err := tuiPoints(d, from, to)
		if err == nil && len(pts) == 0 {
			err = fmt.Errorf("tui: no system samples between %s and %s", query.FormatMS(from), query.FormatMS(to))
		}
		var marks []tuiMark
		if err == nil {
			marks, err = tuiMarks(d, from, to)
		}
		if err != nil {
			if d != db {
				d.Close()
			}
			return err
		}
		if d != db {
			if db != nil {
				db.Close()
			}
			db, loaded = d, win
		}
		ev := &tuiEvents{db: d, from: from, to: to}
		u.from, u.to, u.points, u.marks = from, to, pts, marks
		u.unwritten = tuiUnwritten(d, pts[len(pts)-1].ts, to, u.now())
		u.render = func(pane int, ts int64, width int) []string {
			switch {
			case tuiPanes[pane].name == "events":
				return ev.at(ts, 3*u.paneHeight()) // room to scroll
			case tuiPanes[pane].span:
				return tuiCaptureSpan(g, d, tuiPanes[pane].cmd, u.from, u.to)
			}
			return tuiRender(g, d, pane, ts, width)
		}
		u.diff = func(pane int, a, b int64, width int) ([]string, []string) {
			return tuiCompare(g, d, ev, pane, a, b, width)
		}
		clear(u.cache)
		u.pairs = nil
		return nil
	}
	splash := showSplash(u.color, w.From, w.To)
	err = u.load(w.From, w.To)
	splash(err == nil)
	if err != nil {
		return err
	}
	u.cur = len(u.points) - 1
	if h := tuiCapture(g, db, "hostname", u.points[u.cur].ts); len(h) > 0 {
		u.host = strings.TrimSpace(h[0])
	}
	return u.run()
}

// tuiMinSpan is the narrowest window z zooms to.
const tuiMinSpan = int64(5 * time.Minute / time.Millisecond)

// zoom is z (in: a quarter of the window) and Z (out: four times it),
// around the cursor; out stops at now and at the recording's first sample.
// The cursor and the marks keep their times (a mark outside the new window
// goes).
func (u *tui) zoom(in bool) {
	span := u.to - u.from
	ns := span * 4
	if in {
		if span <= tuiMinSpan {
			u.msg = " z: the narrowest window (5 minutes); Z zooms out"
			return
		}
		ns = max(span/4, tuiMinSpan)
	}
	c := u.points[u.cur].ts
	from := c - ns/2
	to := from + ns
	if !in && u.to >= u.now()-time.Minute.Milliseconds() || to > u.now() {
		to = max(u.to, min(to, u.now())) // a window up to now stays up to now
		from = to - ns
	}
	if in {
		from, to = max(from, u.from), min(to, u.to)
		if to-from < ns { // near an end: the quarter at that end
			if from == u.from {
				to = from + ns
			} else {
				from = to - ns
			}
		}
	}
	marks := [2]int64{-1, -1}
	for i, m := range []int{u.markA, u.markB} {
		if m >= 0 {
			marks[i] = u.points[m].ts
		}
	}
	if err := u.load(from, to); err != nil {
		u.msg = " " + err.Error()
		return
	}
	if !in && u.points[0].ts > u.from { // the recording starts later
		u.from = u.points[0].ts
		if old := span; u.to-u.from <= old {
			u.msg = " Z: the whole recording up to the window's end is shown"
		}
	}
	u.cur = u.at(c, -1)
	u.markA, u.markB = -1, -1
	for i, ts := range marks {
		if j := u.at(ts, -1); ts >= 0 && u.points[j].ts == ts {
			if i == 0 {
				u.markA = j
			} else {
				u.markB = j
			}
		}
	}
	if u.markA < 0 || u.markB < 0 {
		u.compare = false
		if u.markB >= 0 { // B alone is A now
			u.markA, u.markB = u.markB, -1
		}
	}
}

// tuiUnwritten: the window reaches now, and its last sample is no older
// than clifrd's flush interval (and a half): the rest is still in clifrd's
// memory, not missing.
func tuiUnwritten(db *store.DB, last, to, now int64) bool {
	flush := 300.0
	var v string
	db.QueryRow(`SELECT value FROM meta WHERE key = 'flush_interval_s'`).Scan(&v)
	if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
		flush = f
	}
	return to >= now-time.Minute.Milliseconds() && now-last <= int64(flush*1500)
}

// tuiPoints reads the timeline: every system sample in [from, to].
func tuiPoints(db *store.DB, from, to int64) ([]tuiPoint, error) {
	rows, err := db.Query(`
		SELECT s.ts, s.mem_total, s.mem_available, s.load1,
			COALESCE(CAST(s.psi AS BIGINT), 0), COALESCE(s.psi_io_some, 0),
			c.user + c.nice + c.system + c.irq + c.softirq + c.steal,
			c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
		FROM sys_samples s JOIN cpu_samples c ON c.ts = s.ts AND c.cpu = -1
		WHERE s.ts BETWEEN ? AND ? ORDER BY s.ts`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tuiPoint
	var pts, pbusy, ptotal, pio int64
	for rows.Next() {
		var ts, memT, memA, load1, psi, io, busy, total int64
		if err := rows.Scan(&ts, &memT, &memA, &load1, &psi, &io, &busy, &total); err != nil {
			return nil, err
		}
		if len(out) > 0 && ts == pts {
			continue
		}
		p := tuiPoint{ts: ts, cpu: -1, io: -1, load: float64(load1) / 100}
		if memT > 0 {
			p.mem = 100 * float64(memT-memA) / float64(memT)
		}
		if len(out) > 0 {
			if d := total - ptotal; d > 0 {
				p.cpu = 100 * float64(busy-pbusy) / float64(d)
			}
			if psi != 0 && ts > pts && io >= pio {
				p.io = min(100, 100*float64(io-pio)/float64((ts-pts)*1000))
			}
		}
		out = append(out, p)
		pts, pbusy, ptotal, pio = ts, busy, total, io
	}
	return out, rows.Err()
}

// tuiMarkOrder: which symbol a column shows when several events fall in it
// (the first of this list), and the legend.
var tuiMarkOrder = []struct{ sym, name, color string }{
	{"✕", "OOM kill", tuiRed}, {"▲", "unit failed", tuiRed}, {"↻", "boot", tuiYellow},
	{"↺", "unit restarting", tuiYellow}, {"◆", "memory balloon or MemTotal changed", tuiYellow}, {"●", "login", tuiCyan}, {"○", "logout", tuiCyan},
	{"░", "no samples", tuiDim}, {"┈", "not on disk yet (clifrd writes every few minutes)", tuiDim},
}

// The colors.
const (
	tuiRed    = "\x1b[1;31m"
	tuiYellow = "\x1b[33m"
	tuiGreen  = "\x1b[32m"
	tuiCyan   = "\x1b[36m"
)

// paint colors s (nothing without colors).
func (u *tui) paint(color, s string) string {
	if !u.color || color == "" {
		return s
	}
	return color + s + tuiReset
}

// symColor is a mark's color.
func symColor(sym string) string {
	for _, m := range tuiMarkOrder {
		if m.sym == sym {
			return m.color
		}
	}
	return ""
}

// levelColor colors a graph's cell by its height: green, yellow from half,
// red from three quarters.
func levelColor(cell string) string {
	i := strings.Index(sparks, cell) / len("▁")
	switch {
	case cell == " ":
		return ""
	case i >= 6:
		return tuiRed
	case i >= 4:
		return tuiYellow
	}
	return tuiGreen
}

// tuiMarks reads the events the timeline marks: OOM kills, boots, logins
// and logouts, units that failed or are restarted by systemd (Restart=),
// and the recorder's gaps. Texts quote recorded values: termSafe before
// they are printed.
func tuiMarks(db *store.DB, from, to int64) ([]tuiMark, error) {
	var out []tuiMark
	kills, err := query.OOMKills(db, from, to, 0)
	if err != nil {
		return nil, err
	}
	for _, k := range kills {
		t := fmt.Sprintf("OOM kill: PID %d, %s: %s", k.PID, tuiSize(k.RSSKB), k.Command)
		if k.Constraint == "cgroup" {
			t = fmt.Sprintf("OOM kill at a cgroup's limit: PID %d, %s: %s", k.PID, tuiSize(k.RSSKB), k.Command)
		}
		out = append(out, tuiMark{ts: k.TS, sym: "✕", text: t})
	}
	boots, err := query.Boots(db, to)
	if err != nil {
		return nil, err
	}
	for i, bt := range boots {
		if bt.BootMS < from || bt.BootMS > to {
			continue
		}
		t := "boot"
		if bt.Kernel != "" {
			t += ", kernel " + bt.Kernel
		}
		if i > 0 && boots[i-1].Crashed {
			t += fmt.Sprintf("; the previous boot crashed (last sample %s)", query.FormatMS(boots[i-1].LastMS))
		}
		out = append(out, tuiMark{ts: bt.BootMS, sym: "↻", text: t, after: true})
	}
	if recs, ok, err := query.LoginRecords(db, to, boots); err != nil {
		return nil, err
	} else if ok {
		users := map[string]string{} // line -> user, for logouts
		for _, r := range recs {
			switch r.Type {
			case query.UtUserProcess:
				users[r.Line] = r.User
				if r.TimeMS >= from && r.TimeMS <= to {
					t := fmt.Sprintf("login: %s on %s", r.User, r.Line)
					if r.Host != "" {
						t += " from " + r.Host
					}
					out = append(out, tuiMark{ts: r.TimeMS, sym: "●", text: t})
				}
			case query.UtDeadProcess:
				if r.TimeMS >= from && r.TimeMS <= to {
					t := "logout: " + r.Line
					if u := users[r.Line]; u != "" {
						t = fmt.Sprintf("logout: %s on %s", u, r.Line)
					}
					out = append(out, tuiMark{ts: r.TimeMS, sym: "○", text: t})
				}
			}
		}
	}
	units, err := tuiUnitMarks(db, from, to)
	if err != nil {
		return nil, err
	}
	out = append(out, units...)
	balloons, err := query.BalloonChanges(db, from, to)
	if err != nil {
		return nil, err
	}
	for _, b := range balloons {
		out = append(out, tuiMark{ts: b.TS, sym: "◆", text: query.BalloonText(b), after: true})
	}
	gaps, err := query.Events(db, from, to, nil, map[string]bool{"gap": true})
	if err != nil {
		return nil, err
	}
	for _, g := range gaps {
		out = append(out, tuiMark{ts: g.TS, sym: "░", text: "recorder gap: " + g.Detail})
	}
	slices.SortStableFunc(out, func(a, b tuiMark) int { return cmp.Compare(a.ts, b.ts) })
	return out, nil
}

// tuiUnitMarks: units entering the failed state, and services systemd is
// about to restart (sub state auto-restart). A unit's repeated rows in the
// same state are one mark.
func tuiUnitMarks(db *store.DB, from, to int64) ([]tuiMark, error) {
	rows, err := db.Query(`SELECT ts, name, active, sub FROM units
		WHERE action = 'change' AND ts BETWEEN ? AND ? ORDER BY ts, seq`, from, to)
	if err != nil {
		return nil, nil // no units table (recorded since schema 7)
	}
	defer rows.Close()
	var out []tuiMark
	last := map[string]string{}
	for rows.Next() {
		var ts int64
		var name, active, sub string
		if err := rows.Scan(&ts, &name, &active, &sub); err != nil {
			return nil, err
		}
		state := active + "/" + sub
		if last[name] == state {
			continue
		}
		last[name] = state
		switch {
		case active == "failed":
			out = append(out, tuiMark{ts: ts, sym: "▲", text: "unit failed: " + name})
		case sub == "auto-restart":
			out = append(out, tuiMark{ts: ts, sym: "↺", text: "unit restarting (Restart=): " + name})
		}
	}
	return out, rows.Err()
}

func tuiSize(kb int64) string {
	switch {
	case kb >= 1<<20:
		return fmt.Sprintf("%.1f GiB", float64(kb)/(1<<20))
	case kb >= 1<<10:
		return fmt.Sprintf("%d MiB", kb>>10)
	}
	return fmt.Sprintf("%d KiB", kb)
}

// tuiRender is a pane: its command at ts, as clifr --at prints it.
func tuiRender(g *globals, db *store.DB, pane int, ts int64, width int) []string {
	cmd := strings.ReplaceAll(tuiPanes[pane].cmd, "%W", fmt.Sprint(max(width, 80)))
	return tuiCapture(g, db, cmd, ts)
}

// tuiCompare is a pane comparing marks A and B: clifr diff for the commands
// with rows to compare, the events between them (one list each), else A's
// and B's output.
func tuiCompare(g *globals, db *store.DB, ev *tuiEvents, pane int, a, b int64, width int) (left, right []string) {
	name := tuiPanes[pane].name
	switch {
	case name == "events":
		return ev.between(a, b, tuiCompareMax), nil
	case tuiPanes[pane].span:
		return tuiCaptureSpan(g, db, tuiPanes[pane].cmd, a, b), nil
	}
	cmd := strings.ReplaceAll(tuiPanes[pane].cmd, "%W", fmt.Sprint(max(width, 80)))
	if t := tools[name]; t.diff {
		return tuiCapture(g, db, cmd, a, b), nil
	}
	return tuiCapture(g, db, cmd, a), tuiCapture(g, db, cmd, b)
}

// tuiStacked puts A's output above B's.
func tuiStacked(top, bottom []string, a, b int64, width int) []string {
	out := []string{tuiRule("A "+query.FormatMS(a), width)}
	out = append(out, top...)
	out = append(out, "", tuiRule("B "+query.FormatMS(b), width))
	return append(out, bottom...)
}

// tuiSideBySide puts A's output on the left and B's on the right, each cut
// to half the pane.
func tuiSideBySide(left, right []string, a, b int64, width int) []string {
	half := max((width-3)/2, 10)
	pad := func(s string) string {
		s = fit(s, half)
		return s + strings.Repeat(" ", half-utf8.RuneCountInString(s))
	}
	out := []string{pad(tuiRule("A "+query.FormatMS(a), half)) + " │ " + tuiRule("B "+query.FormatMS(b), half)}
	for i := range max(len(left), len(right)) {
		var l, r string
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		out = append(out, pad(l)+" │ "+r)
	}
	return out
}

// tuiCompareMax is the most events the comparison lists.
const tuiCompareMax = 2000

// tuiRule is a title in a line across the pane.
func tuiRule(title string, width int) string {
	return "── " + title + " " + strings.Repeat("─", max(width-utf8.RuneCountInString(title)-4, 0))
}

// tuiEvents is the events pane: clifr events from a few before the cursor
// on, "▸" on the first at or after it. Read in stretches around the cursor:
// a busy host's whole window can hold millions of process events.
type tuiEvents struct {
	db       *store.DB
	from, to int64
	read     func(from, to int64) ([]query.Event, error) // query.Events; tests replace it
	cache    map[int64]tuiEventSpan
}

type tuiEventSpan struct {
	header string
	evs    []query.Event
	lines  []string
	err    error
}

// tuiSentBy: the events pane's SENT BY width (the pane prints one event
// at a time, so its columns cannot be sized to the window's events).
const tuiSentBy = 24

const (
	tuiEventsBefore = 3                                          // events shown before the cursor's
	tuiEventsSpan   = int64(10 * time.Minute / time.Millisecond) // read this much at a time
	tuiEventsLook   = int64(time.Hour / time.Millisecond)        // and look this far back or ahead
)

// span reads the events of [start, start+tuiEventsSpan), cut to the window.
func (e *tuiEvents) span(start int64) tuiEventSpan {
	if sp, ok := e.cache[start]; ok {
		return sp
	}
	if e.cache == nil || len(e.cache) > 50 {
		e.cache = map[int64]tuiEventSpan{}
	}
	if e.read == nil {
		e.read = func(from, to int64) ([]query.Event, error) { return query.Events(e.db, from, to, nil, nil) }
	}
	var sp tuiEventSpan
	from, to := max(start, e.from), min(start+tuiEventsSpan-1, e.to)
	if from <= to {
		var evs []query.Event
		evs, sp.err = e.read(from, to)
		for _, ev := range evs {
			if ev.TS < from || ev.TS > to { // a span reads [from, to] inclusive
				continue
			}
			var b bytes.Buffer
			t := &termWriter{w: &b}
			query.PrintEventsWidth(t, []query.Event{ev}, tuiSentBy)
			t.Flush()
			l := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
			sp.header = l[0]
			sp.evs = append(sp.evs, ev)
			sp.lines = append(sp.lines, strings.Join(l[1:], " "))
		}
	}
	e.cache[start] = sp
	return sp
}

// at is the pane at ts, with at least rows lines when there are events.
func (e *tuiEvents) at(ts int64, rows int) []string {
	start := ts - (ts-e.from)%tuiEventsSpan
	var before []string
	for s := start - tuiEventsSpan; s >= max(e.from-tuiEventsSpan, start-tuiEventsLook) && len(before) < tuiEventsBefore; s -= tuiEventsSpan {
		sp := e.span(s)
		if sp.err != nil {
			return []string{termSafe("clifr: " + sp.err.Error())}
		}
		before = append(slices.Clone(sp.lines), before...)
		if s < e.from {
			break
		}
	}
	header := query.EventsHeader(tuiSentBy)
	var after []string
	marked := false
	for s := start; s <= min(e.to, start+tuiEventsLook) && len(after) < rows; s += tuiEventsSpan {
		sp := e.span(s)
		if sp.err != nil {
			return []string{termSafe("clifr: " + sp.err.Error())}
		}
		if sp.header != "" {
			header = sp.header
		}
		for i, ev := range sp.evs {
			if ev.TS < ts {
				before = append(before, sp.lines[i])
				continue
			}
			mark := "  "
			if !marked {
				mark, marked = "▸ ", true
			}
			after = append(after, mark+sp.lines[i])
		}
	}
	out := []string{"  " + header}
	for _, l := range before[max(len(before)-tuiEventsBefore, 0):] {
		out = append(out, "  "+l)
	}
	if !marked {
		after = append(after, "▸ (no events in the hour after the cursor)")
	}
	return append(out, after...)
}

// between lists the events from a to b, at most limit of them.
func (e *tuiEvents) between(a, b int64, limit int) []string {
	header := query.EventsHeader(tuiSentBy)
	var lines []string
	more := false
	for s := a - (a-e.from)%tuiEventsSpan; s <= b && !more; s += tuiEventsSpan {
		sp := e.span(s)
		if sp.err != nil {
			return []string{termSafe("clifr: " + sp.err.Error())}
		}
		if sp.header != "" {
			header = sp.header
		}
		for i, ev := range sp.evs {
			if ev.TS < a || ev.TS > b {
				continue
			}
			if len(lines) == limit {
				more = true
				break
			}
			lines = append(lines, "  "+sp.lines[i])
		}
	}
	title := fmt.Sprintf("events from A %s to B %s: %d", query.FormatMS(a), query.FormatMS(b), len(lines))
	switch {
	case more:
		title = fmt.Sprintf("events from A %s to B %s: the first %d (move A or B closer for the rest)", query.FormatMS(a), query.FormatMS(b), limit)
	case len(lines) == 0:
		return []string{title}
	}
	return append([]string{title, "  " + header}, lines...)
}

// tuiCapture runs one command at ts and returns its lines (an error as the
// only line); with two times it compares them, as clifr diff.
func tuiCapture(g *globals, db *store.DB, cmd string, ts ...int64) []string {
	var diff []int64
	if len(ts) == 2 {
		diff = ts
	}
	return tuiRun(g, db, cmd, query.Window{At: ts[len(ts)-1]}, diff, ts)
}

// tuiCaptureSpan runs one command over [from, to].
func tuiCaptureSpan(g *globals, db *store.DB, cmd string, from, to int64) []string {
	return tuiRun(g, db, cmd, query.Window{From: from, To: to}, nil, nil)
}

// tuiRun runs cmd over w (diff: two moments compared), after checking that
// the recording covers each of covered; its lines, or an error as the only
// line.
func tuiRun(g *globals, db *store.DB, cmd string, w query.Window, diff, covered []int64) []string {
	var out bytes.Buffer
	err := func() error {
		words, err := splitWords(cmd)
		if err != nil {
			return err
		}
		t := tools[words[0]]
		p, err := parseOpts(t.name, t.opts, words[1:])
		if err != nil {
			return err
		}
		savedOut, savedHdr, savedErr := outOverride, query.HeaderOut, stderr
		outOverride, query.HeaderOut, stderr = &out, io.Discard, &out // diff's "no differences" too
		defer func() { outOverride, query.HeaderOut, stderr = savedOut, savedHdr, savedErr }()
		at := w.At
		if w.IsRange() {
			at = w.To
		}
		c := &runCtx{g: g, w: w, db: db, diffAt: diff}
		for _, t := range covered {
			if err := query.Covered(db, t); err != nil {
				return err
			}
		}
		if _, err := query.LoadUsers(db, at); err != nil {
			return err
		}
		exec, err := t.prepare(p, c)
		if err != nil {
			return err
		}
		return exec()
	}()
	if err != nil {
		return []string{termSafe("clifr: " + err.Error())}
	}
	return strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
}

// The fixed lines around the pane.
const (
	tuiLabelW = 8 // "PSI io  "
	tuiValueW = 7 // "  100%"
	tuiTop    = 9 // header, ruler, 4 graphs, marks, axis, tabs
	tuiBottom = 2 // event line, keys
)

// cols is the timeline's width in columns.
func (u *tui) cols() int { return max(u.width-tuiLabelW-tuiValueW, 10) }

// col is the column of a time.
func (u *tui) col(ts int64) int {
	n := u.cols()
	span := max(u.to-u.from, 1)
	c := int((ts - u.from) * int64(n) / span)
	return min(max(c, 0), n-1)
}

const sparks = "▁▂▃▄▅▆▇█"

// spark is one graph row: each column the mean of its samples, scaled to
// [0, full]; a column without samples is blank.
func (u *tui) spark(val func(tuiPoint) float64, full float64) []string {
	n := u.cols()
	sum, cnt := make([]float64, n), make([]int, n)
	for _, p := range u.points {
		if v := val(p); v >= 0 {
			c := u.col(p.ts)
			sum[c] += v
			cnt[c]++
		}
	}
	out := make([]string, n)
	levels := []rune(sparks)
	for i := range out {
		if cnt[i] == 0 {
			out[i] = " "
			continue
		}
		l := int(sum[i] / float64(cnt[i]) / full * float64(len(levels)))
		out[i] = string(levels[min(max(l, 0), len(levels)-1)])
	}
	return out
}

// axis is the time scale: a label at each multiple of a step that leaves
// room for it.
func (u *tui) axis() string {
	n := u.cols()
	msPerCol := float64(u.to-u.from) / float64(n)
	steps := []time.Duration{time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute,
		15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 3 * time.Hour, 6 * time.Hour,
		12 * time.Hour, 24 * time.Hour}
	step := steps[len(steps)-1]
	for _, s := range steps {
		if float64(s.Milliseconds())/msPerCol >= 10 {
			step = s
			break
		}
	}
	line := []rune(strings.Repeat(" ", n))
	t0 := time.UnixMilli(u.from)
	_, off := t0.Zone()
	first := (u.from+int64(off)*1000+step.Milliseconds()-1)/step.Milliseconds()*step.Milliseconds() - int64(off)*1000
	for ts := first; ts <= u.to; ts += step.Milliseconds() {
		lbl := time.UnixMilli(ts).Format("15:04")
		if step >= 24*time.Hour {
			lbl = time.UnixMilli(ts).Format("01-02")
		}
		c := u.col(ts)
		if c+len(lbl) > n {
			break
		}
		copy(line[c:], []rune(lbl))
	}
	return string(line)
}

// key handles one key; true: quit.
func (u *tui) key(k string) bool {
	last := len(u.points) - 1
	if u.prompt != nil {
		return u.promptKey(k)
	}
	if k == "Tick" {
		if u.playing {
			u.cur = min(u.cur+1, last)
			u.playing = u.cur < last
		}
		return false
	}
	u.msg = ""
	switch k {
	case " ":
		u.playing = !u.playing
		if u.playing && u.cur == last {
			u.cur = 0
		}
	case "+", "=":
		u.speed = min(u.speed+1, len(tuiSpeeds)-1)
	case "-":
		u.speed = max(u.speed-1, 0)
	case "/":
		f := u.filter
		u.prompt = &f
	case "q", "Q", "Ctrl-C":
		return true
	case "?":
		u.help = !u.help
		return false
	case "Esc":
		if !u.help {
			return true
		}
	case "Left", "h":
		u.cur = max(u.cur-1, 0)
	case "Right", "l":
		u.cur = min(u.cur+1, last)
	case "S-Left", "H":
		u.cur = u.at(u.points[u.cur].ts-time.Minute.Milliseconds(), -1)
	case "S-Right", "L":
		u.cur = u.at(u.points[u.cur].ts+time.Minute.Milliseconds(), 1)
	case "Home":
		u.cur = 0
	case "End":
		u.cur = last
	case "n": // an event's sample is the last before it: the state it hit
		for _, m := range u.marks {
			if i := u.sample(m); i > u.cur {
				u.cur = i
				break
			}
		}
	case "N", "p":
		for j := len(u.marks) - 1; j >= 0; j-- {
			if i := u.sample(u.marks[j]); i < u.cur {
				u.cur = i
				break
			}
		}
	case "m":
		u.setMark()
	case "M":
		u.markA, u.markB, u.compare = -1, -1, false
	case "d":
		if u.markA < 0 || u.markB < 0 {
			u.msg = " d compares marks A and B: m on one sample, m on another, then d"
		} else {
			u.compare, u.scroll = !u.compare, 0
		}
	case "v":
		u.stacked, u.scroll = !u.stacked, 0
	case "z", "Z":
		u.zoom(k == "z")
	case "a", "b":
		if m := map[string]int{"a": u.markA, "b": u.markB}[k]; m >= 0 {
			u.cur = m
		}
	case "\t":
		u.setPane((u.pane + 1) % len(tuiPanes))
	case "S-Tab":
		u.setPane((u.pane + len(tuiPanes) - 1) % len(tuiPanes))
	case "Up", "k":
		u.scroll = max(u.scroll-1, 0)
	case "Down", "j":
		u.scroll++
	case "PgUp":
		u.scroll = max(u.scroll-u.paneHeight(), 0)
	case "PgDn":
		u.scroll += u.paneHeight()
	default:
		if i := strings.Index("1234567890", k); len(k) == 1 && i >= 0 && i < len(tuiPanes) {
			u.setPane(i)
		}
	}
	return false
}

// setPane shows pane i from its top, or its end (tail).
func (u *tui) setPane(i int) {
	u.pane, u.scroll = i, 0
	if tuiPanes[i].tail {
		u.scroll = math.MaxInt32 // screen cuts it to the last page
	}
}

// promptKey edits the filter being typed: Enter applies it (empty: no
// filter; a bad pattern: the prompt stays, saying why), Esc leaves it as it
// was.
func (u *tui) promptKey(k string) bool {
	if k != "Tick" {
		u.promptErr = ""
	}
	switch k {
	case "Ctrl-C":
		return true
	case "Enter":
		re, err := tuiFilterRE(*u.prompt)
		if err != nil {
			u.promptErr = err.Error()
			return false
		}
		u.filter, u.filterRE, u.prompt, u.scroll = *u.prompt, re, nil, 0
	case "Esc":
		u.prompt = nil
	case "Backspace":
		if r := []rune(*u.prompt); len(r) > 0 {
			*u.prompt = string(r[:len(r)-1])
		}
	case "Tick":
		return u.keyTick()
	default:
		if r := []rune(k); len(r) == 1 && r[0] >= ' ' {
			*u.prompt += k
		}
	}
	return false
}

// keyTick plays on while the filter is typed.
func (u *tui) keyTick() bool {
	p := u.prompt
	u.prompt = nil
	defer func() { u.prompt = p }()
	return u.key("Tick")
}

// tick is how long termLoop waits before the next sample while playing.
func (u *tui) tick() time.Duration {
	if !u.playing {
		return 0
	}
	return tuiSpeeds[u.speed]
}

// tuiFilterRE compiles a filter: a regular expression (Go's RE2 syntax),
// any case; nil for an empty one.
func tuiFilterRE(text string) (*regexp.Regexp, error) {
	if text == "" {
		return nil, nil
	}
	re, err := regexp.Compile("(?i)" + text)
	if err != nil {
		var se *syntax.Error
		if errors.As(err, &se) {
			return nil, fmt.Errorf("bad pattern: %s: %s", se.Code, strings.TrimPrefix(se.Expr, "(?i)"))
		}
		return nil, fmt.Errorf("bad pattern: %v", err)
	}
	return re, nil
}

// tuiFilter keeps a pane's header and the lines re matches: the header is
// the first line, or, when a blank line comes within the first 8 (top's
// summary, iostat), everything up to the line after it; titles
// (comparisons' "#" and "──" lines) stay too.
func tuiFilter(lines []string, re *regexp.Regexp, text string) []string {
	head := min(1, len(lines))
	for i, l := range lines[:min(len(lines), 8)] {
		if strings.TrimSpace(l) == "" {
			head = min(i+2, len(lines))
			break
		}
	}
	out := slices.Clone(lines[:head])
	n := 0
	for _, l := range lines[head:] {
		switch t := strings.TrimSpace(l); {
		case re.MatchString(l):
			n++
		case strings.HasPrefix(t, "#"), strings.HasPrefix(t, "──"):
		default:
			continue
		}
		out = append(out, l)
	}
	if n == 0 {
		out = append(out, fmt.Sprintf("(no line matches %q)", text))
	}
	return out
}

// setMark is m: mark A, then B (the later of the two is B), then A again.
func (u *tui) setMark() {
	switch {
	case u.markA < 0 || u.markB >= 0:
		u.markA, u.markB, u.compare = u.cur, -1, false
		u.msg = " A set: move to another sample and press m for B"
	case u.cur == u.markA:
		u.msg = " B must be another sample than A"
	default:
		u.markB = u.cur
		if u.markB < u.markA {
			u.markA, u.markB = u.markB, u.markA
		}
		u.msg = " B set: d compares A and B"
	}
}

// at is the sample at ts: the last at or before it (dir < 0) or the first
// at or after it (dir > 0), else the nearest end.
func (u *tui) at(ts int64, dir int) int {
	i, _ := slices.BinarySearchFunc(u.points, ts, func(p tuiPoint, t int64) int { return int(p.ts - t) })
	if dir < 0 && (i == len(u.points) || u.points[i].ts > ts) {
		i--
	}
	return min(max(i, 0), len(u.points)-1)
}

func (u *tui) paneHeight() int { return max(u.height-tuiTop-tuiBottom, 1) }

// The terminal's attributes.
const (
	tuiRev   = "\x1b[7m"
	tuiBold  = "\x1b[1m"
	tuiDim   = "\x1b[2m"
	tuiReset = "\x1b[0m"
	tuiEOL   = "\x1b[K"
)

// screen is the whole screen, each line cleared to its end.
func (u *tui) screen() string {
	var b strings.Builder
	line := func(s string) { b.WriteString(s + tuiEOL + "\r\n") }
	p := u.points[u.cur]
	n := u.cols()
	cc := u.col(p.ts)

	zone := time.UnixMilli(u.from).Format("MST")
	end := query.FormatMS(u.to)[:16]
	if end[:10] == query.FormatMS(u.from)[:10] {
		end = end[11:]
	}
	cur := query.FormatMS(p.ts)
	if cur[:10] == query.FormatMS(u.to)[:10] && end == query.FormatMS(u.to)[11:16] {
		cur = cur[11:]
	}
	head := fmt.Sprintf(" clifr  %s  %s – %s %s   cursor %s", u.host, query.FormatMS(u.from)[:16], end, zone, cur)
	for i, m := range []int{u.markA, u.markB} {
		if m >= 0 {
			head += fmt.Sprintf("  %c %s", 'A'+i, query.FormatMS(u.points[m].ts)[11:])
		}
	}
	line(tuiRev + fit(head, u.width) + tuiReset)

	ruler := []rune(strings.Repeat(" ", n))
	if u.compare {
		for c := u.col(u.points[u.markA].ts); c < u.col(u.points[u.markB].ts); c++ {
			ruler[c] = '─'
		}
	}
	for i, m := range []int{u.markA, u.markB} {
		if m >= 0 {
			ruler[u.col(u.points[m].ts)] = rune('A' + i)
		}
	}
	ruler[cc] = '▼'
	line(strings.Repeat(" ", tuiLabelW) + string(ruler))

	maxLoad := 1.0
	for _, q := range u.points {
		maxLoad = max(maxLoad, q.load)
	}
	// LOAD is relative to the window's highest load: one color, not levels.
	graphs := []struct {
		label string
		val   func(tuiPoint) float64
		full  float64
		now   string
		color func(cell string) string
	}{
		{"CPU", func(q tuiPoint) float64 { return q.cpu }, 100, pct(p.cpu), levelColor},
		{"MEM", func(q tuiPoint) float64 { return q.mem }, 100, pct(p.mem), levelColor},
		{"LOAD", func(q tuiPoint) float64 { return q.load }, maxLoad, fmt.Sprintf("%.2f", p.load), func(string) string { return tuiCyan }},
		{"PSI io", func(q tuiPoint) float64 { return q.io }, 100, pct(p.io), levelColor},
	}
	for _, gr := range graphs {
		cells := u.spark(gr.val, gr.full)
		for i, c := range cells {
			cells[i] = u.paint(gr.color(c), c)
		}
		cells[cc] = tuiRev + cells[cc] + tuiReset
		line(fmt.Sprintf(" %-*s%s%*s", tuiLabelW-1, gr.label, strings.Join(cells, ""), tuiValueW, gr.now))
	}

	var ev strings.Builder
	for _, r := range u.markRow() {
		ev.WriteString(u.paint(symColor(string(r)), string(r)))
	}
	line(fmt.Sprintf(" %-*s%s", tuiLabelW-1, "events", ev.String()))
	line(tuiDim + strings.Repeat(" ", tuiLabelW) + u.axis() + tuiReset)

	line(u.tabRow())

	body := u.pane1(p.ts)
	if u.compare {
		body = u.paneAB()
	}
	if u.filterRE != nil {
		body = tuiFilter(body, u.filterRE, u.filter)
	}
	if u.help {
		body = u.tuiHelp()
	}
	ph := u.paneHeight()
	u.scroll = min(u.scroll, max(len(body)-ph, 0))
	for i := range ph {
		s := ""
		if j := u.scroll + i; j < len(body) {
			s = fit(body[j], u.width)
		}
		line(s)
	}

	if u.msg != "" {
		line(tuiBold + fit(u.msg, u.width) + tuiReset)
	} else if r := []rune(fit(u.nearMark(p.ts), u.width)); len(r) > 1 { // " SYM time text"
		line(" " + u.paint(symColor(string(r[1])), string(r[1])) + string(r[2:]))
	} else {
		line("")
	}
	keys := " ←→ sample  ⇧←→ minute  z/Z zoom  n/N event  space play  / filter  m mark A/B  d compare  tab pane  ↑↓ scroll  ? help  q quit"
	if u.prompt != nil {
		l := fit("/"+termSafe(*u.prompt)+"█   (a regular expression, any case; Enter: filter the pane, empty: no filter; Esc: cancel)", u.width)
		if u.promptErr != "" {
			l = tuiBold + fit("/"+termSafe(*u.prompt)+"█   "+termSafe(u.promptErr), u.width) + tuiReset
		}
		b.WriteString(l + tuiEOL)
		return b.String()
	}
	b.WriteString(tuiDim + fit(keys, u.width) + tuiReset + tuiEOL)
	return b.String()
}

// pane1 is the pane at ts, rendered once per width.
func (u *tui) pane1(ts int64) []string {
	k := tuiKey{pane: u.pane, width: u.width, ts: ts}
	if tuiPanes[u.pane].span {
		k.ts = 0 // the same at every sample
	}
	if l, ok := u.cache[k]; ok {
		return l
	}
	if len(u.cache) > 500 {
		clear(u.cache)
	}
	l := u.render(u.pane, ts, u.width)
	u.cache[k] = l
	return l
}

// tabRow is the panes' names, the current one in reverse, then what is on
// (comparison, play, filter) in bold. When the names do not fit, those
// around the current one are shown, ‹ › where more are hidden.
func (u *tui) tabRow() string {
	var st []string
	if u.compare {
		st = append(st, "A → B (d: back, v: layout)")
	}
	if u.playing {
		st = append(st, "▶ "+tuiSpeeds[u.speed].String()+" a sample")
	}
	if u.filter != "" {
		st = append(st, "/"+termSafe(u.filter))
	}
	status := fit(strings.Join(st, "   "), u.width/2)
	room := u.width - 1 - 2 // the leading space, ‹ and ›
	if status != "" {
		room -= utf8.RuneCountInString(status) + 3
	}
	w := func(i int) int { return utf8.RuneCountInString(tuiPanes[i].name) + 2 }
	lo, hi, used := u.pane, u.pane, w(u.pane)
	for grew := true; grew; {
		grew = false
		if hi+1 < len(tuiPanes) && used+w(hi+1) <= room {
			hi++
			used += w(hi)
			grew = true
		}
		if lo > 0 && used+w(lo-1) <= room {
			lo--
			used += w(lo)
			grew = true
		}
	}
	var b strings.Builder
	b.WriteString(" ")
	if lo > 0 {
		b.WriteString(tuiDim + "‹" + tuiReset)
	}
	for i := lo; i <= hi; i++ {
		if i == u.pane {
			b.WriteString(tuiRev + " " + tuiPanes[i].name + " " + tuiReset)
		} else {
			b.WriteString(" " + tuiPanes[i].name + " ")
		}
	}
	if hi < len(tuiPanes)-1 {
		b.WriteString(tuiDim + "›" + tuiReset)
	}
	if status != "" {
		b.WriteString("   " + tuiBold + status + tuiReset)
	}
	return b.String()
}

// paneAB is the pane comparing marks A and B, rendered once per width.
func (u *tui) paneAB() []string {
	a, b := u.points[u.markA].ts, u.points[u.markB].ts
	k := tuiKey{pane: u.pane, width: u.width, a: a, b: b}
	p, ok := u.pairs[k]
	if !ok {
		if u.pairs == nil || len(u.pairs) > 50 {
			u.pairs = map[tuiKey][2][]string{}
		}
		p[0], p[1] = u.diff(u.pane, a, b, u.width)
		u.pairs[k] = p
	}
	switch {
	case p[1] == nil:
		return p[0]
	case u.stacked:
		return tuiStacked(p[0], p[1], a, b, u.width)
	}
	return tuiSideBySide(p[0], p[1], a, b, u.width)
}

// tuiHelp is what ? shows in the pane.
func (u *tui) tuiHelp() []string {
	l := []string{
		"Keys",
		"  ← →  h l       one sample back, forward",
		"  ⇧← ⇧→  H L     one minute",
		"  Home End       the window's first, last sample",
		"  z  Z           zoom in to a quarter of the window around the cursor (down to",
		"                 5 minutes), zoom out to four times it (up to now and the",
		"                 recording's start; a wider window takes longer to read)",
		"  n  N           next, previous event on the timeline (the sample before it)",
		"  m              mark the sample: A, then B (the later one is B), then A again",
		"  M              clear the marks",
		"  a  b           go to mark A, B",
		"  d              compare A and B in the pane, and back: what appeared, went",
		"                 and changed (ps, ss, lsof, df), the events between them, else",
		"                 the output at A and at B side by side; oom: the kills from A to B",
		"  v              A and B side by side, or A above B (the panes without a change list)",
		"  tab ⇧tab       the next, previous pane: " + tuiPaneNames(),
		"  1-9 0          the first ten panes",
		"  ↑ ↓ PgUp PgDn  scroll the pane",
		"  space          play: one sample after another, and pause",
		"  + -            play faster, slower (" + tuiSpeeds[0].String() + " to " + tuiSpeeds[len(tuiSpeeds)-1].String() + " a sample)",
		"  /              filter the pane: its header and the lines a regular expression",
		"                 matches, any case (postgres|nginx, ^root, :(80|443) ); / then",
		"                 Enter on nothing: no filter",
		"  ?              this help (? or Esc to close)",
		"  q              quit",
		"",
		"Timeline: CPU busy, memory used (without page cache), the 1-minute load, the",
		"share of time some task waited for I/O (PSI); each column is a stretch of the",
		"window, its mean shown; blank: no sample there.",
		"",
		"Events row",
	}
	for _, m := range tuiMarkOrder {
		l = append(l, fmt.Sprintf("  %s  %s", u.paint(m.color, m.sym), m.name))
	}
	return l
}

func tuiPaneNames() string {
	var n []string
	for _, p := range tuiPanes {
		n = append(n, p.name)
	}
	return strings.Join(n, " ")
}

// markRow is the events row: each column the most important symbol of its
// events (tuiMarkOrder), a gap shaded up to the next sample.
func (u *tui) markRow() []rune {
	n := u.cols()
	row := []rune(strings.Repeat(" ", n))
	rank := func(r rune) int {
		for i, m := range tuiMarkOrder {
			if []rune(m.sym)[0] == r {
				return i
			}
		}
		return len(tuiMarkOrder)
	}
	put := func(c int, r rune) {
		if rank(r) < rank(row[c]) {
			row[c] = r
		}
	}
	for _, m := range u.marks {
		put(u.col(m.ts), []rune(m.sym)[0])
	}
	// Stretches without samples: between two samples further apart than
	// tuiGapFactor times the usual interval.
	gap := '░'
	if d := u.interval() * tuiGapFactor; d > 0 {
		for i := 1; i < len(u.points); i++ {
			if a, b := u.points[i-1].ts, u.points[i].ts; b-a > d {
				for c := u.col(a) + 1; c < u.col(b); c++ {
					put(c, gap)
				}
			}
		}
	}
	// After the last sample: still in clifrd's memory, or a gap.
	last := u.points[len(u.points)-1].ts
	switch d := u.interval() * tuiGapFactor; {
	case u.unwritten:
		for c := u.col(last) + 1; c < n; c++ {
			put(c, '┈')
		}
	case d > 0 && u.to-last > d:
		for c := u.col(last) + 1; c < n; c++ {
			put(c, gap)
		}
	}
	return row
}

// tuiGapFactor: samples further apart than this many usual intervals leave
// a gap.
const tuiGapFactor = 3

// interval is the usual time between samples (the median).
func (u *tui) interval() int64 {
	if len(u.points) < 2 {
		return 0
	}
	d := make([]int64, 0, len(u.points)-1)
	for i := 1; i < len(u.points); i++ {
		d = append(d, u.points[i].ts-u.points[i-1].ts)
	}
	slices.Sort(d)
	return d[len(d)/2]
}

// nearMark is the event line: the mark nearest the cursor within two
// columns, else nothing.
func (u *tui) nearMark(ts int64) string {
	span := 2 * (u.to - u.from) / int64(u.cols())
	best, bd := -1, int64(-1)
	for i, m := range u.marks {
		d := max(m.ts-ts, ts-m.ts)
		if d <= span && (best < 0 || d < bd) {
			best, bd = i, d
		}
	}
	if best < 0 {
		return ""
	}
	m := u.marks[best]
	more := 0
	for _, o := range u.marks {
		if max(o.ts-ts, ts-o.ts) <= span {
			more++
		}
	}
	t := fmt.Sprintf(" %s %s %s", m.sym, query.FormatMS(m.ts)[11:], m.text)
	if more > 1 {
		t += fmt.Sprintf("   (+%d nearby)", more-1)
	}
	return termSafe(t)
}

func pct(v float64) string {
	if v < 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", v)
}

// fit cuts s to w columns (one per rune: the panes' text is filtered).
func fit(s string, w int) string {
	if utf8.RuneCountInString(s) <= w {
		return s
	}
	return string([]rune(s)[:w])
}

// run draws the screen and reads keys until q.
func (u *tui) run() error {
	return termLoop(func(w, h int) string {
		u.width, u.height = w, h
		return u.screen()
	}, u.key, u.tick)
}
