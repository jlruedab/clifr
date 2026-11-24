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
	"os"
	"slices"
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
var tuiPanes = []struct{ name, cmd string }{
	{"top", "top -b -n 1 -w %W"},
	{"ps", "ps aux"},
	{"ss", "ss -tanp"},
	{"lsof", "lsof -i"},
	{"free", "free -m"},
	{"vmstat", "vmstat"},
	{"iostat", "iostat -x"},
	{"events", ""}, // clifr events over the window, from the cursor on
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
}

type tuiKey struct {
	pane, width int
	ts          int64
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
	db, err := openWindow(g, duck.Window{From: w.From, To: w.To})
	if err != nil {
		return err
	}
	defer db.Close()
	u := &tui{from: w.From, to: w.To, cache: map[tuiKey][]string{}, color: os.Getenv("NO_COLOR") == ""}
	if u.points, err = tuiPoints(db, w.From, w.To); err != nil {
		return err
	}
	if len(u.points) == 0 {
		return fmt.Errorf("tui: no system samples between %s and %s", query.FormatMS(w.From), query.FormatMS(w.To))
	}
	if u.marks, err = tuiMarks(db, w.From, w.To); err != nil {
		return err
	}
	u.cur = len(u.points) - 1
	ev := &tuiEvents{db: db, from: w.From, to: w.To}
	u.render = func(pane int, ts int64, width int) []string {
		if tuiPanes[pane].name == "events" {
			return ev.at(ts, 3*u.paneHeight()) // room to scroll
		}
		return tuiRender(g, db, pane, ts, width)
	}
	if h := tuiCapture(g, db, "hostname", u.points[u.cur].ts); len(h) > 0 {
		u.host = strings.TrimSpace(h[0])
	}
	return u.run()
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
	{"↺", "unit restarting", tuiYellow}, {"●", "login", tuiCyan}, {"○", "logout", tuiCyan},
	{"░", "no samples", tuiDim},
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
		out = append(out, tuiMark{ts: k.TS, sym: "✕",
			text: fmt.Sprintf("OOM kill: PID %d, %s: %s", k.PID, tuiSize(k.RSSKB), k.Command)})
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
			query.PrintEvents(t, []query.Event{ev})
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
	header := "TIME                     EVENT        PID DETAIL"
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

// tuiCapture runs one command at ts and returns its lines (an error as the
// only line).
func tuiCapture(g *globals, db *store.DB, cmd string, ts int64) []string {
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
		savedOut, savedHdr := outOverride, query.HeaderOut
		outOverride, query.HeaderOut = &out, io.Discard
		defer func() { outOverride, query.HeaderOut = savedOut, savedHdr }()
		c := &runCtx{g: g, w: query.Window{At: ts}, db: db}
		if err := query.Covered(db, ts); err != nil {
			return err
		}
		if _, err := query.LoadUsers(db, ts); err != nil {
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
	switch k {
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
	case "\t":
		u.pane, u.scroll = (u.pane+1)%len(tuiPanes), 0
	case "S-Tab":
		u.pane, u.scroll = (u.pane+len(tuiPanes)-1)%len(tuiPanes), 0
	case "Up", "k":
		u.scroll = max(u.scroll-1, 0)
	case "Down", "j":
		u.scroll++
	case "PgUp":
		u.scroll = max(u.scroll-u.paneHeight(), 0)
	case "PgDn", " ":
		u.scroll += u.paneHeight()
	default:
		if len(k) == 1 && k[0] >= '1' && int(k[0]-'1') < len(tuiPanes) {
			u.pane, u.scroll = int(k[0]-'1'), 0
		}
	}
	return false
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
	line(tuiRev + fit(head, u.width) + tuiReset)

	ruler := []rune(strings.Repeat(" ", n))
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

	var tabs strings.Builder
	tabs.WriteString(" ")
	for i, t := range tuiPanes {
		if i == u.pane {
			tabs.WriteString(tuiRev + " " + t.name + " " + tuiReset)
		} else {
			tabs.WriteString(" " + t.name + " ")
		}
	}
	line(tabs.String())

	body := u.pane1(p.ts)
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

	if r := []rune(fit(u.nearMark(p.ts), u.width)); len(r) > 1 { // " SYM time text"
		line(" " + u.paint(symColor(string(r[1])), string(r[1])) + string(r[2:]))
	} else {
		line("")
	}
	keys := " ←→ sample  ⇧←→ minute  n/N next/prev event  tab pane  ↑↓ scroll  ? help  q quit"
	b.WriteString(tuiDim + fit(keys, u.width) + tuiReset + tuiEOL)
	return b.String()
}

// pane1 is the pane at ts, rendered once per width.
func (u *tui) pane1(ts int64) []string {
	k := tuiKey{pane: u.pane, width: u.width, ts: ts}
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

// tuiHelp is what ? shows in the pane.
func (u *tui) tuiHelp() []string {
	l := []string{
		"Keys",
		"  ← →  h l       one sample back, forward",
		"  ⇧← ⇧→  H L     one minute",
		"  Home End       the window's first, last sample",
		"  n  N           next, previous event on the timeline (the sample before it)",
		"  tab ⇧tab 1-8   the pane: " + tuiPaneNames(),
		"  ↑ ↓ PgUp PgDn  scroll the pane",
		"  ?              this help (? or Esc to close)",
		"  q              quit",
		"",
		"Timeline: CPU busy, memory used (without page cache), the 1-minute load, the",
		"share of time some task waited for I/O (PSI); each column is a stretch of the",
		"window, its mean shown; blank: no sample there (or not yet written to disk).",
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
	gap := []rune(tuiMarkOrder[len(tuiMarkOrder)-1].sym)[0]
	if d := u.interval() * tuiGapFactor; d > 0 {
		for i := 1; i < len(u.points); i++ {
			if a, b := u.points[i-1].ts, u.points[i].ts; b-a > d {
				for c := u.col(a) + 1; c < u.col(b); c++ {
					put(c, gap)
				}
			}
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
	}, u.key)
}
