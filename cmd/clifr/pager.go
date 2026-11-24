package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"clifr/internal/query"
)

// page is one screen of output: a command's output at one moment (a sample,
// a comparison), rendered on demand.
type page struct {
	title string // "" for a single output
	ts    int64  // the moment it shows (for g)
	body  func(io.Writer) error
}

// show prints the pages, or pages through them interactively (-I, or by
// default when both stdin and stdout are terminals; --plain never).
func (c *runCtx) show(pages []page) error {
	if c.interactive() {
		return runPager(pages, c.g.interactive)
	}
	out, done := stdout()
	if c.g.json {
		out, done = dataOut()
	}
	defer done()
	for i, p := range pages {
		if i > 0 {
			fmt.Fprintln(out)
		}
		if p.title != "" {
			fmt.Fprintf(out, "# %s\n", p.title)
		}
		if err := p.body(out); err != nil {
			return err
		}
	}
	return nil
}

func (c *runCtx) interactive() bool {
	if c.g.plain || c.g.json {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd())) && term.IsTerminal(int(os.Stdin.Fd()))
}

// pager is the state of the interactive view; it knows nothing of the
// terminal, so it can be tested.
type pager struct {
	pages          []page
	cache          map[int][]string
	cur, top, left int
	height, width  int     // screen size; the last line is the status line
	prompt         *string // reading a time for g
	msg            string
	err            error
	now            func() time.Time // for times typed at g ("10:01" is today); time.Now
}

func (p *pager) lines(i int) []string {
	if l, ok := p.cache[i]; ok {
		return l
	}
	var b bytes.Buffer
	if t := p.pages[i].title; t != "" {
		fmt.Fprintf(&b, "# %s\n", t)
	}
	if err := p.pages[i].body(&b); err != nil {
		p.err = err
		fmt.Fprintf(&b, "error: %v\n", err)
	}
	l := strings.Split(strings.TrimRight(termSafe(b.String()), "\n"), "\n")
	p.cache[i] = l
	return l
}

func (p *pager) view() int { return max(p.height-1, 1) }

func (p *pager) setPage(i int) {
	if i >= 0 && i < len(p.pages) && i != p.cur {
		p.cur, p.top = i, 0
	}
}

func (p *pager) scroll(d int) {
	p.top = max(min(p.top+d, len(p.lines(p.cur))-p.view()), 0)
}

// key handles one key; it reports whether to quit.
func (p *pager) key(k string) bool {
	p.msg = ""
	if p.prompt != nil {
		switch k {
		case "Enter":
			p.jump(*p.prompt)
			p.prompt = nil
		case "Esc":
			p.prompt = nil
		case "Backspace":
			if s := *p.prompt; s != "" {
				*p.prompt = s[:len(s)-1]
			}
		default:
			if len(k) == 1 {
				*p.prompt += k
			}
		}
		return false
	}
	switch k {
	case "q", "Q", "Ctrl-C":
		return true
	case "n", "PgDn":
		p.setPage(p.cur + 1)
	case "p", "PgUp":
		p.setPage(p.cur - 1)
	case "Home":
		p.setPage(0)
	case "End":
		p.setPage(len(p.pages) - 1)
	case "Down", "j", "Enter":
		p.scroll(1)
	case "Up", "k":
		p.scroll(-1)
	case " ", "f":
		p.scroll(p.view() - 1)
	case "b":
		p.scroll(-(p.view() - 1))
	case "Right", "l":
		p.left += 8
	case "Left", "h":
		p.left = max(p.left-8, 0)
	case "g":
		s := ""
		p.prompt = &s
	}
	return false
}

// jump goes to the last page at or before the time typed (the first page
// if none). A time of day without a date is the one nearest the page shown
// (its day, the day before or after: a range may cross midnight); the other
// forms ("now", "-30m", a date) are as on the command line.
func (p *pager) jump(s string) {
	t, err := query.ParseWhen(s, p.now())
	if err != nil {
		p.msg = err.Error()
		return
	}
	if cur := p.pages[p.cur].ts; cur != 0 && clockOnly(s) {
		shown := time.UnixMilli(cur)
		best := t
		for _, d := range []int{-1, 0, 1} {
			c, _ := query.ParseWhen(s, shown.AddDate(0, 0, d))
			if c.Sub(shown).Abs() < best.Sub(shown).Abs() {
				best = c
			}
		}
		t = best
	}
	ms, best := t.UnixMilli(), 0
	for i, pg := range p.pages {
		if pg.ts != 0 && pg.ts <= ms {
			best = i
		}
	}
	p.setPage(best)
}

// clockOnly: s is a time of day without a date ("10:01", "10:01:30").
func clockOnly(s string) bool {
	for _, layout := range []string{"15:04:05", "15:04"} {
		if _, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return true
		}
	}
	return false
}

// screen is the text to draw: the visible lines cut to the width, then the
// status line.
func (p *pager) screen() string {
	var b strings.Builder
	l := p.lines(p.cur)
	for i := p.top; i < p.top+p.view(); i++ {
		line := ""
		if i < len(l) {
			line = l[i]
			if p.left < len(line) {
				line = line[p.left:]
			} else {
				line = ""
			}
			if len(line) > p.width {
				line = line[:p.width]
			}
		}
		b.WriteString(line + "\x1b[K\r\n")
	}
	status := fmt.Sprintf(" %d/%d  lines %d-%d of %d  n/p next/previous  Home/End  g time  arrows, space, b scroll  q quit",
		p.cur+1, len(p.pages), p.top+1, min(p.top+p.view(), len(l)), len(l))
	switch {
	case p.prompt != nil:
		status = " go to time: " + *p.prompt
	case p.msg != "":
		status = " " + p.msg
	}
	if len(status) > p.width {
		status = status[:p.width]
	}
	b.WriteString("\x1b[7m" + status + strings.Repeat(" ", max(p.width-len(status), 0)) + "\x1b[0m")
	return b.String()
}

// keyName decodes one read from the terminal in raw mode.
func keyName(b []byte) string {
	switch s := string(b); s {
	case "\x1b[5~":
		return "PgUp"
	case "\x1b[6~":
		return "PgDn"
	case "\x1b[H", "\x1b[1~", "\x1bOH":
		return "Home"
	case "\x1b[F", "\x1b[4~", "\x1bOF":
		return "End"
	case "\x1b[A", "\x1bOA":
		return "Up"
	case "\x1b[B", "\x1bOB":
		return "Down"
	case "\x1b[C", "\x1bOC":
		return "Right"
	case "\x1b[D", "\x1bOD":
		return "Left"
	case "\r", "\n":
		return "Enter"
	case "\x1b":
		return "Esc"
	case "\x7f", "\b":
		return "Backspace"
	case "\x03":
		return "Ctrl-C"
	case "\x1b[1;2D":
		return "S-Left"
	case "\x1b[1;2C":
		return "S-Right"
	case "\x1b[Z":
		return "S-Tab"
	default:
		return s
	}
}

// runPager shows the pages on the terminal. One page that fits on the
// screen is just printed, unless -I asked for the pager.
func runPager(pages []page, forced bool) error {
	out := int(os.Stdout.Fd())
	w, h, err := term.GetSize(out)
	if err != nil {
		return errors.New("--interactive: cannot read the terminal size")
	}
	p := &pager{pages: pages, cache: map[int][]string{}, width: w, height: h, now: time.Now}
	if len(pages) == 1 && !forced && len(p.lines(0)) < h {
		_, err := os.Stdout.WriteString(strings.Join(p.lines(0), "\n") + "\n")
		return err
	}
	if err := termLoop(func(w, h int) string {
		p.width, p.height = w, h
		return p.screen()
	}, p.key); err != nil {
		return err
	}
	return p.err
}
