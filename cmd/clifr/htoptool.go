package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/term"

	"clifr/internal/query"
)

func htopTool() *tool {
	return &tool{
		name: "htop", synopsis: "[-t] [-s COLUMN] [-u USER] [-p PID[,PID...]] [-C]",
		opts: []opt{
			{short: 't', long: "tree", help: "the tree view"},
			{short: 's', long: "sort-key", arg: "COLUMN", help: "sort by COLUMN: " + strings.Join(query.HtopSortKeys, ", ") + " (default PERCENT_CPU)"},
			{short: 'u', long: "user", arg: "USER", help: "only this user's processes"},
			{short: 'p', long: "pid", arg: "PID", help: "only these processes (comma separated, or repeat -p)"},
			{short: 'C', long: "no-color", help: "monochrome: each part of a bar with its own character"},
		},
		about:  "htop's screen at a moment, as text",
		window: true,
		notes: []string{
			"htop's default screen (as root, no htoprc) as the recorded host's release draws it: 3.4.1;",
			"3.3.0 (RHEL 9's EPEL, Ubuntu 24.04), 3.2.1 (RHEL 8's EPEL), 3.0.5 (Ubuntu 22.04). The header",
			"(CPU bars, Mem, Swp, Tasks, Load average, Uptime), the screen tabs, the column titles and every",
			"process, not cut at a screen's height, without the function key bar. Lines are $COLUMNS wide,",
			"else the terminal's, else 80. %CPU and the CPU bars are over the interval between the process",
			"sample at or before T and the one before it (htop's refresh interval); the other values are",
			"those of the process sample at or before T. Threads are not recorded: user threads are hidden,",
			"as with htop's H key (the Tasks line still counts them, from each process's thread count).",
			"Kernel threads are hidden, as htop's default. Processes only seen through exec/exit events",
			"(no values) are left out.",
		},
		examples: []string{`clifr --at "02:45" htop`, `clifr --at "02:45" "htop -t"`, `COLUMNS=200 clifr --at "02:45" "htop -s PERCENT_MEM"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("htop: unexpected argument %q", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("htop: one screen at a moment: use --at")
			}
			o := query.HtopOpts{Tree: p.has("tree"), NoColor: p.has("no-color"), Width: htopWidth()}
			if p.has("sort-key") {
				k := strings.ToUpper(p.set["sort-key"])
				if k == "COMMAND" {
					k = "COMM"
				}
				if !slices.Contains(query.HtopSortKeys, k) {
					return nil, fmt.Errorf("htop: unknown sort key %q (%s)", p.set["sort-key"], strings.Join(query.HtopSortKeys, ", "))
				}
				o.SortKey = k
			}
			for _, v := range p.all["pid"] {
				for _, f := range strings.Split(v, ",") {
					n, err := strconv.Atoi(f)
					if err != nil || n < 1 {
						return nil, fmt.Errorf("htop: bad PID %q", f)
					}
					o.PIDs = append(o.PIDs, n)
				}
			}
			return func() error {
				sc, err := query.HtopAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				if _, err := query.LoadUsers(c.db, sc.SampleTS); err != nil {
					return err
				}
				if p.has("user") {
					u := p.set["user"]
					uid, ok := query.UserID(u)
					if !ok {
						if n, err := strconv.Atoi(u); err == nil && n >= 0 {
							uid, ok = n, true
						}
					}
					if !ok {
						return fmt.Errorf("htop: unknown user %q", u)
					}
					o.UIDs = []int{uid}
				}
				// HtopAt named the users before LoadUsers: name them again.
				for i := range sc.Procs {
					sc.Procs[i].User = query.UserName(sc.Procs[i].UID, false)
				}
				st := query.StyleAt(c.db, sc.SampleTS)
				o.Version = st.Htop
				if sc.PrevTS != 0 {
					c.header("htop: %s's screen at %s: %%CPU and the CPU bars over %s .. %s (%.0f s)", query.HtopVersion(st),
						query.FormatMS(c.w.At), query.FormatMS(sc.PrevTS), query.FormatMS(sc.SampleTS), float64(sc.SampleTS-sc.PrevTS)/1000)
				} else {
					c.header("htop: %s's screen at %s: %%CPU and the CPU bars since boot (no process sample before %s)", query.HtopVersion(st),
						query.FormatMS(c.w.At), query.FormatMS(sc.SampleTS))
				}
				c.header("htop: threads are not recorded: user threads hidden (htop's H key); Tasks counts them")
				events := 0
				for _, pr := range sc.Procs {
					if !pr.Sampled && !pr.Kernel {
						events++
					}
				}
				if events > 0 {
					c.header("htop: %d processes only seen through exec/exit events (no values) left out", events)
				}
				return c.emit([]query.HtopJSON{query.HtopJSONOf(sc, o)}, func(int) rowMeta { return rowMeta{TS: c.w.At, SampleTS: sc.SampleTS} },
					func(w io.Writer) { query.PrintHtop(w, sc, o) })
			}, nil
		},
	}
}

// htopWidth is the screen's width: $COLUMNS, else the terminal's, else 80.
func htopWidth() int {
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
		return n
	}
	if term.IsTerminal(int(os.Stdout.Fd())) {
		if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
			return w
		}
	}
	return 80
}
