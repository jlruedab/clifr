package main

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"clifr/internal/query"
)

func topTool() *tool {
	return &tool{
		name: "top", synopsis: "-b [-n 1] [-c] [-i] [-w COLUMNS] [-o FIELD] [-p PIDS] [-u USER] [-d SECONDS]",
		about: "summary and processes by CPU use, as top -b prints them",
		opts: []opt{
			{short: 'b', help: "batch mode (always: clifr prints, the pager pages)"},
			{short: 'n', arg: "N", help: "iterations: 1 with --at; with --since --samples, at most N samples"},
			{short: 'c', help: "the command line instead of the command name"},
			{short: 'i', help: "leave out processes that used no CPU in the interval"},
			{short: 'w', arg: "COLUMNS", help: "line width (default 80, as top -b: lines use one column less, cut ones end in +)"},
			{short: 'o', arg: "FIELD", help: "sort by %CPU (default), %MEM, PID, USER, PR, NI, VIRT, RES, S, TIME+, COMMAND; -FIELD: reversed"},
			{short: 'p', arg: "PIDS", help: "only these processes (comma separated, or repeat -p)"},
			{short: 'u', arg: "USER", help: "only this user's processes (name or number)"},
			{short: 'd', arg: "SECONDS", help: "with --since --samples: the spacing between samples (as --every)"},
		},
		window: true,
		notes: []string{
			"--at: the summary from the system sample at or before T; the processes alive at T with their",
			"values from the process sample at or before it, %CPU over the interval since the sample before",
			"(top's own first screen covers a fraction of a second). The number of users at T as uptime counts",
			"them (left out before 2026-11-20: not recorded). Recordings before 2026-10-22 have no SHR (shown",
			"as -) and no priority (PR is 20 + NI, never rt).",
			"Processes only seen through exec/exit events show - for every value and count as sleeping.",
			"--since: one report per sample with --samples (-n and -d as for top).",
		},
		examples: []string{`clifr --at "02:45" "top -b -n 1"`, `clifr --at "02:45" "top -b -c -o %MEM"`,
			`clifr --since "02:00" --until "02:10" --samples "top -b -n 5"`},
		prepare: prepareTop,
	}
}

func prepareTop(p parsed, c *runCtx) (func() error, error) {
	if len(p.pos) > 0 {
		return nil, fmt.Errorf("top: unexpected argument %q", p.pos[0])
	}
	f := query.TopFormat{Width: 80, CmdLine: p.has("c")}
	if v, ok := p.set["w"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 80 || n > 512 {
			return nil, fmt.Errorf("top: bad width %q (80 to 512)", v)
		}
		f.Width = n
	}
	field, reverse := "%CPU", false
	if v, ok := p.set["o"]; ok {
		field = strings.TrimPrefix(v, "+")
		if rest, ok := strings.CutPrefix(field, "-"); ok {
			field, reverse = rest, true
		}
		field = strings.ToUpper(field)
		if !slices.Contains(query.TopFields, field) {
			return nil, fmt.Errorf("top: unknown sort field %q (%s)", v, strings.Join(query.TopFields, " "))
		}
	}
	if c.g.changes {
		return nil, errors.New("top: --changes is not supported; use --samples for one report per sample")
	}
	if v, ok := p.set["n"]; ok {
		n, err := strconv.Atoi(v)
		switch {
		case err != nil || n <= 0:
			return nil, fmt.Errorf("top: bad count %q", v)
		case !c.w.IsRange() && n != 1:
			return nil, errors.New("top: -n N above 1 needs --since and --samples (one report per sample)")
		case c.w.IsRange():
			c.g.number = n
		}
	}
	if v, ok := p.set["d"]; ok {
		secs, err := strconv.ParseFloat(v, 64)
		if err != nil || secs <= 0 {
			return nil, fmt.Errorf("top: bad delay %q (seconds)", v)
		}
		if !c.w.IsRange() {
			return nil, errors.New("top: -d needs --since and --samples")
		}
		c.g.everyMS = int64(secs * 1000)
	}
	if c.w.IsRange() && !c.g.samples {
		return nil, errors.New("top: a range needs --samples (one report per sample)")
	}
	pids := map[int]bool{}
	for _, v := range splitList(p.all["p"]) {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("top: bad PID %q", v)
		}
		pids[n] = true
	}
	user := p.set["u"]
	keep := func(r *query.TopRow) bool {
		if len(pids) > 0 && !pids[r.PID] {
			return false
		}
		if user != "" && user != r.User && user != strconv.Itoa(r.UID) {
			return false
		}
		return !p.has("i") || r.Sampled && r.CPU > 0
	}
	at := func(t int64) (query.TopReport, error) {
		rep, err := query.TopAt(c.db, t)
		if err != nil {
			return rep, err
		}
		kept := rep.Procs[:0]
		for i := range rep.Procs {
			if keep(&rep.Procs[i]) {
				kept = append(kept, rep.Procs[i])
			}
		}
		rep.Procs = kept
		query.SortTop(rep.Procs, field)
		if reverse {
			slices.Reverse(rep.Procs)
		}
		return rep, nil
	}
	return func() error {
		v := view[query.TopReport]{
			name: "top",
			at: func(t int64) ([]query.TopReport, func(*query.TopReport) rowMeta, error) {
				rep, err := at(t)
				return []query.TopReport{rep}, func(r *query.TopReport) rowMeta {
					return rowMeta{TS: t, SampleTS: r.SampleTS, Sampled: topSampled}
				}, err
			},
			key:  func(*query.TopReport) string { return "top" },
			same: func(a, b *query.TopReport) bool { return true },
			print: func(w io.Writer, reps []query.TopReport) {
				for _, r := range reps {
					query.PrintTop(w, r, f)
				}
			},
		}
		if ok, err := rangeView(c, v); ok {
			return err
		}
		rep, err := at(c.w.At)
		if err != nil {
			return err
		}
		c.header("top at %s: processes from the sample at %s, %%CPU since %s; summary from the system sample at %s",
			query.FormatMS(c.w.At), query.FormatMS(rep.SampleTS), topSince(rep.PrevTS), query.FormatMS(rep.Uptime.TS))
		return c.emit(rep, func(int) rowMeta {
			return rowMeta{TS: c.w.At, SampleTS: rep.SampleTS, Sampled: topSampled}
		}, func(w io.Writer) { query.PrintTop(w, rep, f) })
	}, nil
}

func topSince(prev int64) string {
	if prev == 0 {
		return "each process started"
	}
	return query.FormatMS(prev)
}

// topSampled: everything top shows is from samples, except the ids, user,
// command and start time.
var topSampled = []string{"uptime", "tasks", "cpu", "mem", "procs"}
