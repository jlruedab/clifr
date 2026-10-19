package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"

	"clifr/internal/query"
)

// The system-wide tools: at T the averages since boot (what the real tool
// prints without an interval); over a range one report for the whole range
// (--summary, the default) or one per interval (--samples, or an interval
// argument as for the real tool: "vmstat 60").

func addSystemTools() {
	common := []string{
		"--at: averages since boot at the sample at or before T, as the tool prints without an interval.",
		"--since: one report for the range; with --samples (or an INTERVAL argument) one per interval,",
		"at least INTERVAL (or -e) long and a multiple of the recording interval (30 s by default).",
	}
	addTool(&tool{
		name: "vmstat", synopsis: "[INTERVAL [COUNT]]",
		about: "memory, swap, I/O, system and CPU activity", window: true, notes: common,
		examples: []string{`clifr --since "02:00" --until "02:30" "vmstat 60"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			return prepareSys("vmstat", p, c, func(spans []query.Span) error {
				rows, err := query.VMStat(c.db, spans)
				if err != nil {
					return err
				}
				return c.emit(rows, func(i int) rowMeta { return spanMeta(spans, rows[i].TS, rows[i]) },
					func(w io.Writer) { query.PrintVMStat(w, rows) })
			})
		},
	})
	addTool(&tool{
		name: "mpstat", synopsis: "[-P ALL|N[,M...]] [INTERVAL [COUNT]]",
		about:  "CPU time by CPU",
		opts:   []opt{{short: 'P', arg: "CPUS", help: "ALL, or CPU numbers separated by commas (default: the total only)"}},
		window: true, notes: common,
		examples: []string{`clifr --at "02:45" "mpstat -P ALL"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			cpus := p.set["P"]
			return prepareSys("mpstat", p, c, func(spans []query.Span) error {
				rows, err := query.MPStat(c.db, spans, cpus)
				if err != nil {
					return err
				}
				return c.emit(rows, func(i int) rowMeta { return spanMeta(spans, rows[i].TS, rows[i], "cpu") },
					func(w io.Writer) { query.PrintMPStat(w, rows) })
			})
		},
	})
	addTool(&tool{
		name: "iostat", synopsis: "[-x] [-d] [-p [ALL]] [INTERVAL [COUNT]]",
		about: "CPU and block device I/O",
		opts: []opt{
			{short: 'x', help: "extended device statistics"},
			{short: 'd', help: "device report only (no avg-cpu)"},
			{short: 'p', help: "also list partitions (ALL is accepted)"},
		},
		window: true, notes: common,
		examples: []string{`clifr --since "02:00" --until "02:30" --samples -e 1m "iostat -x"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if p.has("p") && len(p.pos) > 0 && p.pos[0] == "ALL" {
				p.pos = p.pos[1:]
			}
			return prepareSys("iostat", p, c, func(spans []query.Span) error {
				reps, err := query.IOStat(c.db, spans, p.has("p"))
				if err != nil {
					return err
				}
				return c.emit(reps, func(i int) rowMeta { return spanMeta(spans, reps[i].TS, reps[i]) },
					func(w io.Writer) { query.PrintIOStat(w, reps, p.has("x"), p.has("d")) })
			})
		},
	})
	addTool(&tool{
		name: "uptime", about: "time since boot and load averages", window: true,
		notes: []string{"The number of logged-in users is not recorded and not shown."},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("uptime: unexpected argument %q", p.pos[0])
			}
			return prepareSys("uptime", p, c, func(spans []query.Span) error {
				rows, err := query.Uptime(c.db, spans)
				if err != nil {
					return err
				}
				return c.emit(rows, func(i int) rowMeta { return spanMeta(spans, rows[i].TS, rows[i]) },
					func(w io.Writer) { query.PrintUptime(w, rows) })
			})
		},
	})
}

// prepareSys reads INTERVAL [COUNT], chooses the spans and runs print.
func prepareSys(name string, p parsed, c *runCtx, print func([]query.Span) error) (func() error, error) {
	if len(p.pos) > 2 {
		return nil, fmt.Errorf("%s: unexpected argument %q", name, p.pos[2])
	}
	every, number := c.g.everyMS, c.g.number
	if len(p.pos) > 0 {
		n, err := strconv.Atoi(p.pos[0])
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("%s: bad interval %q (seconds)", name, p.pos[0])
		}
		every = int64(n) * 1000
	}
	if len(p.pos) > 1 {
		n, err := strconv.Atoi(p.pos[1])
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("%s: bad count %q", name, p.pos[1])
		}
		number = n
	}
	samples := c.g.samples || len(p.pos) > 0
	switch {
	case !c.w.IsRange() && (len(p.pos) > 0 || c.g.samples):
		return nil, fmt.Errorf("%s: an interval needs a range (--since)", name)
	case c.g.changes:
		return nil, fmt.Errorf("%s: --changes is not available for %s; use --samples", name, name)
	}
	return func() error {
		spans, err := query.SysSpans(c.db, c.w, every)
		if err != nil {
			return err
		}
		switch {
		case !c.w.IsRange():
			if name == "uptime" {
				c.header("uptime at the sample of %s (logged-in users are not recorded)", query.FormatMS(spans[0].To))
			} else {
				c.header("%s: averages since boot at the sample of %s", name, query.FormatMS(spans[0].To))
			}
		case samples:
			if number > 0 && len(spans) > number {
				spans = spans[:number]
			}
			c.header("%s: %d intervals between samples, %s .. %s", name, len(spans), query.FormatMS(spans[0].From), query.FormatMS(spans[len(spans)-1].To))
		default:
			for i := 1; i < len(spans); i++ {
				if spans[i].From != spans[i-1].To {
					return errors.New(name + ": the system rebooted within the range; use --samples")
				}
			}
			spans = []query.Span{{From: spans[0].From, To: spans[len(spans)-1].To}}
			c.header("%s: one report for %s .. %s (use --samples for one per interval)", name, query.FormatMS(spans[0].From), query.FormatMS(spans[0].To))
		}
		return print(spans)
	}, nil
}

// spanMeta: a counter row ends at a sample (its ts_ms); over a range it
// covers the interval from the previous one. Every value is sampled.
func spanMeta(spans []query.Span, ts int64, row any, exact ...string) rowMeta {
	m := rowMeta{Sampled: jsonKeys(row, append(exact, "ts_ms", "time", "since_boot")...)}
	for _, sp := range spans {
		if sp.To == ts && sp.From != 0 {
			m.From, m.To = sp.From, sp.To
		}
	}
	return m
}
