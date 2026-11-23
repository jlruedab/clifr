package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"clifr/internal/query"
)

// vmstatTool is vmstat with its reports: the default one (-a -w -t -S -n
// -y), -s, -f and -D (counters at a moment), -d, -p and -m (the counters at
// each report's sample).
func vmstatTool(common []string) *tool {
	return &tool{
		name: "vmstat", synopsis: "[-a] [-w] [-t] [-n] [-y] [-S UNIT] [-s|-f|-d|-D|-p DEVICE|-m] [INTERVAL [COUNT]]",
		about: "memory, swap, I/O, system and CPU activity",
		opts: []opt{
			{short: 'a', help: "inactive and active memory instead of buffers and cache"},
			{short: 'w', help: "wide output"},
			{short: 't', help: "a timestamp after each line"},
			{short: 'n', help: "the header once (vmstat into a pipe repeats it every 21 lines)"},
			{short: 'y', help: "no since-boot line (clifr prints none over a range anyway)"},
			{short: 'S', arg: "UNIT", help: "memory and swap in b, k (1000), K (1024, default), m or M"},
			{short: 's', help: "the counters and memory as a list (a moment: --at)"},
			{short: 'f', help: "forks since boot (a moment: --at)"},
			{short: 'd', help: "each disk's counters since boot"},
			{short: 'D', help: "the disks' counters summed (a moment: --at)"},
			{short: 'p', arg: "DEVICE", help: "one disk or partition's counters since boot"},
			{short: 'm', help: "slab caches (as read every minute)"},
		},
		window: true,
		notes: append(append([]string{}, common...),
			"-d, -D, -p: devices that did no I/O since boot are not recorded (not listed, not summed).",
			"The release of the recorded host decides the layout: procps-ng 4.0.4, 3.3.17 (RHEL 9, Ubuntu 22.04:",
			"no gu column), 3.3.15 (RHEL 8)."),
		examples: []string{`clifr --since "02:00" --until "02:30" "vmstat 60"`, `clifr --at "02:45" "vmstat -s"`,
			`clifr --since "02:00" --until "02:30" "vmstat -d 600"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			o := query.VmstatOpts{Active: p.has("a"), Wide: p.has("w"), Times: p.has("t"), OneHead: p.has("n")}
			if u := p.set["S"]; u != "" {
				if !strings.ContainsRune("bBkKmM", rune(u[0])) {
					return nil, errors.New("vmstat: -S requires k, K, m or M (default is KiB)")
				}
				o.Unit = u[0]
			}
			var modes []string
			for _, m := range []string{"s", "f", "d", "D", "p", "m"} {
				if p.has(m) {
					modes = append(modes, "-"+m)
				}
			}
			if len(modes) > 1 && !(len(modes) == 2 && p.has("f")) {
				return nil, fmt.Errorf("vmstat: %s: one report at a time", strings.Join(modes, " "))
			}
			style := func(t int64) query.VmstatOpts { o.Version = query.StyleAt(c.db, t).Vmstat; return o }
			switch {
			case p.has("f"), p.has("s"), p.has("D"):
				if c.w.IsRange() {
					return nil, fmt.Errorf("vmstat %s: the counters at a moment; use --at", modes[0])
				}
				if len(p.pos) > 0 {
					return nil, fmt.Errorf("vmstat %s: unexpected argument %q", modes[0], p.pos[0])
				}
				return func() error {
					spans, err := query.SysSpans(c.db, c.w, 0) // the sample at or before T
					if err != nil {
						return err
					}
					at := spans[0].To
					o := style(at)
					if p.has("D") {
						s, err := query.VMStatDiskSumAt(c.db, at)
						if err != nil {
							return err
						}
						c.header("vmstat -D: the disks' counters since boot at the sample of %s (devices that did no I/O are not recorded)", query.FormatMS(s.TS))
						return c.emit([]query.VMStatDiskSum{s}, func(int) rowMeta { return rowMeta{TS: c.w.At, SampleTS: s.TS} },
							func(w io.Writer) { query.PrintVMStatDiskSum(w, s, o) })
					}
					s, err := query.VMStatSumAt(c.db, at)
					if err != nil {
						return err
					}
					c.header("vmstat %s: the counters at the sample of %s", modes[0], query.FormatMS(s.TS))
					return c.emit([]query.VMStatSum{s}, func(int) rowMeta { return rowMeta{TS: c.w.At, SampleTS: s.TS} },
						func(w io.Writer) {
							if p.has("f") { // -f prints and exits before the other reports
								query.PrintVMStatForks(w, s)
								return
							}
							query.PrintVMStatSum(w, s, o)
						})
				}, nil
			case p.has("d"), p.has("p"), p.has("m"):
				name := strings.TrimPrefix(p.set["p"], "/dev/")
				return prepareSys("vmstat "+modes[0], p, c, func(spans []query.Span) error {
					o := style(spans[len(spans)-1].To)
					switch {
					case p.has("p"):
						var parts []query.VMStatPart
						for _, sp := range spans {
							x, ok, err := query.VMStatPartAt(c.db, sp.To, name)
							if err != nil {
								return err
							}
							if !ok {
								return fmt.Errorf("vmstat: Disk/Partition %s not found", name)
							}
							parts = append(parts, x)
						}
						return c.emit(parts, func(i int) rowMeta { return rowMeta{TS: parts[i].TS} },
							func(w io.Writer) { query.PrintVMStatParts(w, name, parts) })
					case p.has("m"):
						var reps []query.VMStatSlabs
						for _, sp := range spans {
							slabs, _, err := query.SlabsAt(c.db, sp.To)
							if err != nil {
								return errors.New(strings.Replace(err.Error(), "slabtop:", "vmstat -m:", 1))
							}
							reps = append(reps, query.VMStatSlabs{TS: sp.To, Slabs: slabs})
						}
						return c.emit(reps, func(i int) rowMeta { return rowMeta{TS: reps[i].TS} },
							func(w io.Writer) { query.PrintVMStatSlabs(w, reps, o) })
					}
					var reps []query.VMStatDisks
					for _, sp := range spans {
						d, err := query.VMStatDisksAt(c.db, sp.To, true)
						if err != nil {
							return err
						}
						reps = append(reps, d)
					}
					c.header("vmstat -d: devices that did no I/O since boot are not recorded")
					return c.emit(reps, func(i int) rowMeta { return rowMeta{TS: reps[i].TS} },
						func(w io.Writer) { query.PrintVMStatDisks(w, reps, o) })
				})
			}
			return prepareSys("vmstat", p, c, func(spans []query.Span) error {
				rows, err := query.VMStat(c.db, spans)
				if err != nil {
					return err
				}
				o := style(spans[len(spans)-1].To)
				return c.emit(rows, func(i int) rowMeta { return spanMeta(spans, rows[i].TS, rows[i]) },
					func(w io.Writer) { query.PrintVMStatOpts(w, rows, o) })
			})
		},
	}
}
