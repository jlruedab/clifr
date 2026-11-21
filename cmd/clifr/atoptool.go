package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"

	"clifr/internal/query"
)

func atopTool() *tool {
	return &tool{
		name: "atop", synopsis: "[-m|-d|-s|-v|-c] [INTERVAL [COUNT]]",
		opts: []opt{
			{short: 'm', help: "memory view: segment sizes, growth, swap, sorted by resident memory"},
			{short: 'd', help: "disk view: bytes read, written and cancelled, sorted by disk transfer"},
			{short: 's', help: "scheduling view: threads by state, policy, nice, priority, CPU, run delay"},
			{short: 'v', help: "various view: parent, real user and group, start date and time"},
			{short: 'c', help: "command-line view: the full command line (255 bytes, as atop reads it)"},
		},
		about:  "the system and its processes since boot, as atop prints its first screen into a pipe",
		window: true,
		notes: []string{
			"atop's screen since boot as root (atop 1 1), as the recorded host's atop prints it (2.7.1 on",
			"RHEL 8 and 9 and Ubuntu 22.04, 2.12.1 otherwise): its system lines (processes, CPUs, load,",
			"memory, swap, paging, pressure, disks, network) from the system sample at or before T, then every",
			"process with its totals since it started, the most CPU time first. The values are those of",
			"clifrd's samples (every 10 s for the system, every --interval for processes). An interface's busy",
			"% needs its speed: wireless interfaces show ---- (atop asks the driver). Recorded since schema 12",
			"(older recordings: no committed memory, page tables, OOM kills or pressure).",
			"Over a range (atop INTERVAL [COUNT]): the screen since boot at --since, then one per INTERVAL",
			"seconds up to --until (or COUNT screens): each the increase between the samples at or before its",
			"bounds, and only the processes active in it (a process whose only change was a context switch or",
			"page fault, without a CPU tick, is not seen as active) and those that exited in it (<name>, their",
			"CPU time up to their last sample). Choose INTERVAL as a multiple of the recorded intervals.",
			"The process views -m -d -s -v -c are atop's, each with its columns fitted to 80 characters by",
			"atop's priorities; PSIZE (proportional size) is 0B as in atop without -R. Thread sums (BDELAY,",
			"NVCSW, NIVCSW, TSLPI...), segment sizes and group names are recorded since schema 12.",
		},
		examples: []string{`clifr --at "02:45" atop`, `clifr --since "02:40" --until "02:50" "atop 60"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			var nums []int64
			for _, a := range p.pos {
				v, err := strconv.ParseInt(a, 10, 64)
				if err != nil || v < 1 {
					return nil, fmt.Errorf("atop: %q: INTERVAL and COUNT are positive numbers (atop [INTERVAL [COUNT]])", a)
				}
				nums = append(nums, v)
			}
			if len(nums) > 2 {
				return nil, errors.New("atop: atop [INTERVAL [COUNT]]")
			}
			view := ""
			for _, v := range []string{"m", "d", "s", "v", "c"} {
				if p.has(v) {
					if view != "" {
						return nil, fmt.Errorf("atop: -%s and -%s: one process view at a time", view, v)
					}
					view = v
				}
			}
			if !c.w.IsRange() {
				if len(nums) > 0 && (len(nums) != 2 || nums[1] != 1) {
					return nil, errors.New("atop: with --at, only the screen since boot (atop or atop 1 1); for intervals use --since and --until")
				}
				return func() error {
					a, err := query.AtopSysAt(c.db, c.w.At)
					if err != nil {
						return err
					}
					a.V271, a.View = query.StyleAt(c.db, c.w.At).Atop271, view
					return c.emit([]*query.AtopSys{a}, func(int) rowMeta { return rowMeta{TS: c.w.At} },
						func(w io.Writer) {
							query.PrintAtopSys(w, a)
							query.PrintAtopProcs(w, a)
						})
				}, nil
			}
			if len(nums) == 0 {
				return nil, errors.New("atop: over a range give the interval: atop INTERVAL [COUNT] (seconds)")
			}
			step := nums[0] * 1000
			count := int64(-1)
			if len(nums) == 2 {
				count = nums[1]
			}
			return func() error {
				v271 := query.StyleAt(c.db, c.w.From).Atop271
				var screens []*query.AtopSys
				first, err := query.AtopSysAt(c.db, c.w.From)
				if err != nil {
					return err
				}
				first.V271, first.View = v271, view
				screens = append(screens, first)
				for t := c.w.From + step; t <= c.w.To && (count < 0 || int64(len(screens)) < count); t += step {
					a, err := query.AtopIntervalAt(c.db, t-step, t)
					if err != nil {
						return err
					}
					a.V271, a.View = v271, view
					screens = append(screens, a)
				}
				return c.emit(screens, func(i int) rowMeta { return rowMeta{TS: screens[i].T} },
					func(w io.Writer) {
						for _, a := range screens {
							query.PrintAtopSys(w, a)
							query.PrintAtopProcs(w, a)
						}
					})
			}, nil
		},
	}
}
