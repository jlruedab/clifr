package main

import (
	"errors"
	"fmt"
	"io"

	"clifr/internal/query"
)

func atopTool() *tool {
	return &tool{
		name: "atop", synopsis: "[1 1]",
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
		},
		examples: []string{`clifr --at "02:45" atop`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if n := len(p.pos); n != 0 && (n != 2 || p.pos[0] != "1" || p.pos[1] != "1") {
				return nil, fmt.Errorf("atop: only the screen since boot is supported (atop or atop 1 1), not %q", p.pos)
			}
			if c.w.IsRange() {
				return nil, errors.New("atop: needs --at")
			}
			return func() error {
				a, err := query.AtopSysAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				a.V271 = query.StyleAt(c.db, c.w.At).Atop271
				return c.emit([]*query.AtopSys{a}, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) {
						query.PrintAtopSys(w, a)
						query.PrintAtopProcs(w, a)
					})
			}, nil
		},
	}
}
