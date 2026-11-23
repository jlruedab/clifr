package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"clifr/internal/query"
)

// lscpuTool is util-linux's lscpu over the recorded CPU files.
func lscpuTool() *tool {
	return &tool{
		name:     "lscpu",
		synopsis: "[-e[=LIST] | -p[=LIST] | -C[=LIST]] [-a|-b|-c] [-B] [-x] [-y] [--output-all]",
		about:    "CPU architecture, topology, caches and frequencies, as util-linux lscpu prints them",
		opts: []opt{
			{short: 'e', long: "extended", arg: "LIST", optional: true, attached: true, help: "a table, one line per CPU"},
			{short: 'p', long: "parse", arg: "LIST", optional: true, attached: true, help: "parsable output, one line per CPU"},
			{short: 'C', long: "caches", arg: "LIST", optional: true, attached: true, help: "the caches, one line each"},
			{short: 'a', long: "all", help: "online and offline CPUs (-e, -p)"},
			{short: 'b', long: "online", help: "online CPUs only (-e, -p)"},
			{short: 'c', long: "offline", help: "offline CPUs only (-e, -p)"},
			{short: 'B', long: "bytes", help: "sizes in bytes"},
			{short: 'x', long: "hex", help: "CPU masks instead of lists"},
			{short: 'y', long: "physical", help: "physical ids instead of logical ones (-e, -p)"},
			{long: "output-all", help: "every column"},
		},
		window: true,
		notes: []string{
			"From the CPU files clifrd records once a minute (sysfs topology, caches, frequency limits,",
			"vulnerabilities; /proc/cpuinfo without its MHz) since 2026-11-23, and the CPUs' MHz at the",
			"sample (MHZ, CPU(s) scaling MHz: cpuinfo's, where lscpu reads scaling_cur_freq). As an",
			"unprivileged user runs it: no BIOS lines (DMI is root's). Into a pipe: one flat list. The",
			"release of the recorded host decides the layout: 2.41, 2.39 (Ubuntu 24.04), 2.37 (RHEL 9,",
			"Ubuntu 22.04), 2.32 (RHEL 8).",
		},
		examples: []string{`clifr --at "02:45" lscpu`, `clifr --at "02:45" "lscpu -e"`, `clifr --at "02:45" "lscpu -C"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("lscpu: unexpected argument %q", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("lscpu: needs --at")
			}
			o := query.LscpuOpts{Hex: p.has("hex"), Bytes: p.has("bytes"), Physical: p.has("physical"), Online: p.has("online"),
				Offline: p.has("offline"), All: p.has("all"), OutputAll: p.has("output-all")}
			modes := 0
			list := ""
			for _, m := range []struct{ opt, mode string }{{"extended", "e"}, {"parse", "p"}, {"caches", "C"}} {
				if p.has(m.opt) {
					o.Mode, list = m.mode, p.set[m.opt]
					modes++
				}
			}
			if modes > 1 {
				return nil, errors.New("lscpu: -e, -p and -C are mutually exclusive")
			}
			if (o.All || o.Online || o.Offline) && (o.Mode == "" || o.Mode == "C") {
				return nil, errors.New("lscpu: options --all, --online and --offline may only be used with options --extended or --parse.")
			}
			if list = strings.TrimPrefix(list, "="); list != "" {
				o.ColsAdd = strings.HasPrefix(list, "+")
				for _, n := range strings.Split(strings.TrimPrefix(list, "+"), ",") {
					n = strings.ToUpper(strings.TrimSpace(n))
					if !query.LscpuColumn(n, o.Mode == "C") {
						return nil, fmt.Errorf("lscpu: unknown column: %s", n)
					}
					o.Cols = append(o.Cols, n)
				}
			}
			return func() error {
				o.Version = query.StyleAt(c.db, c.w.At).Lscpu
				if o.Version == "2.32" && (o.Mode == "C" || o.Bytes) {
					return errors.New("lscpu: util-linux 2.32 (the recorded host's) has no -C or -B")
				}
				for _, n := range o.Cols {
					if o.Mode != "C" && !query.LscpuColumnIn(n, o.Version) {
						return fmt.Errorf("lscpu: unknown column: %s", n)
					}
				}
				x, err := query.LscpuAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				c.header("lscpu: CPU files as read at %s; MHz from the sample", query.FormatMS(x.TS))
				rows := query.LscpuJSON(x, o)
				return c.emit(rows, func(int) rowMeta { return rowMeta{TS: c.w.At, SampleTS: x.TS} },
					func(w io.Writer) { query.PrintLscpu(w, x, o) })
			}, nil
		},
	}
}
