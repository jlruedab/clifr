package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"clifr/internal/query"
)

// lsmemTool is util-linux's lsmem over the recorded memory blocks.
func lsmemTool() *tool {
	return &tool{
		name:     "lsmem",
		synopsis: "[-a] [-b] [-n] [-o LIST] [--output-all] [-r|-P] [-S LIST] [--summary[=WHEN]]",
		about:    "memory ranges and their online state, as util-linux lsmem prints them",
		opts: []opt{
			{short: 'a', long: "all", help: "every memory block on its own line"},
			{short: 'b', long: "bytes", help: "sizes in bytes"},
			{short: 'n', long: "noheadings", help: "no header line"},
			{short: 'o', long: "output", arg: "LIST", help: "these columns (+LIST: added to the default ones)"},
			{long: "output-all", help: "every column"},
			{short: 'r', long: "raw", help: "raw output"},
			{short: 'P', long: "pairs", help: "NAME=\"value\" pairs"},
			{short: 'S', long: "split", arg: "LIST", help: "split ranges by these columns (none: by none)"},
			{long: "summary", arg: "WHEN", optional: true, help: "never, always or only (alone: only)"},
		},
		window: true,
		notes: []string{
			"From /sys/devices/system/memory as clifrd reads it every 10 minutes (since 2026-11-23). The",
			"release of the recorded host decides the layout: 2.41, 2.39 (Ubuntu 24.04), 2.37 (RHEL 9,",
			"Ubuntu 22.04), 2.32 (RHEL 8).",
		},
		examples: []string{`clifr --at "02:45" lsmem`, `clifr --at "02:45" "lsmem -o +NODE,ZONES"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("lsmem: unexpected argument %q", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("lsmem: needs --at")
			}
			o := query.LsmemOpts{All: p.has("all"), Bytes: p.has("bytes"), NoHead: p.has("noheadings"), Raw: p.has("raw"),
				Pairs: p.has("pairs")}
			if o.Raw && o.Pairs {
				return nil, errors.New("lsmem: -r and -P are mutually exclusive")
			}
			cols := func(list string) ([]string, error) {
				var out []string
				for _, n := range strings.Split(list, ",") {
					n = strings.ToUpper(strings.TrimSpace(n))
					if !query.LsmemColumn(n) {
						return nil, fmt.Errorf("lsmem: unknown column: %s", n)
					}
					out = append(out, n)
				}
				return out, nil
			}
			if p.has("output-all") {
				o.Cols = []string{"RANGE", "SIZE", "STATE", "REMOVABLE", "BLOCK", "NODE", "ZONES"}
			}
			if l := p.set["output"]; l != "" {
				o.ColsAdd = strings.HasPrefix(l, "+")
				x, err := cols(strings.TrimPrefix(l, "+"))
				if err != nil {
					return nil, err
				}
				if o.ColsAdd && p.has("output-all") {
					o.Cols, o.ColsAdd = append(o.Cols, x...), false
				} else {
					o.Cols = x
				}
			}
			if l := p.set["split"]; l != "" {
				if strings.EqualFold(l, "none") {
					o.Split = []string{}
				} else {
					x, err := cols(l)
					if err != nil {
						return nil, err
					}
					o.Split = x
				}
			}
			if p.has("summary") {
				switch v := p.set["summary"]; v {
				case "":
					o.Summary = "only"
				case "never", "always", "only":
					o.Summary = v
				default:
					return nil, errors.New("lsmem: unsupported --summary argument")
				}
			}
			if (o.Raw || o.Pairs) && o.Summary == "only" {
				return nil, errors.New("lsmem: options --{raw,json,pairs} and --summary=only are mutually exclusive")
			}
			return func() error {
				o.Version = query.StyleAt(c.db, c.w.At).Lsipc // the same util-linux release
				if o.Version == "2.32" && p.has("output-all") {
					return errors.New("lsmem: util-linux 2.32 (the recorded host's) has no --output-all")
				}
				m, err := query.LsmemAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				c.header("lsmem: memory blocks as read at %s", query.FormatMS(m.TS))
				cols, rows := query.LsmemRows(m, o)
				objs := make([]map[string]string, len(rows))
				for i, r := range rows {
					objs[i] = map[string]string{}
					for j, col := range cols {
						objs[i][strings.ToLower(col)] = r[j]
					}
				}
				return c.emit(objs, func(int) rowMeta { return rowMeta{TS: c.w.At, SampleTS: m.TS} },
					func(w io.Writer) { query.PrintLsmem(w, m, o) })
			}, nil
		},
	}
}
