package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/query"
)

// lsnsTool is util-linux's lsns over the processes' recorded namespaces.
func lsnsTool() *tool {
	return &tool{
		name:     "lsns",
		synopsis: "[-l] [-t TYPE]... [-p PID] [-o LIST] [--output-all] [-n] [-r] [-u] [-W] [NAMESPACE]",
		about:    "namespaces and the processes in them, as util-linux lsns prints them (as root)",
		opts: []opt{
			{short: 'l', long: "list", help: "a list instead of the process tree"},
			{short: 't', long: "type", arg: "TYPE", help: "only this type (mnt, net, ipc, user, pid, uts, cgroup, time); repeatable"},
			{short: 'p', long: "task", arg: "PID", help: "only the namespaces of this process"},
			{short: 'o', long: "output", arg: "LIST", help: "these columns (+LIST: added to the default ones)"},
			{long: "output-all", help: "every column"},
			{short: 'n', long: "noheadings", help: "no header line"},
			{short: 'r', long: "raw", help: "raw output"},
			{short: 'u', long: "notruncate", help: "accepted (a pipe truncates nothing)"},
			{short: 'W', long: "nowrap", help: "accepted"},
		},
		window: true,
		notes: []string{
			"The namespaces of the processes sampled at T (recorded since 2026-11-23, schema 15: each process's",
			"namespaces when it was first sampled). Not recorded, so not listed: namespaces held only by open",
			"file descriptors, sockets or bind mounts without a process in them; PNS and ONS (-T) are not",
			"available. NSFS: the recorded nsfs mounts. As root runs it (every process).",
		},
		examples: []string{`clifr --at "02:45" lsns`, `clifr --at "02:45" "lsns -t net"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if c.w.IsRange() {
				return nil, errors.New("lsns: needs --at")
			}
			o := query.LsnsOpts{List: p.has("list"), NoHead: p.has("noheadings"), Raw: p.has("raw"), ASCII: !query.LocaleUTF8()}
			for _, t := range p.all["type"] {
				if o.Types == nil {
					o.Types = map[string]bool{}
				}
				switch t {
				case "mnt", "net", "ipc", "user", "pid", "uts", "cgroup", "time":
					o.Types[t] = true
				default:
					return nil, fmt.Errorf("lsns: unknown namespace type: %s", t)
				}
			}
			if s := p.set["task"]; s != "" {
				n, err := strconv.Atoi(s)
				if err != nil || n <= 0 {
					return nil, fmt.Errorf("lsns: invalid PID argument: '%s'", s)
				}
				o.PID = n
			}
			if p.has("output-all") {
				o.Cols = []string{"NS", "TYPE", "PATH", "NPROCS", "PID", "PPID", "COMMAND", "UID", "USER", "NETNSID", "NSFS"}
			}
			if l := p.set["output"]; l != "" {
				o.ColsAdd = strings.HasPrefix(l, "+")
				var cols []string
				for _, n := range strings.Split(strings.TrimPrefix(l, "+"), ",") {
					n = strings.ToUpper(strings.TrimSpace(n))
					if n == "PNS" || n == "ONS" {
						return nil, fmt.Errorf("lsns: %s is not recorded", n)
					}
					if !query.LsnsColumn(n) {
						return nil, fmt.Errorf("lsns: unknown column: %s", n)
					}
					cols = append(cols, n)
				}
				o.Cols = cols
			}
			if len(p.pos) > 0 {
				return nil, errors.New("lsns: a NAMESPACE argument (its processes) is not supported")
			}
			return func() error {
				o.Version = query.StyleAt(c.db, c.w.At).Lsipc // the same util-linux release
				if o.Version == "2.32" && o.Types["time"] {
					return errors.New("lsns: util-linux 2.32 (the recorded host's) has no time namespaces")
				}
				l, err := query.LsnsAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				c.header("lsns: the namespaces of the processes sampled at %s (not those held only by fds, sockets or bind mounts)", query.FormatMS(l.TS))
				lo := o
				lo.List = true
				cols, rows := l.Rows(lo)
				objs := make([]map[string]string, len(rows))
				for i, r := range rows {
					objs[i] = map[string]string{}
					for j, col := range cols {
						objs[i][strings.ToLower(col)] = r[j]
					}
				}
				return c.emit(objs, func(int) rowMeta { return rowMeta{TS: c.w.At, SampleTS: l.TS} },
					func(w io.Writer) { query.PrintLsns(w, l, o) })
			}, nil
		},
	}
}
