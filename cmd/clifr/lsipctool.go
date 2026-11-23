package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/query"
)

// lsipcTool is util-linux's lsipc over the recorded System V IPC objects.
func lsipcTool() *tool {
	return &tool{
		name:     "lsipc",
		synopsis: "[-q|-m|-s] [-g] [-i ID] [-b] [-c|-t|-o LIST] [-P] [-r|-e|-n] [--noheadings] [--time-format FMT]",
		about:    "System V IPC limits and objects, as util-linux lsipc prints them",
		opts: []opt{
			{short: 'q', long: "queues", help: "message queues"},
			{short: 'm', long: "shmems", help: "shared memory segments"},
			{short: 's', long: "semaphores", help: "semaphore arrays"},
			{short: 'g', long: "global", help: "the limits and their use (the default)"},
			{short: 'i', long: "id", arg: "ID", help: "one object, in detail"},
			{short: 'b', long: "bytes", help: "sizes in bytes"},
			{short: 'c', long: "creator", help: "the creator and owner columns"},
			{short: 't', long: "time", help: "the time columns"},
			{short: 'o', long: "output", arg: "LIST", help: "these columns (+LIST: added to the default ones)"},
			{short: 'P', long: "numeric-perms", help: "permissions as numbers"},
			{short: 'r', long: "raw", help: "raw output"},
			{short: 'e', long: "export", help: "NAME=\"value\" pairs"},
			{short: 'n', long: "newline", help: "export, one value per line"},
			{long: "noheadings", help: "no header line"},
			{long: "notruncate", help: "accepted (a pipe truncates nothing)"},
			{long: "time-format", arg: "FMT", help: "short, full or iso"},
		},
		window: true,
		notes: []string{
			"/proc/sysvipc at the last system sample at or before T and the limits as last read (sysctl,",
			"every minute); COMMAND is the creator's command line if it was alive at T. util-linux 2.41's",
			"POSIX message queue count (MQUMNI USED) is not recorded (\"-\"); POSIX objects (-M -Q -S) and",
			"semaphore values (--id with -s: Elements) are not recorded. The release of the recorded host",
			"decides the layout: 2.41, 2.39 (Ubuntu 24.04), 2.37 (RHEL 9, Ubuntu 22.04), 2.32 (RHEL 8).",
		},
		examples: []string{`clifr --at "02:45" lsipc`, `clifr --at "02:45" "lsipc -m"`, `clifr --at "02:45" "lsipc -m -i 23"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("lsipc: unexpected argument %q", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("lsipc: needs --at")
			}
			o := query.LsipcOpts{Global: p.has("global"), Bytes: p.has("bytes"), Creator: p.has("creator"), Times: p.has("time"),
				NumPerms: p.has("numeric-perms"), NoHead: p.has("noheadings"), Raw: p.has("raw"), Export: p.has("export"),
				Newline: p.has("newline"), TimeMode: p.set["time-format"], ID: -1}
			kinds := 0
			for _, k := range []struct{ opt, kind string }{{"queues", "msg"}, {"shmems", "shm"}, {"semaphores", "sem"}} {
				if p.has(k.opt) {
					o.Kind = k.kind
					kinds++
				}
			}
			if kinds > 1 {
				return nil, errors.New("lsipc: -q, -m and -s are mutually exclusive")
			}
			if n := btoi(o.Creator) + btoi(o.Times) + btoi(p.has("output")); n > 1 {
				return nil, errors.New("lsipc: -c, -t and -o are mutually exclusive")
			}
			if btoi(o.Raw)+btoi(o.Export)+btoi(o.Newline) > 1 {
				return nil, errors.New("lsipc: -r, -e and -n are mutually exclusive")
			}
			if s := p.set["id"]; s != "" {
				n, err := strconv.Atoi(s)
				if err != nil || n < 0 {
					return nil, fmt.Errorf("lsipc: failed to parse IPC identifier: '%s'", s)
				}
				o.ID = n
			}
			switch o.TimeMode {
			case "", "short", "full", "iso":
			default:
				return nil, fmt.Errorf("lsipc: unknown time format: %s", o.TimeMode)
			}
			if o.Global && o.ID >= 0 {
				return nil, errors.New("lsipc: -g and -i are mutually exclusive")
			}
			if o.Kind == "" && (o.Creator || o.Times || o.ID >= 0) {
				return nil, errors.New("lsipc: --global is mutually exclusive with --creator, --id, --name and --time")
			}
			if cols := p.set["output"]; cols != "" {
				o.ColsAdd = strings.HasPrefix(cols, "+")
				for _, n := range strings.Split(strings.TrimPrefix(cols, "+"), ",") {
					n = strings.ToUpper(strings.TrimSpace(n))
					if _, ok := query.LsipcColumn(n); !ok {
						return nil, fmt.Errorf("lsipc: unknown column: %s", n)
					}
					if !query.LsipcApplies(n, o.Kind) && !(o.Global && query.LsipcApplies(n, "")) {
						return nil, fmt.Errorf("lsipc: column %s does not apply to the specified IPC", n)
					}
					o.Cols = append(o.Cols, n)
				}
			}
			return func() error {
				o.Version = query.StyleAt(c.db, c.w.At).Lsipc
				tb, err := query.LsipcAt(c.db, c.w.At, o)
				if err != nil {
					return err
				}
				if o.Kind == "sem" && tb.Pretty {
					c.header("lsipc: the semaphores' values (Elements) are not recorded")
				}
				if tb.MqUsedUnknown {
					c.header("lsipc: MQUMNI's USED (POSIX message queues in /dev/mqueue) is not recorded")
				}
				return c.emit(tb.Objects, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { query.PrintLsipc(w, tb, o) })
			}, nil
		},
	}
}
