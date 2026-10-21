package main

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"clifr/internal/query"
)

func pstreeTool() *tool {
	return &tool{
		name: "pstree", synopsis: "-p [-l] [-T] [-n] [-A|-U] [PID]",
		about: "the process tree, as psmisc pstree prints it",
		opts: []opt{
			{short: 'p', help: "show PIDs (required: without it pstree merges identical subtrees, not reconstructed)"},
			{short: 'l', help: "long lines: none is cut (otherwise at 132 columns, ending in +)"},
			{short: 'T', help: "hide threads (always: threads are not recorded)"},
			{short: 'n', help: "sort children by PID instead of by name"},
			{short: 'A', help: "ASCII line drawing (the default)"},
			{short: 'U', help: "UTF-8 line drawing"},
		},
		window: true,
		notes: []string{
			"--at: the processes alive at T (as ps aux shows them), from PID 1 or the PID given.",
			"Threads are not recorded: the tree is pstree's with -T, without {thread}(TID) entries.",
			"--since: one tree per sample with --samples.",
		},
		examples: []string{`clifr --at "02:45" "pstree -lp"`, `clifr --at "02:45" "pstree -lpT 4242"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if !p.has("p") {
				return nil, errors.New("pstree: add -p: without it pstree merges identical subtrees (N*[...]), which clifr does not reconstruct")
			}
			if p.has("A") && p.has("U") {
				return nil, errors.New("pstree: use -A or -U, not both")
			}
			f := query.PstreeFormat{Root: 1, SortPID: p.has("n"), Unicode: p.has("U"), Long: p.has("l")}
			switch {
			case len(p.pos) > 1:
				return nil, fmt.Errorf("pstree: unexpected argument %q", p.pos[1])
			case len(p.pos) == 1:
				n, err := strconv.Atoi(p.pos[0])
				if err != nil || n <= 0 {
					return nil, fmt.Errorf("pstree: bad PID %q (user names are not supported)", p.pos[0])
				}
				f.Root = n
			}
			if c.g.changes {
				return nil, errors.New("pstree: --changes is not supported; use --samples, or ps aux f with --changes")
			}
			if c.w.IsRange() && !c.g.samples {
				return nil, errors.New("pstree: a range needs --samples (one tree per sample)")
			}
			if !p.has("T") {
				c.header("pstree: threads are not recorded; shown as with -T")
			}
			return func() error {
				at := func(t int64) ([]pstreeLine, func(*pstreeLine) rowMeta, error) {
					rows, s, err := query.PSAt(c.db, t)
					if err != nil {
						return nil, nil, err
					}
					lines, ok := query.Pstree(rows, f)
					if !ok {
						return nil, nil, fmt.Errorf("pstree: no process %d at %s", f.Root, query.FormatMS(t))
					}
					out := make([]pstreeLine, len(lines))
					for i, l := range lines {
						out[i] = pstreeLine{Line: l}
					}
					return out, func(*pstreeLine) rowMeta { return rowMeta{TS: t, SampleTS: s} }, nil
				}
				v := view[pstreeLine]{name: "pstree", at: at,
					key:  func(l *pstreeLine) string { return l.Line },
					same: func(a, b *pstreeLine) bool { return true },
					print: func(w io.Writer, lines []pstreeLine) {
						for _, l := range lines {
							fmt.Fprintln(w, l.Line)
						}
					}}
				if ok, err := rangeView(c, v); ok {
					return err
				}
				lines, meta, err := at(c.w.At)
				if err != nil {
					return err
				}
				return c.emit(lines, func(i int) rowMeta { return meta(&lines[i]) }, func(w io.Writer) { v.print(w, lines) })
			}, nil
		},
	}
}

// pstreeLine is one line of the tree (--json: one object per line).
type pstreeLine struct {
	Line string `json:"line"`
}

func dateTool() *tool {
	return &tool{
		name: "date", synopsis: "[-u|--utc|--universal] [-R]",
		about: "the moment asked for, as date prints it",
		opts: []opt{
			{short: 'u', long: "utc", help: "in UTC"},
			{long: "universal", help: "in UTC (the same as -u)"},
			{short: 'R', long: "rfc-email", help: "RFC 5322 format: Wed, 21 Oct 2026 14:06:24 +1030"},
		},
		window: true,
		notes: []string{
			"--at T prints T itself (exact), in GNU date's C-locale format, in the time zone of --tz",
			"(default: local time) or UTC with -u.",
		},
		examples: []string{`clifr --at "02:45" date`, `clifr --at "02:45" "date --utc"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("date: unexpected argument %q (+FORMAT and setting the date are not supported)", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("date: needs --at")
			}
			utc := p.has("utc") || p.has("universal")
			return func() error {
				t := time.UnixMilli(c.w.At)
				if utc {
					t = t.UTC()
				}
				s := dateText(t, p.has("rfc-email"))
				return c.emit(dateRow{Date: s}, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { fmt.Fprintln(w, s) })
			}, nil
		},
	}
}

type dateRow struct {
	Date string `json:"date"`
}

// dateText is GNU date's output in the C locale ("Wed Oct 21 14:06:24 ACDT
// 2026", the day padded with a space), or with rfc its -R format.
func dateText(t time.Time, rfc bool) string {
	if rfc {
		return t.Format("Mon, 02 Jan 2006 15:04:05 -0700")
	}
	return t.Format("Mon Jan _2 15:04:05 MST 2006")
}

func findmntTool() *tool {
	return &tool{
		name: "findmnt", synopsis: "[-l] [-a|--ascii]",
		about: "the mount tree, as util-linux findmnt prints it",
		opts: []opt{
			{short: 'l', long: "list", help: "a list in mountinfo order instead of the tree"},
			{short: 'a', long: "ascii", help: "ASCII tree characters (the default: as in the C locale)"},
		},
		window: true, diff: true,
		notes: []string{
			"--at: the mount table at T (exact), TARGET SOURCE FSTYPE OPTIONS. The parent of each mount is",
			"not recorded: it is taken to be the mount on the longest prefix of its path (findmnt reads it",
			"from mountinfo; the two differ only for mounts made under a path that was later mounted over).",
			"--since: --samples, or --changes (mounts that appeared, went or changed options).",
		},
		examples: []string{`clifr --at "02:45" findmnt`, `clifr --since "02:00" --until "03:00" --changes findmnt`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("findmnt: unexpected argument %q (searching by device or path is not supported)", p.pos[0])
			}
			if c.w.IsRange() && !c.g.samples && !c.g.changes {
				return nil, errors.New("findmnt: over a range, add --samples or --changes")
			}
			list := p.has("list")
			v := view[query.FindmntRow]{
				name: "findmnt",
				at: func(t int64) ([]query.FindmntRow, func(*query.FindmntRow) rowMeta, error) {
					rows, err := query.Findmnt(c.db, t, list)
					return rows, func(*query.FindmntRow) rowMeta { return rowMeta{TS: t} }, err
				},
				key:   func(r *query.FindmntRow) string { return strconv.Itoa(r.MountID) + " " + r.Target },
				same:  func(a, b *query.FindmntRow) bool { return a.Source == b.Source && a.Options == b.Options },
				print: query.PrintFindmnt,
			}
			return func() error {
				if ok, err := rangeView(c, v); ok {
					return err
				}
				rows, meta, err := v.at(c.w.At)
				if err != nil {
					return err
				}
				return c.emit(rows, func(i int) rowMeta { return meta(&rows[i]) }, func(w io.Writer) { v.print(w, rows) })
			}, nil
		},
	}
}

func hostnameTool() *tool {
	return &tool{
		name: "hostname", synopsis: "[-s]",
		about: "the host name, as clifrd recorded it when it started",
		opts: []opt{
			{short: 's', long: "short", help: "up to the first dot"},
		},
		window: true,
		notes: []string{
			"The name the kernel had when the clifrd run covering T started; a later change is not recorded.",
			"-f (the FQDN, from DNS) is not recorded.",
		},
		examples: []string{`clifr --at "02:45" hostname`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("hostname: unexpected argument %q (setting the name is not supported)", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("hostname: needs --at")
			}
			return func() error {
				h := query.MetaAt(c.db, "hostname", c.w.At)
				if h == "" {
					return fmt.Errorf("hostname: not recorded at %s", query.FormatMS(c.w.At))
				}
				if p.has("short") {
					h, _, _ = strings.Cut(h, ".")
				}
				return c.emit(hostRow{Hostname: h}, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { fmt.Fprintln(w, h) })
			}, nil
		},
	}
}

type hostRow struct {
	Hostname string `json:"hostname"`
}

func unameTool() *tool {
	return &tool{
		name: "uname", synopsis: "[-a] [-s] [-n] [-r] [-v] [-m] [-p] [-i] [-o]",
		about: "the kernel, as clifrd recorded it when it started",
		opts: []opt{
			{short: 'a', long: "all", help: "everything, in the order below"},
			{short: 's', long: "kernel-name", help: "kernel name (the default)"},
			{short: 'n', long: "nodename", help: "host name"},
			{short: 'r', long: "kernel-release", help: "kernel release"},
			{short: 'v', long: "kernel-version", help: "kernel version"},
			{short: 'm', long: "machine", help: "machine hardware name"},
			{short: 'p', long: "processor", help: "processor type (the machine, as RHEL's and Debian's coreutils print it)"},
			{short: 'i', long: "hardware-platform", help: "hardware platform (the machine, likewise)"},
			{short: 'o', long: "operating-system", help: "operating system (GNU/Linux)"},
		},
		window: true,
		notes: []string{
			"The values of the clifrd run covering T (recorded since schema 3; a kernel changes only at boot).",
		},
		examples: []string{`clifr --at "02:45" "uname -a"`, `clifr --at "02:45" "uname -r"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("uname: unexpected argument %q", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("uname: needs --at")
			}
			keys := []string{"kernel-name", "nodename", "kernel-release", "kernel-version", "machine", "processor", "hardware-platform", "operating-system"}
			var want []string
			for _, k := range keys {
				if p.has("all") || p.has(k) {
					want = append(want, k)
				}
			}
			if len(want) == 0 {
				want = []string{"kernel-name"}
			}
			return func() error {
				at := func(key string) string { return query.MetaAt(c.db, key, c.w.At) }
				machine := at("uname_machine")
				if at("uname_release") == "" {
					return fmt.Errorf("uname: not in this recording at %s (recorded since schema 3)", query.FormatMS(c.w.At))
				}
				vals := map[string]string{"kernel-name": at("uname_sysname"), "nodename": at("hostname"),
					"kernel-release": at("uname_release"), "kernel-version": at("uname_version"), "machine": machine,
					"processor": machine, "hardware-platform": machine, "operating-system": "GNU/Linux"}
				var out []string
				for _, k := range want {
					out = append(out, vals[k])
				}
				line := strings.Join(out, " ")
				return c.emit(unameRow{Uname: line}, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { fmt.Fprintln(w, line) })
			}, nil
		},
	}
}

type unameRow struct {
	Uname string `json:"uname"`
}

func lastTool() *tool {
	return &tool{
		name: "last", synopsis: "[-F] reboot",
		about: "the boots of the machine within the recording, as util-linux last reboot prints them",
		opts: []opt{
			{short: 'F', long: "fulltimes", help: "full times (date and seconds)"},
		},
		window: true,
		notes: []string{
			"Only reboot: logins are not recorded. The boots that started by T (boot id and time of each",
			"clifrd run; the kernel recorded since schema 3, \"-\" before). The boot covering T is \"still",
			"running\"; an earlier one ends at its last recorded sample (wtmp has the shutdown time, or",
			"\"crash\"). \"wtmp begins\" is the start of the recording.",
		},
		examples: []string{`clifr --at now "last -F reboot"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) != 1 || p.pos[0] != "reboot" {
				return nil, errors.New(`last: only "last [-F] reboot" (logins are not recorded)`)
			}
			if c.w.IsRange() {
				return nil, errors.New("last: needs --at")
			}
			return func() error {
				boots, err := query.Boots(c.db, c.w.At)
				if err != nil {
					return err
				}
				if len(boots) == 0 {
					return fmt.Errorf("last: no boot recorded by %s", query.FormatMS(c.w.At))
				}
				var begins sql.NullInt64
				c.db.QueryRow(`SELECT MIN(ts) FROM samples`).Scan(&begins)
				return c.emit(boots, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { query.PrintLastReboot(w, boots, begins.Int64, p.has("fulltimes")) })
			}, nil
		},
	}
}

func nstatTool() *tool {
	return &tool{
		name: "nstat", synopsis: "-a [-z] [-s]  |  [-z] [-s] (with --since)",
		about: "kernel protocol counters (/proc/net/snmp, netstat, snmp6), as iproute2 nstat prints them",
		opts: []opt{
			{short: 'a', long: "ignore", help: "absolute values since boot (required with --at)"},
			{short: 'z', long: "zeros", help: "also the counters that are 0"},
			{short: 's', long: "noupdate", help: "accepted (clifr keeps no history file)"},
		},
		window: true,
		notes: []string{
			"--at with -a: the values at the system sample at or before T. --since without -a: the increase",
			"from the start of the range to its end, with the rate per second (what nstat shows since its",
			"last run). Recorded since 2026-10-21 (schema 4).",
		},
		examples: []string{`clifr --at "02:45" "nstat -zas"`, `clifr --since "02:00" --until "02:05" nstat`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("nstat: unexpected argument %q (counter patterns are not supported)", p.pos[0])
			}
			if !c.w.IsRange() && !p.has("ignore") {
				return nil, errors.New("nstat: with --at add -a (values since boot); for increases give a range with --since")
			}
			if c.w.IsRange() && p.has("ignore") {
				return nil, errors.New("nstat: -a needs --at; over a range nstat shows the increase")
			}
			return func() error {
				rows, from, to, err := query.Nstat(c.db, c.w, p.has("zeros"))
				if err != nil {
					return err
				}
				if c.w.IsRange() {
					c.header("nstat: increase from the system sample at %s to the one at %s", query.FormatMS(from), query.FormatMS(to))
				} else {
					c.header("nstat at %s: since boot, from the system sample at %s", query.FormatMS(c.w.At), query.FormatMS(to))
				}
				return c.emit(rows, func(int) rowMeta {
					return rowMeta{TS: c.w.At, SampleTS: to, From: from, To: to, Sampled: []string{"value", "rate"}}
				},
					func(w io.Writer) { query.PrintNstat(w, rows) })
			}, nil
		},
	}
}
