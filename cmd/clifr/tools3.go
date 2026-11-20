package main

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"clifr/internal/query"
	"clifr/internal/store"
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
		about: "the host name, as clifrd recorded it",
		opts: []opt{
			{short: 's', long: "short", help: "up to the first dot"},
		},
		window: true,
		notes: []string{
			"The name the kernel had at the last system sample at or before T (before schema 9: when the run started).",
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
				h := query.HostnameAt(c.db, c.w.At)
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
			{short: 'p', long: "processor", help: "processor type (the machine, as RHEL's and Debian's coreutils print it; \"unknown\" with uutils, Ubuntu 25.10 and later)"},
			{short: 'i', long: "hardware-platform", help: "hardware platform (likewise)"},
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
			var want []string
			for _, k := range query.UnameKeys {
				if p.has("all") || p.has(k) {
					want = append(want, k)
				}
			}
			if len(want) == 0 {
				want = []string{"kernel-name"}
			}
			return func() error {
				vals := query.UnameAt(c.db, c.w.At)
				if vals["kernel-release"] == "" {
					return fmt.Errorf("uname: not in this recording at %s (recorded since schema 3)", query.FormatMS(c.w.At))
				}
				line := query.UnameLine(vals, want, p.has("all"))
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

func ipTool() *tool {
	return &tool{
		name: "ip", synopsis: "[-s [-s]] [-d] link [show] [[dev] NAME]  |  [-o] [-d] [-4|-6] address [show] [[dev] NAME]  |  [-4|-6] [-d] route [show] [table ID|all]  |  [-4|-6] rule [list]  |  [-s [-s]] [-4|-6] neigh [show] [dev NAME]  |  netns [list]",
		about: "network interfaces, addresses, routes, rules, neighbours and named namespaces, as iproute2 ip prints them",
		opts: []opt{
			{short: 's', long: "stats", help: "link: statistics (twice: also the error counters)"},
			{short: 'd', long: "details", help: "details (each interface type's own parameters are not reconstructed)"},
			{short: 'o', long: "oneline", help: "address: one line per address"},
			{short: '4', help: "IPv4 only (route and rule: the default)"},
			{short: '6', help: "IPv6 only"},
		},
		window: true,
		notes: []string{
			"link: the interfaces at the system sample at or before T; address, route, rule: as they were at",
			"T (clifrd records each change as the kernel announces it, and the kernel's order of routes and",
			"rules about a second after changes). Recorded since",
			"2026-10-21, printed in iproute2 6.19's layout. -d prints the generic attributes and an",
			"interface's type (bridge, bond, vlan, ...) but not that type's parameters.",
			"--since: one report per sample with --samples.",
			"neigh: the neighbour table dumped at the system sample at or before T (since schema 9), its",
			"timers (-s) counted on to T; netns: /run/netns at that sample. Both in the recorded host's",
			"iproute2 layout (Ubuntu 22.04's 5.15 separates fields differently).",
		},
		examples: []string{`clifr --at "02:45" "ip -s -d link"`, `clifr --at "02:45" "ip -s -s neigh"`, `clifr --at "02:45" "ip -o addr"`, `clifr --at "02:45" "ip -d address show dev eth0"`},
		prepare:  prepareIP,
	}
}

func prepareIP(p parsed, c *runCtx) (func() error, error) {
	args := p.pos
	if len(args) == 0 {
		return nil, errors.New(`ip: give an object: link or address`)
	}
	obj := ""
	switch {
	case strings.HasPrefix("neighbour", args[0]) || strings.HasPrefix("neighbor", args[0]):
		obj = "neigh" // first: "n" is neighbour for ip too
	case strings.HasPrefix("netns", args[0]) && len(args[0]) >= 3:
		obj = "netns"
	case strings.HasPrefix("link", args[0]):
		obj = "link"
	case strings.HasPrefix("address", args[0]):
		obj = "address"
	case strings.HasPrefix("route", args[0]):
		obj = "route"
	case strings.HasPrefix("rule", args[0]):
		obj = "rule"
	default:
		return nil, fmt.Errorf("ip: object %q is not supported (link, address, route, rule, neigh, netns)", args[0])
	}
	args = args[1:]
	if len(args) > 0 && (args[0] == "show" || args[0] == "list" || args[0] == "lst" || args[0] == "ls") {
		args = args[1:]
	}
	if obj == "route" || obj == "rule" {
		return prepareIPRouting(p, c, obj, args)
	}
	if obj == "neigh" || obj == "netns" {
		return prepareIPNeigh(p, c, obj, args)
	}
	dev := ""
	switch {
	case len(args) == 2 && args[0] == "dev":
		dev = args[1]
	case len(args) == 1 && args[0] != "dev":
		dev = args[0]
	case len(args) > 0:
		return nil, fmt.Errorf("ip %s: unsupported arguments %q (only [dev] NAME)", obj, strings.Join(args, " "))
	}
	if obj == "link" && (p.has("oneline") || p.has("4") || p.has("6")) {
		return nil, errors.New("ip link: -o, -4 and -6 are supported with address only")
	}
	if obj == "address" && p.has("stats") {
		return nil, errors.New("ip address: -s is supported with link only")
	}
	if c.g.changes {
		return nil, errors.New("ip: --changes is not supported; use --samples")
	}
	if c.w.IsRange() && !c.g.samples {
		return nil, errors.New("ip: a range needs --samples (one report per sample)")
	}
	ao := query.IPAddrOptions{OneLine: p.has("oneline"), Details: p.has("details"), Dev: dev}
	switch {
	case p.has("4") && p.has("6"):
		return nil, errors.New("ip: use -4 or -6, not both")
	case p.has("4"):
		ao.Family = 2
	case p.has("6"):
		ao.Family = 10
	}
	lo := query.IPLinkOptions{Stats: len(p.all["stats"]), Details: p.has("details"), Dev: dev}
	type report struct {
		Links []store.LinkRow `json:"links"`
		Addrs []store.AddrRow `json:"addresses,omitempty"`
	}
	at := func(t int64) ([]report, func(*report) rowMeta, error) {
		links, s, err := query.LinksAt(c.db, t)
		if err != nil {
			return nil, nil, err
		}
		if dev != "" {
			found := false
			for _, l := range links {
				found = found || l.Name == dev
			}
			if !found {
				return nil, nil, fmt.Errorf("ip %s: device %q does not exist at %s", obj, dev, query.FormatMS(t))
			}
		}
		r := report{Links: links}
		if obj == "address" {
			if r.Addrs, err = query.AddrsAt(c.db, t); err != nil {
				return nil, nil, err
			}
		}
		return []report{r}, func(*report) rowMeta { return rowMeta{TS: t, SampleTS: s} }, nil
	}
	print := func(w io.Writer, reps []report) {
		for _, r := range reps {
			if obj == "link" {
				query.PrintIPLink(w, r.Links, lo)
			} else {
				query.PrintIPAddr(w, r.Links, r.Addrs, ao)
			}
		}
	}
	return func() error {
		v := view[report]{name: "ip " + obj, at: at, key: func(*report) string { return obj },
			same: func(a, b *report) bool { return true }, print: print}
		if ok, err := rangeView(c, v); ok {
			return err
		}
		reps, meta, err := at(c.w.At)
		if err != nil {
			return err
		}
		return c.emit(reps, func(i int) rowMeta { return meta(&reps[i]) }, func(w io.Writer) { print(w, reps) })
	}, nil
}

// prepareIPRouting: ip [-4|-6] [-d] route [show] [table ID|all] and ip
// [-4|-6] rule [list].
func prepareIPRouting(p parsed, c *runCtx, obj string, args []string) (func() error, error) {
	if p.has("stats") || p.has("oneline") {
		return nil, fmt.Errorf("ip %s: -s and -o are not supported", obj)
	}
	o := query.IPRouteOptions{Table: 254, Details: p.has("details")}
	switch {
	case p.has("4") && p.has("6"):
		return nil, errors.New("ip: use -4 or -6, not both")
	case p.has("6"):
		o.Family = 10
	case p.has("4"):
		o.Family = 2
	}
	switch {
	case obj == "route" && len(args) == 2 && args[0] == "table":
		switch args[1] {
		case "all":
			o.Table = 0
		case "main":
			o.Table = 254
		case "local":
			o.Table = 255
		case "default":
			o.Table = 253
		default:
			n, err := strconv.Atoi(args[1])
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("ip route: table %q: give all, main, local, default or a number", args[1])
			}
			o.Table = n
		}
	case len(args) > 0:
		return nil, fmt.Errorf("ip %s: unsupported arguments %q", obj, strings.Join(args, " "))
	}
	// ip's default family is IPv4, except for routes of all tables, which
	// lists both.
	if o.Family == 0 && (obj == "rule" || o.Table != 0) {
		o.Family = 2
	}
	if c.g.changes {
		return nil, errors.New("ip: --changes is not supported; use --samples")
	}
	if c.w.IsRange() && !c.g.samples {
		return nil, errors.New("ip: a range needs --samples (one report per sample)")
	}
	type report struct {
		TS    int64              `json:"ts_ms"`
		Rows  []store.RoutingRow `json:"-"`
		names map[int]string
		Lines []string `json:"lines"`
	}
	at := func(t int64) ([]report, func(*report) rowMeta, error) {
		rows, err := query.RoutingAt(c.db, t, obj)
		if err != nil {
			return nil, nil, err
		}
		names := map[int]string{}
		if links, _, err := query.LinksAt(c.db, t); err == nil {
			for _, l := range links {
				names[l.Index] = l.Name
			}
		}
		r := report{TS: t, Rows: rows, names: names}
		var sb strings.Builder
		if obj == "route" {
			query.PrintIPRoute(&sb, rows, o, func(i int) string {
				if n, ok := names[i]; ok {
					return n
				}
				return fmt.Sprintf("if%d", i)
			}, t)
		} else {
			query.PrintIPRule(&sb, rows, o.Family, o.Details)
		}
		if s := strings.TrimSuffix(sb.String(), "\n"); s != "" {
			r.Lines = strings.Split(s, "\n")
		}
		return []report{r}, func(*report) rowMeta { return rowMeta{TS: t} }, nil
	}
	print := func(w io.Writer, reps []report) {
		for _, r := range reps {
			for _, l := range r.Lines {
				fmt.Fprintln(w, l)
			}
		}
	}
	return func() error {
		v := view[report]{name: "ip " + obj, at: at, key: func(*report) string { return obj },
			same: func(a, b *report) bool { return true }, print: print}
		if ok, err := rangeView(c, v); ok {
			return err
		}
		reps, meta, err := at(c.w.At)
		if err != nil {
			return err
		}
		return c.emit(reps, func(i int) rowMeta { return meta(&reps[i]) }, func(w io.Writer) { print(w, reps) })
	}, nil
}

func dmesgTool() *tool {
	return &tool{
		name: "dmesg", synopsis: "[-T] [-t] [-x]",
		about: "the kernel log, as util-linux dmesg prints it",
		opts: []opt{
			{short: 'T', long: "ctime", help: "human-readable times (computed as the host's dmesg does, from the boot time)"},
			{short: 't', long: "notime", help: "no times"},
			{short: 'x', long: "decode", help: "facility and level as names"},
		},
		window: true,
		notes: []string{
			"--at T: the records of the boot running at T still in the kernel's buffer, as dmesg would have",
			"printed them then. A range: the records written in it (all boots). clifrd reads /dev/kmsg as the",
			"kernel writes it (needs CAP_SYSLOG) and masks the --redact patterns in it; recorded since schema 6.",
			"The buffer's oldest record is recorded at most 10 s after records arrive, so for a few seconds",
			"after a burst the oldest lines may still be listed although the kernel had dropped them.",
		},
		examples: []string{`clifr --at "02:45" "dmesg -T"`, `clifr --since "02:00" --until "03:00" dmesg`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("dmesg: unexpected argument %q", p.pos[0])
			}
			o := query.DmesgOptions{Ctime: p.has("ctime"), NoTime: p.has("notime"), Decode: p.has("decode"),
				ASCII: !query.LocaleUTF8()}
			return func() error {
				var recs []query.Kmsg
				var err error
				ts := c.w.At
				if c.w.IsRange() {
					recs, err = query.KmsgBetween(c.db, c.w.From, c.w.To)
					ts = c.w.To
				} else {
					recs, err = query.KmsgAt(c.db, c.w.At)
				}
				if err != nil {
					return err
				}
				st := query.StyleAt(c.db, ts)
				return c.emit(recs, func(i int) rowMeta { return rowMeta{TS: recs[i].TS} },
					func(w io.Writer) { query.PrintDmesg(w, recs, o, st) })
			}, nil
		},
	}
}

func systemctlTool() *tool {
	return &tool{
		name: "systemctl", synopsis: "[list-units] [-a] [--failed] [--state=STATE,...] [-t TYPE,...] [--plain] [--no-legend] [PATTERN...]",
		about: "systemd's loaded units, as systemctl list-units prints them",
		opts: []opt{
			{short: 'a', long: "all", help: "also inactive units and units following others"},
			{long: "failed", help: "failed units only (--state=failed)"},
			{long: "state", arg: "STATE", help: "units in these load, active or sub states (comma-separated)"},
			{short: 't', long: "type", arg: "TYPE", help: "units of these types (comma-separated: service, socket, ...)"},
			{long: "plain", help: "no status column"},
			{long: "no-legend", help: "no header and legend"},
			{long: "no-pager", help: "accepted (clifr pages with --pager)"},
			{short: 'l', long: "full", help: "accepted (nothing is shortened)"},
		},
		window: true,
		notes: []string{
			"The units at T: clifrd lists them over systemd's private socket (or the system bus) at the start,",
			"hourly and a fraction of a second after systemd signals a change (at most every second); recorded",
			"since schema 7. Printed as the recorded host's systemd prints them into a pipe (RHEL 8's 239, RHEL",
			"9's 252 and Ubuntu 22.04's 249, or 258 and later); with * and -> for its circle and arrow when clifr's",
			"locale is not UTF-8, as systemctl decides it.",
		},
		examples: []string{`clifr --at "02:45" "systemctl list-units --failed"`, `clifr --at "02:45" "systemctl -a -t service"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			args := p.pos
			if len(args) > 0 && args[0] == "list-units" {
				args = args[1:]
			} else if len(args) > 0 && !strings.ContainsAny(args[0], "*?[.") {
				return nil, fmt.Errorf("systemctl: only list-units is supported, not %q", args[0])
			}
			split := func(k string) []string {
				var out []string
				for _, v := range p.all[k] {
					out = append(out, strings.Split(v, ",")...)
				}
				return out
			}
			o := query.ListUnitsOptions{All: p.has("all"), Plain: p.has("plain"), NoLegend: p.has("no-legend"),
				States: split("state"), Types: split("type"), Pattern: args, ASCII: !query.LocaleUTF8()}
			if p.has("failed") {
				o.States = append(o.States, "failed")
			}
			if c.w.IsRange() {
				return nil, errors.New("systemctl: needs --at")
			}
			return func() error {
				units, err := query.UnitsAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				st := query.StyleAt(c.db, c.w.At)
				return c.emit(query.FilterUnits(units, o), func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { query.PrintListUnits(w, units, o, st) })
			}, nil
		},
	}
}

func cglsTool() *tool {
	return &tool{
		name: "systemd-cgls", synopsis: "[-l] [-k] [--no-pager]",
		about: "processes by control group, as systemd-cgls prints the tree",
		opts: []opt{
			{short: 'l', long: "full", help: "do not shorten command lines"},
			{short: 'k', help: "include kernel threads"},
			{long: "no-pager", help: "accepted (clifr pages with --pager)"},
		},
		window: true,
		notes: []string{
			"The processes of the sample at or before T in their systemd cgroup (name=systemd's on cgroup v1),",
			"read when clifrd first sampled them and at every fd walk: a process moved to another cgroup in",
			"between shows where it was. Processes only seen through exec/exit events are not listed. Siblings",
			"in cgroupfs order (the kernel's name hash, which systemd-cgls shows unsorted); delegated cgroups",
			"marked with an ellipsis (their trusted.delegate or user.delegate attribute, recorded). Without -l,",
			"lines fit $COLUMNS (80 when unset, as systemd-cgls into a pipe). Recorded since 2026-10-22.",
		},
		examples: []string{`clifr --at "02:45" "systemd-cgls"`, `clifr --at "02:45" "systemd-cgls -l"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("systemd-cgls: only the whole tree is supported, not %q", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("systemd-cgls: needs --at")
			}
			o := query.CglsOptions{Full: p.has("full"), Kernel: p.has("k"), ASCII: !query.LocaleUTF8(), Columns: 80}
			if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
				o.Columns = n
			}
			return func() error {
				procs, info, s, err := query.CglsAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				o.Style = query.StyleAt(c.db, s).SystemdCgls
				c.header("systemd-cgls at %s, from the sample at %s", query.FormatMS(c.w.At), query.FormatMS(s))
				if o.Style == "252" && query.TrustedDerived(info) {
					c.header("trusted.* attributes derived from their user.* copies (clifrd ran without CAP_SYS_ADMIN, which reading them needs)")
				}
				return c.emit(procs, func(int) rowMeta { return rowMeta{TS: c.w.At, SampleTS: s} },
					func(w io.Writer) { query.PrintCgls(w, procs, info, o) })
			}, nil
		},
	}
}

func containersTool() *tool {
	return &tool{
		name: "containers", synopsis: "[-q] [--no-trunc]",
		about: "clifr only: containers found from their processes' cgroups (docker, podman, containerd, CRI-O, LXC/LXD/Incus)",
		opts: []opt{
			{short: 'q', help: "container ids only"},
			{long: "no-trunc", help: "the whole 64-character id"},
		},
		window: true,
		notes: []string{
			"A container is known by the cgroup of its processes (docker-ID.scope, libpod-ID.scope,",
			"cri-containerd-ID.scope, crio-ID.scope, or the cgroupfs driver's /docker/ID): its id and runtime",
			"only. LXC, LXD and Incus: lxc.payload.NAME (or LXC 3's /lxc/NAME), the name as the id, runtime",
			"lxc (lxc.monitor.NAME is LXC's monitor process, not the container). NAME (since 2026-11-09):",
			"Docker's (its API's container list), Podman's (its storage's list), a pod's container as",
			"NAMESPACE/POD/CONTAINER (the kubelet's /var/log/containers links), - when not recorded; --json",
			"also has image, pod, namespace, compose_project. Ports and states are not recorded; a container",
			"without processes (created, exited) is not seen. PID and COMMAND: its earliest process.",
			"--at: the containers with processes at the sample at or before T, STARTED = their first",
			"process's start. --since: every container with processes in the range, with first and last",
			"seen (running: processes still alive at the end). Processes only seen through exec/exit events",
			"have no cgroup and do not count. Recorded since 2026-10-22. --json: netns, its network",
			"namespace (0: the host's); ss -N ID lists its sockets.",
		},
		examples: []string{`clifr --at "02:45" containers`, `clifr --since yesterday --until today "containers --no-trunc"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("containers: unexpected argument %q", p.pos[0])
			}
			return func() error {
				var cs []query.Container
				if c.w.IsRange() {
					var err error
					if cs, err = query.ContainersBetween(c.db, c.w.From, c.w.To); err != nil {
						return err
					}
					c.header("containers with processes between %s and %s", query.FormatMS(c.w.From), query.FormatMS(c.w.To))
				} else {
					var s int64
					var err error
					if cs, s, err = query.ContainersAt(c.db, c.w.At); err != nil {
						return err
					}
					c.header("containers at %s, from the processes of the sample at %s", query.FormatMS(c.w.At), query.FormatMS(s))
				}
				return c.emit(cs, func(int) rowMeta { return rowMeta{From: c.w.From, To: c.w.To, TS: c.w.At} },
					func(w io.Writer) {
						if p.has("q") {
							for _, x := range cs {
								id := x.ID
								if !p.has("no-trunc") && x.Runtime != "lxc" { // an LXC id is its name
									id = id[:min(12, len(id))]
								}
								fmt.Fprintln(w, id)
							}
							return
						}
						query.PrintContainers(w, cs, c.w.IsRange(), p.has("no-trunc"))
					})
			}, nil
		},
	}
}

func swaponTool() *tool {
	return &tool{
		name: "swapon", synopsis: "[--show[=COLUMNS]] [--bytes] [--noheadings] [--raw] | --summary",
		about: "the swap areas, as util-linux swapon --show (the default) or --summary prints them",
		opts: []opt{
			{long: "show", arg: "COLUMNS", optional: true, help: "a table (the default); columns NAME, TYPE, SIZE, USED, PRIO"},
			{short: 's', long: "summary", help: "/proc/swaps as it was"},
			{long: "bytes", help: "sizes in bytes"},
			{long: "noheadings", help: "no header line"},
			{long: "raw", help: "no column alignment"},
			{short: 'v', long: "verbose", help: "accepted (prints nothing more)"},
		},
		window: true,
		notes: []string{
			"/proc/swaps at the last system sample at or before T (recorded since schema 9). UUID and LABEL",
			"are not recorded. --summary in the recorded host's util-linux layout (RHEL 8's 2.32 has its",
			"own columns). Enabling or disabling swap is not supported.",
		},
		examples: []string{`clifr --at "02:45" swapon`, `clifr --at "02:45" "swapon --summary"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("swapon: unexpected argument %q (enabling swap is not supported)", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("swapon: needs --at")
			}
			cols := query.SwapColumns
			if v := p.set["show"]; v != "" {
				cols = nil
				for _, col := range strings.Split(strings.ToUpper(v), ",") {
					if !slices.Contains(query.SwapColumns, col) {
						return nil, fmt.Errorf("swapon: unknown column %q (recorded: %s)", col, strings.Join(query.SwapColumns, ", "))
					}
					cols = append(cols, col)
				}
			}
			return func() error {
				swaps, raw, err := query.SwapsAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				return c.emit(swaps, func(int) rowMeta { return rowMeta{TS: c.w.At} }, func(w io.Writer) {
					if p.has("summary") {
						query.PrintSwapSummary(w, swaps, raw, query.StyleAt(c.db, c.w.At).SwapSummaryOwn)
						return
					}
					query.PrintSwapon(w, swaps, cols, p.has("bytes"), p.has("noheadings"), p.has("raw"))
				})
			}, nil
		},
	}
}

func lsmodTool() *tool {
	return &tool{
		name: "lsmod", about: "the loaded kernel modules, as kmod's lsmod prints them",
		window: true,
		notes: []string{
			"/proc/modules at the last system sample at or before T (recorded since schema 9); the users of",
			"each module in the order sysfs lists them, as lsmod reads them.",
		},
		examples: []string{`clifr --at "02:45" lsmod`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("lsmod: unexpected argument %q", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("lsmod: needs --at")
			}
			return func() error {
				mods, err := query.ModulesAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				return c.emit(mods, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { query.PrintLsmod(w, mods) })
			}, nil
		},
	}
}

func lsblkTool() *tool {
	return &tool{
		name: "lsblk", synopsis: "[-f] [-b] [-n]",
		about: "the block devices as a tree, as util-linux lsblk prints them",
		opts: []opt{
			{short: 'f', long: "fs", help: "file systems: type, version, label, UUID, available space, use"},
			{short: 'b', long: "bytes", help: "sizes in bytes"},
			{short: 'n', long: "noheadings", help: "no header line"},
		},
		window: true,
		notes: []string{
			"The devices of /sys/block and their partitions as clifrd last read them at or before T (when the",
			"kernel or udev reported a change, else every minute; recorded since schema 9), with file systems",
			"from udev's database; mount points from the mount table at T, FSAVAIL and FSUSE% from the last",
			"statfs sample of the mount shown. Printed as the recorded host's util-linux does (RHEL 8's 2.32:",
			"one MOUNTPOINT, -f without FSVER, FSAVAIL and FSUSE%), with ASCII tree lines when clifr's",
			"locale is not UTF-8.",
		},
		examples: []string{`clifr --at "02:45" lsblk`, `clifr --at "02:45" "lsblk -f"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("lsblk: unexpected argument %q (devices cannot be selected yet)", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("lsblk: needs --at")
			}
			return func() error {
				roots, err := query.LsblkAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				o := query.LsblkOptions{FS: p.has("fs"), Bytes: p.has("bytes"), NoHeadings: p.has("noheadings"),
					V232: query.StyleAt(c.db, c.w.At).LsblkV232, ASCII: !query.LocaleUTF8()}
				return c.emit(roots, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { query.PrintLsblk(w, roots, o) })
			}, nil
		},
	}
}

// prepareIPNeigh: ip [-s [-s]] [-4|-6] neigh [show] [dev NAME] and ip
// netns [list].
func prepareIPNeigh(p parsed, c *runCtx, obj string, args []string) (func() error, error) {
	o := query.IPNeighOptions{Stats: p.has("stats")}
	switch {
	case obj == "netns" && len(args) > 0:
		return nil, fmt.Errorf("ip netns: unsupported arguments %q (only list)", strings.Join(args, " "))
	case len(args) == 2 && args[0] == "dev":
		o.Dev = args[1]
	case len(args) > 0:
		return nil, fmt.Errorf("ip neigh: unsupported arguments %q (only dev NAME)", strings.Join(args, " "))
	}
	switch {
	case p.has("4") && p.has("6"):
		return nil, errors.New("ip: use -4 or -6, not both")
	case p.has("4"):
		o.Family = 2
	case p.has("6"):
		o.Family = 10
	}
	if p.has("oneline") || p.has("details") {
		return nil, fmt.Errorf("ip %s: -o and -d are not supported", obj)
	}
	if c.w.IsRange() {
		return nil, fmt.Errorf("ip %s: needs --at", obj)
	}
	return func() error {
		t := c.w.At
		if obj == "netns" {
			ns, err := query.NetnsAt(c.db, t)
			if err != nil {
				return err
			}
			return c.emit(ns, func(int) rowMeta { return rowMeta{TS: t} }, func(w io.Writer) { query.PrintIPNetns(w, ns) })
		}
		ns, ok, err := query.NeighsAt(c.db, t)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("ip neigh: not recorded at %s (recorded since schema 9)", query.FormatMS(t))
		}
		links, _, err := query.LinksAt(c.db, t)
		if err != nil {
			return err
		}
		o.Old = query.StyleAt(c.db, t).IPNeighOld
		return c.emit(ns, func(int) rowMeta { return rowMeta{TS: t} }, func(w io.Writer) { query.PrintIPNeigh(w, ns, links, o, t) })
	}, nil
}

func lslocksTool() *tool {
	return &tool{
		name: "lslocks", synopsis: "[-b] [-n]",
		about: "the file locks, as util-linux lslocks prints them",
		opts: []opt{
			{short: 'b', long: "bytes", help: "sizes in bytes"},
			{short: 'n', long: "noheadings", help: "no header line"},
		},
		window: true,
		notes: []string{
			"/proc/locks at the last system sample at or before T (recorded since schema 9), with the path and",
			"size of each locked file as clifrd found them through the holder's fds, and the holder of an OFD",
			"lock from fdinfo (shown by util-linux 2.41; older versions print -1 \"(undefined)\"). Commands",
			"from the process sample at or before T.",
		},
		examples: []string{`clifr --at "02:45" lslocks`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("lslocks: unexpected argument %q", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("lslocks: needs --at")
			}
			return func() error {
				st := query.StyleAt(c.db, c.w.At)
				locks, err := query.LocksAt(c.db, c.w.At, st.LslocksOld)
				if err != nil {
					return err
				}
				return c.emit(locks, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) {
						query.PrintLslocks(w, locks, p.has("bytes"), p.has("noheadings"), st.LslocksZeroSize)
					})
			}, nil
		},
	}
}

func ipcsTool() *tool {
	return &tool{
		name: "ipcs", synopsis: "[-q] [-m] [-s] [-a] [-u]",
		about: "System V message queues, shared memory and semaphores, as util-linux ipcs prints them",
		opts: []opt{
			{short: 'q', long: "queues", help: "message queues"},
			{short: 'm', long: "shmems", help: "shared memory segments"},
			{short: 's', long: "semaphores", help: "semaphore arrays"},
			{short: 'a', long: "all", help: "all three (the default)"},
			{short: 'u', long: "summary", help: "status summary"},
		},
		window: true,
		notes: []string{
			"/proc/sysvipc at the last system sample at or before T (recorded since schema 9). Owners are",
			"named by the users of the machine running clifr.",
		},
		examples: []string{`clifr --at "02:45" ipcs`, `clifr --at "02:45" "ipcs -m -u"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("ipcs: unexpected argument %q", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("ipcs: needs --at")
			}
			o := query.IPCSOptions{Msg: p.has("queues"), Shm: p.has("shmems"), Sem: p.has("semaphores"), Summary: p.has("summary")}
			return func() error {
				ipc, err := query.IPCAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				return c.emit([]*query.IPC{ipc}, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { query.PrintIPCS(w, ipc, o) })
			}, nil
		},
	}
}

func sysctlTool() *tool {
	return &tool{
		name: "sysctl", synopsis: "-a | NAME... [-n] [-N] [-e] [-r REGEX]",
		about: "kernel parameters, as procps sysctl prints them",
		opts: []opt{
			{short: 'a', long: "all", help: "every parameter"},
			{short: 'A', help: "the same as -a"},
			{short: 'X', help: "the same as -a"},
			{short: 'n', long: "values", help: "values only"},
			{short: 'N', long: "names", help: "names only"},
			{short: 'e', long: "ignore", help: "no error for unknown names"},
			{short: 'r', long: "pattern", arg: "REGEX", help: "only names matching REGEX"},
		},
		window: true,
		notes: []string{
			"/proc/sys as clifrd last read it at or before T (every minute; recorded since schema 9), walked",
			"and printed as sysctl -a does. Counters that change all the time (fs.dentry-state,",
			"kernel.random.*) are as of that read. Setting values is not supported.",
		},
		examples: []string{`clifr --at "02:45" "sysctl -a"`, `clifr --at "02:45" "sysctl net.ipv4.ip_forward vm.swappiness"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			o := query.SysctlOptions{Values: p.has("values"), Names: p.has("names"), IgnoreUnknown: p.has("ignore")}
			all := p.has("all") || p.has("A") || p.has("X")
			for _, k := range p.pos {
				if strings.Contains(k, "=") {
					return nil, fmt.Errorf("sysctl: %q: setting values is not supported", k)
				}
			}
			switch {
			case all && len(p.pos) > 0:
				return nil, errors.New("sysctl: give -a or names, not both")
			case !all && len(p.pos) == 0:
				return nil, errors.New("sysctl: give -a or the names of parameters")
			case !all:
				o.Keys = p.pos
			}
			if v, ok := p.set["pattern"]; ok {
				re, err := regexp.Compile(v)
				if err != nil {
					return nil, fmt.Errorf("sysctl: -r: %v", err)
				}
				o.Pattern = re
			}
			if c.w.IsRange() {
				return nil, errors.New("sysctl: needs --at")
			}
			return func() error {
				lines, err := query.SysctlAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				sel, err := query.SelectSysctl(lines, o)
				if err != nil && len(sel) == 0 {
					return err
				}
				perr := c.emit(sel, func(int) rowMeta { return rowMeta{TS: c.w.At} }, func(w io.Writer) { query.PrintSysctl(w, sel, o) })
				if err != nil {
					return err
				}
				return perr
			}, nil
		},
	}
}

func slabtopTool() *tool {
	return &tool{
		name: "slabtop", synopsis: "-o",
		about:  "the kernel's slab caches, as procps slabtop -o prints them",
		opts:   []opt{{short: 'o', long: "once", help: "print once (the only mode for recorded data)"}},
		window: true,
		notes: []string{
			"/proc/slabinfo as clifrd last read it at or before T (every minute; recorded since schema 9),",
			"sorted by number of objects as the recorded host's procps does (3.3 and 4.0 order equal caches",
			"differently).",
		},
		examples: []string{`clifr --at "02:45" "slabtop -o"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("slabtop: unexpected argument %q", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("slabtop: needs --at")
			}
			return func() error {
				slabs, _, err := query.SlabsAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				v3 := query.StyleAt(c.db, c.w.At).Slabtop3
				return c.emit(slabs, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { query.PrintSlabtop(w, slabs, v3) })
			}, nil
		},
	}
}

func numastatTool() *tool {
	return &tool{
		name: "numastat", synopsis: "[-m] [-n] [-c] [-z]",
		about: "per-node NUMA statistics and memory, as numactl's numastat prints them",
		opts: []opt{
			{short: 'm', long: "meminfo", help: "per-node memory (meminfo) in MB"},
			{short: 'n', long: "numastat", help: "the numastat counters in MB"},
			{short: 'c', long: "compress", help: "narrow columns, no decimals"},
			{short: 'z', long: "zero-filter", help: "leave out rows and columns that are all zero"},
		},
		window: true,
		notes: []string{
			"/sys/devices/system/node as clifrd last read it at or before T (every minute; recorded since",
			"schema 9), in numastat 2.0.19's layout; without options the counters as numastat prints them",
			"for compatibility. Per-process statistics (-p) are not recorded.",
		},
		examples: []string{`clifr --at "02:45" numastat`, `clifr --at "02:45" "numastat -m"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("numastat: unexpected argument %q (processes are not supported)", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("numastat: needs --at")
			}
			o := query.NumastatOptions{Meminfo: p.has("meminfo"), Numastat: p.has("numastat"), Compress: p.has("compress"),
				NoZero: p.has("zero-filter")}
			if (o.Compress || o.NoZero) && !o.Meminfo && !o.Numastat {
				o.Numastat = true // any option leaves the compatibility output
			}
			return func() error {
				nodes, err := query.NUMAAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				page := query.PageBytes(c.db)
				o.Old = query.StyleAt(c.db, c.w.At).NumastatOld
				return c.emit(nodes, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { query.PrintNumastat(w, nodes, o, page) })
			}, nil
		},
	}
}

func conntrackTool() *tool {
	return &tool{
		name: "conntrack", synopsis: "-S | -C",
		about: "connection tracking statistics, as conntrack-tools' conntrack prints them",
		opts: []opt{
			{short: 'S', long: "stats", help: "per-CPU counters"},
			{short: 'C', long: "count", help: "number of tracked connections"},
		},
		window: true,
		notes: []string{
			"-S: the per-CPU counters clifrd asked ctnetlink for at or before T (every minute, only while",
			"nf_conntrack_netlink is loaded: clifrd does not load kernel modules; recorded since schema 9).",
			"-C: net.netfilter.nf_conntrack_count from the sysctl read. The table itself (-L) is not recorded.",
		},
		examples: []string{`clifr --at "02:45" "conntrack -S"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 || p.has("stats") == p.has("count") {
				return nil, errors.New("conntrack: only -S or -C (the connection table is not recorded)")
			}
			if c.w.IsRange() {
				return nil, errors.New("conntrack: needs --at")
			}
			return func() error {
				if p.has("count") {
					lines, err := query.SysctlAt(c.db, c.w.At)
					if err != nil {
						return err
					}
					for _, l := range lines {
						if l.Name == "net.netfilter.nf_conntrack_count" {
							return c.emit([]query.SysctlLine{l}, func(int) rowMeta { return rowMeta{TS: c.w.At} },
								func(w io.Writer) { fmt.Fprintln(w, l.Value) })
						}
					}
					return errors.New("conntrack: connection tracking was not loaded")
				}
				cpus, err := query.ConntrackAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				if len(cpus) == 0 {
					return errors.New("conntrack: nf_conntrack_netlink was not loaded (clifrd does not load it)")
				}
				old := query.StyleAt(c.db, c.w.At).ConntrackOld
				return c.emit(cpus, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { query.PrintConntrackStats(w, cpus, old) })
			}, nil
		},
	}
}

func nfsstatTool() *tool {
	return &tool{
		name: "nfsstat", synopsis: "[-s] [-c] [-n] [-r] [-o all|net|rpc|nfs|rc|fh|io|ra] [-2|-3|-4] [-l] [-v] | -m",
		about: "NFS client and server statistics, as nfs-utils' nfsstat prints them",
		opts: []opt{
			{short: 's', long: "server", help: "server statistics only"},
			{short: 'c', long: "client", help: "client statistics only"},
			{short: 'n', long: "nfs", help: "NFS calls only"},
			{short: 'r', long: "rpc", help: "RPC statistics only"},
			{short: 'o', arg: "FACILITY", help: "all, net, rpc, nfs, rc, fh, io or ra"},
			{short: '2', help: "NFS version 2"}, {short: '3', help: "NFS version 3"}, {short: '4', help: "NFS version 4"},
			{short: 'l', long: "list", help: "list form"},
			{short: 'v', long: "verbose", help: "everything (-o all)"},
			{short: 'm', long: "mounts", help: "the NFS mounts and their options"},
		},
		window: true,
		notes: []string{
			"/proc/net/rpc/nfs and nfsd as clifrd last read them at or before T (every minute; recorded since",
			"schema 9); -m: the mount table at T.",
		},
		examples: []string{`clifr --at "02:45" nfsstat`, `clifr --at "02:45" "nfsstat -o all"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("nfsstat: unexpected argument %q", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("nfsstat: needs --at")
			}
			o := query.NFSStatOptions{Server: p.has("server"), Client: p.has("client"), Calls: p.has("nfs"), RPC: p.has("rpc"),
				V2: p.has("2"), V3: p.has("3"), V4: p.has("4"), List: p.has("list")}
			for _, f := range p.all["o"] {
				switch f {
				case "all":
					o.Calls, o.RPC, o.Net, o.RC, o.FH, o.IO, o.RA = true, true, true, true, true, true, true
				case "nfs":
					o.Calls = true
				case "rpc":
					o.RPC = true
				case "net":
					o.Net = true
				case "rc":
					o.RC = true
				case "fh":
					o.FH = true
				case "io":
					o.IO = true
				case "ra":
					o.RA = true
				default:
					return nil, fmt.Errorf("nfsstat: unknown category: %s", f)
				}
			}
			if p.has("verbose") {
				o.Server, o.Client = true, true
				o.Calls, o.RPC, o.Net, o.RC, o.FH, o.IO, o.RA = true, true, true, true, true, true, true
			}
			return func() error {
				if p.has("mounts") {
					mounts, err := query.MountsAt(c.db, c.w.At)
					if err != nil {
						return err
					}
					return c.emit(mounts, func(int) rowMeta { return rowMeta{TS: c.w.At} },
						func(w io.Writer) { query.PrintNFSMounts(w, mounts) })
				}
				st, err := query.NFSStatsAt(c.db, c.w.At)
				if err != nil {
					return err
				}
				var perr error
				err = c.emit([]*query.NFSStats{st}, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { perr = query.PrintNFSStat(w, st, o) })
				if perr != nil {
					return perr
				}
				return err
			}, nil
		},
	}
}

func mountstatsTool() *tool {
	return &tool{
		name: "mountstats", synopsis: "[-n|-r|-x|-R] [MOUNTPOINT...]",
		about: "per-mount NFS statistics, as nfs-utils' mountstats prints them",
		opts: []opt{
			{short: 'n', long: "nfs", help: "NFS statistics only"},
			{short: 'r', long: "rpc", help: "RPC statistics only"},
			{short: 'x', long: "xprt", help: "transport statistics only"},
			{short: 'R', long: "raw", help: "as /proc/self/mountstats prints it"},
		},
		window: true,
		notes: []string{
			"The NFS mounts of the host's mountstats as clifrd last read it at or before T (every minute; init's",
			"mount namespace; recorded since schema 9), in the recorded host's nfs-utils layout (RHEL 8's 2.3.3",
			"has no mount age and no error counts).",
		},
		examples: []string{`clifr --at "02:45" mountstats`, `clifr --at "02:45" "mountstats -r /data"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if c.w.IsRange() {
				return nil, errors.New("mountstats: needs --at")
			}
			n := 0
			for _, k := range []string{"nfs", "rpc", "xprt", "raw"} {
				if p.has(k) {
					n++
				}
			}
			if n > 1 {
				return nil, errors.New("mountstats: -n, -r, -x and -R exclude each other")
			}
			return func() error {
				st := query.StyleAt(c.db, c.w.At)
				mounts, err := query.MountstatsAt(c.db, c.w.At, !st.Mountstats233)
				if err != nil {
					return err
				}
				o := query.MountstatsOptions{NFS: p.has("nfs"), RPC: p.has("rpc"), Xprt: p.has("xprt"), Raw: p.has("raw"),
					MountPoints: p.pos, V233: st.Mountstats233}
				return c.emit(mounts, func(int) rowMeta { return rowMeta{TS: c.w.At} },
					func(w io.Writer) { query.PrintMountstats(w, mounts, o) })
			}, nil
		},
	}
}
