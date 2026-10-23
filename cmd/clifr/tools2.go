package main

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"clifr/internal/query"
)

var bsdPS = regexp.MustCompile(`^[auxwflZ]+$`)

// splitList splits ps/lsof lists: "1,2 3" and repeated options.
func splitList(vals []string) []string {
	var out []string
	for _, v := range vals {
		out = append(out, strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' })...)
	}
	return out
}

func psTool() *tool {
	return &tool{
		name: "ps", diff: true, synopsis: "aux[f|Z] | alx | -e|-p PIDS|-u USERS|-C NAMES [-f | -o FORMAT]",
		about: "processes and their CPU, memory, state and command line",
		opts: []opt{
			{short: 'e', help: "every process"},
			{short: 'A', help: "every process (the same as -e)"},
			{short: 'p', arg: "PIDS", help: "these processes (comma separated, or repeat -p)"},
			{short: 'u', arg: "USERS", help: "processes of these users (names or numbers)"},
			{short: 'C', arg: "NAMES", help: "processes with these command names"},
			{short: 'f', help: "full format: UID PID PPID C STIME TTY TIME CMD"},
			{short: 'o', arg: "FORMAT", help: "these columns: pid ppid uid user comm args cmd rss vsz %cpu %mem c ni nlwp s stat lstart start stime etime etimes time tty f pri priority rtprio cls psr minflt majflt wchan label (KEY:WIDTH, KEY=HEADING)"},
		},
		window: true,
		notes: []string{
			"BSD forms: aux (w, ww accepted: lines are never cut; f: the process tree in COMMAND, as procps",
			"draws it; Z: the security label first), alx (F UID PID PPID PRI NI VSZ RSS WCHAN STAT TTY TIME",
			"COMMAND). Without -f or -o: PID TTY TIME CMD.",
			"WCHAN: re-read when the process used CPU since the sample before, so a process that slept again",
			"without using a whole clock tick shows where it waited before. Label and cgroup: read when the",
			"process is first sampled, at an exec and every fd walk. Recordings before 2026-10-22 have none",
			"of F, WCHAN, LABEL, RTPRIO, CLS, PSR, MINFLT, MAJFLT (\"-\"); PRI from the nice value.",
			"--at: the processes alive at T with their values from the sample at or before T (sampled);",
			"processes only seen through exec/exit events show \"-\" for sampled values.",
			"--since: every process seen in the range, identical commands collapsed, with first/last",
			"seen and peaks (ps aux or ps -e).",
		},
		examples: []string{`clifr --at "02:45" "ps aux"`, `clifr --at "02:45" "ps -ef"`,
			`clifr --at "02:45" "ps -u postgres -o pid,rss,etime,args"`, `clifr --since yesterday --until today "ps aux"`},
		prepare: preparePS,
	}
}

func preparePS(p parsed, c *runCtx) (func() error, error) {
	dash := len(p.set) > 0
	if len(p.pos) > 0 {
		bsd := p.pos[0]
		has := func(l string) bool { return strings.Contains(bsd, l) }
		if dash || len(p.pos) != 1 || !bsdPS.MatchString(bsd) || !has("a") || !has("x") || has("u") == has("l") ||
			has("l") && (has("f") || has("Z")) || has("f") && has("Z") {
			return nil, errors.New(`ps: the BSD forms supported are "ps aux" (with f for the tree, or Z for the security label) and "ps alx"; other forms use -e, -p, -u or -C (see: clifr help ps)`)
		}
		var f query.PSFormat
		switch {
		case has("l"):
			f = query.PSLong
		case has("Z"):
			f = query.PSAuxLabel
		}
		forest := has("f")
		if (forest || f != nil) && c.w.IsRange() && !c.g.samples && !c.g.changes {
			return nil, fmt.Errorf("ps: %s needs --at, --samples or --changes, not the range summary", bsd)
		}
		return func() error { return runPS(c, nil, f, forest) }, nil
	}
	all := p.has("e") || p.has("A")
	pids, users, names := splitList(p.all["p"]), splitList(p.all["u"]), splitList(p.all["C"])
	if !all && len(pids) == 0 && len(users) == 0 && len(names) == 0 {
		return nil, errors.New("ps: add -e, -p, -u or -C: without them ps lists the processes of the current terminal")
	}
	f := query.PSDefault
	switch {
	case p.has("f") && p.has("o"):
		return nil, errors.New("ps: use -f or -o, not both")
	case p.has("f"):
		f = query.PSFull
	case p.has("o"):
		var err error
		if f, err = query.ParsePSFormat(strings.Join(p.all["o"], ",")); err != nil {
			return nil, err
		}
	}
	if c.w.IsRange() && !all && !c.g.samples && !c.g.changes {
		return nil, errors.New("ps: the range summary lists every process (-e or aux); -p, -u and -C need --at, --samples or --changes")
	}
	var sel func(r *query.PSRow) bool
	if !all {
		pidSet := map[int]bool{}
		for _, v := range pids {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("ps: bad PID %q", v)
			}
			pidSet[n] = true
		}
		sel = func(r *query.PSRow) bool {
			if pidSet[r.PID] {
				return true
			}
			for _, u := range users {
				if u == strconv.Itoa(r.UIDNum) || u == query.UserName(r.UIDNum, false) {
					return true
				}
			}
			for _, n := range names {
				if n == r.CommName {
					return true
				}
			}
			return false
		}
	}
	return func() error { return runPS(c, sel, f, false) }, nil
}

// runPS prints ps at a moment (aux when f is nil) or the range summary.
func runPS(c *runCtx, sel func(*query.PSRow) bool, f query.PSFormat, forest bool) error {
	if ok, err := rangeView(c, psView(c, sel, f, forest)); ok {
		return err
	}
	db, w := c.db, c.w
	if w.IsRange() {
		rows, err := query.PSRange(db, w.From, w.To)
		if err != nil {
			return err
		}
		c.header("processes between %s and %s, identical commands collapsed (SRC ev: only seen through exec/exit events)",
			query.FormatMS(w.From), query.FormatMS(w.To))
		return c.emit(rows, func(int) rowMeta {
			return rowMeta{From: w.From, To: w.To, Sampled: []string{"last_seen_ms", "peak_pcpu", "peak_rss_kb"}}
		}, func(w io.Writer) { query.PrintPSRange(w, rows) })
	}
	rows, s, err := query.PSAt(db, w.At)
	if err != nil {
		return err
	}
	if sel != nil {
		kept := rows[:0]
		for i := range rows {
			if sel(&rows[i]) {
				kept = append(kept, rows[i])
			}
		}
		rows = kept
	}
	if forest {
		rows = query.PSForest(rows)
	}
	c.header("ps at %s, reconstructed from sample at %s (%d processes)", query.FormatMS(w.At), query.FormatMS(s), len(rows))
	// OOM kills soon after T are not in the sample; point them out.
	if kills, err := query.OOMKills(db, s, w.At+query.IntervalMS(db), 0); err == nil {
		for _, k := range kills {
			c.header("OOM kill at %s: pid %d, RSS at the kill %d kB (%s); see: clifr ... oom", query.FormatMS(k.TS), k.PID, k.RSSKB, k.Command)
		}
	}
	return c.emit(rows, func(int) rowMeta {
		return rowMeta{TS: w.At, SampleTS: s, Sampled: psSampled}
	}, func(out io.Writer) {
		if f == nil {
			query.PrintPS(out, rows)
		} else {
			query.PrintPSFormat(out, rows, f)
		}
	})
}

// psSampled are the ps fields read at each sample; the others (ids, user,
// terminal, start, command, elapsed time) are exact for the process.
var psSampled = []string{"pcpu", "pmem", "vsz_kb", "rss_kb", "stat", "time", "nice", "threads", "cpu_ticks",
	"io_rchar", "io_wchar", "io_read_bytes", "io_write_bytes"}

func lsofTool() *tool {
	return &tool{
		name: "lsof", diff: true, synopsis: "[-n] [-P] [-a] [-i] [-p PIDS] [-u USERS] [-c NAME]",
		about: "open files and sockets of every process",
		opts: []opt{
			{short: 'p', arg: "PIDS", help: "these processes (comma separated)"},
			{short: 'u', arg: "USERS", help: "processes of these users (names or numbers)"},
			{short: 'c', arg: "NAME", help: "processes whose command begins with NAME (repeatable)"},
			{short: 'i', help: "internet sockets"},
			{short: 'a', help: "AND the selections (by default, like lsof, any one selects)"},
			{short: 'n', help: "accepted: addresses are never resolved"},
			{short: 'P', help: "accepted: ports are never resolved"},
		},
		window: true,
		notes: []string{
			"Files: those held across two fd walks (2 minutes by default) and deleted files (sampled).",
			"TCP sockets exact (events); UDP sockets from the keyframe.",
		},
		examples: []string{`clifr --at "02:45" "lsof -p 58841"`, `clifr --at "02:45" "lsof -a -i -u postgres"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			var s query.LsofSelect
			for _, v := range splitList(p.all["p"]) {
				pid, err := strconv.Atoi(v)
				if err != nil || pid <= 0 {
					return nil, fmt.Errorf("lsof: bad PID %q", v)
				}
				s.PIDs = append(s.PIDs, pid)
			}
			s.Users, s.Commands = splitList(p.all["u"]), p.all["c"]
			s.Inet, s.And = p.has("i"), p.has("a")
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("lsof: file arguments are not supported (%q)", p.pos[0])
			}
			return func() error { return runLsof(c, s) }, nil
		},
	}
}

func runLsof(c *runCtx, sel query.LsofSelect) error {
	if ok, err := rangeView(c, lsofView(c, sel)); ok {
		return err
	}
	db, w := c.db, c.w
	o := sel.Options()
	if w.IsRange() {
		rows, err := query.LsofRange(db, w.From, w.To, o)
		if err != nil {
			return err
		}
		rows = sel.Filter(rows)
		c.header("files held between %s and %s (%d)", query.FormatMS(w.From), query.FormatMS(w.To), len(rows))
		events := query.TCPFromEvents(db)
		return c.emit(rows, func(i int) rowMeta {
			m := rowMeta{From: w.From, To: w.To}
			if !(events && rows[i].Node == "TCP") {
				m.Sampled = []string{"first_seen_ms", "last_seen_ms"} // bounded by fd walks
			}
			return m
		}, func(w io.Writer) { query.PrintLsof(w, rows, true) })
	}
	rows, s, sfd, err := query.LsofAt(db, w.At, o)
	if err != nil {
		return err
	}
	rows = sel.Filter(rows)
	if query.TCPFromEvents(db) {
		c.header("lsof at %s: files from the full fd walk at %s (sampled); TCP sockets exact (events); UDP from the keyframe (%d rows)",
			query.FormatMS(w.At), query.FormatMS(sfd), len(rows))
	} else {
		c.header("lsof at %s: files from full fd walk at %s, inet sockets from sample at %s (%d rows)",
			query.FormatMS(w.At), query.FormatMS(sfd), query.FormatMS(s), len(rows))
	}
	events, kf := query.TCPFromEvents(db), query.KeyframeAt(db, w.At)
	return c.emit(rows, func(i int) rowMeta {
		r := rows[i]
		switch {
		case events && r.Node == "TCP":
			return rowMeta{TS: w.At}
		case events && r.Node == "UDP":
			return rowMeta{TS: w.At, SampleTS: kf, Sampled: jsonKeys(r)}
		case !events && strings.HasPrefix(r.Type, "IPv"):
			return rowMeta{TS: w.At, SampleTS: s, Sampled: jsonKeys(r)}
		}
		return rowMeta{TS: w.At, SampleTS: sfd, Sampled: jsonKeys(r)} // from the fd walk
	}, func(w io.Writer) { query.PrintLsof(w, rows, false) })
}

func freeTool() *tool {
	return &tool{
		name: "free", synopsis: "[-b|-k|-m|-g|-h] [-w] [-t] [-s SECONDS] [-c COUNT]",
		about: "memory and swap use",
		opts: []opt{
			{short: 'b', long: "bytes", help: "bytes"},
			{short: 'k', long: "kibi", help: "KiB (the default)"},
			{short: 'm', long: "mebi", help: "MiB"},
			{short: 'g', long: "gibi", help: "GiB"},
			{short: 'h', long: "human", help: "the shortest unit that fits (Ki, Mi, Gi)"},
			{short: 'w', long: "wide", help: "buffers and cache in separate columns"},
			{short: 't', long: "total", help: "a Total line (memory plus swap)"},
			{short: 's', long: "seconds", arg: "SECONDS", help: "with --since: one report every SECONDS"},
			{short: 'c', long: "count", arg: "COUNT", help: "with --since: stop after COUNT reports"},
		},
		window: true,
		notes: []string{
			"--at: the counters of the sample at or before T (sampled).",
			"--since: one report per sample with --samples or -s (spacing -e or -s, count -n or -c).",
		},
		examples: []string{`clifr --at "02:45" "free -h"`, `clifr --since "02:00" --until "02:30" "free -m -s 60"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			f := query.FreeFormat{Unit: "k", Wide: p.has("wide"), Total: p.has("total")}
			for _, u := range []string{"bytes", "kibi", "mebi", "gibi", "human"} {
				if p.has(u) {
					f.Unit = map[string]string{"bytes": "b", "kibi": "k", "mebi": "m", "gibi": "g", "human": "h"}[u]
				}
			}
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("free: unexpected argument %q", p.pos[0])
			}
			every, number := c.g.everyMS, c.g.number
			if v, ok := p.set["seconds"]; ok {
				n, err := strconv.ParseFloat(v, 64)
				if err != nil || n <= 0 {
					return nil, fmt.Errorf("free: bad -s %q", v)
				}
				every = int64(n * 1000)
			}
			if v, ok := p.set["count"]; ok {
				n, err := strconv.Atoi(v)
				if err != nil || n <= 0 {
					return nil, fmt.Errorf("free: bad -c %q", v)
				}
				number = n
			}
			samples := c.g.samples || p.has("seconds") || p.has("count")
			switch {
			case !c.w.IsRange() && samples:
				return nil, errors.New("free: -s and -c need a range (--since)")
			case c.w.IsRange() && !samples:
				return nil, errors.New("free: over a range, add --samples or -s SECONDS (one report per sample)")
			case c.g.changes:
				return nil, errors.New("free: --changes is not available for free; use --samples")
			}
			return func() error {
				spans, err := query.SysSpans(c.db, c.w, every)
				if err != nil {
					return err
				}
				if c.w.IsRange() {
					if number > 0 && len(spans) > number {
						spans = spans[:number]
					}
					c.header("free: %d samples, %s .. %s", len(spans), query.FormatMS(spans[0].To), query.FormatMS(spans[len(spans)-1].To))
				} else {
					c.header("free at the sample of %s", query.FormatMS(spans[0].To))
				}
				rows, err := query.Free(c.db, spans)
				if err != nil {
					return err
				}
				return c.emit(rows, func(i int) rowMeta {
					return rowMeta{Sampled: jsonKeys(rows[i], "ts_ms")}
				}, func(w io.Writer) { query.PrintFree(w, rows, f) })
			}, nil
		},
	}
}

func netstatTool() *tool {
	return &tool{
		name: "netstat", diff: true, synopsis: "-n -t|-u [-a|-l] [-p] [-W] [-4|-6]  |  -s [-t] [-u] [-w] [-6]",
		about: "TCP and UDP sockets (net-tools)",
		opts: []opt{
			{short: 't', long: "tcp", help: "TCP sockets"},
			{short: 'u', long: "udp", help: "UDP sockets (recorded at keyframes)"},
			{short: 'a', long: "all", help: "listening and non-listening sockets"},
			{short: 'l', long: "listening", help: "only listening sockets"},
			{short: 'n', long: "numeric", help: "numeric addresses and ports (required: clifr cannot resolve past host names)"},
			{short: 'p', long: "programs", help: "PID/Program name"},
			{short: 'W', long: "wide", help: "do not cut addresses"},
			{short: '4', help: "only IPv4 sockets"},
			{short: '6', help: "only IPv6 sockets (with -s: the IPv6 statistics)"},
			{short: 's', long: "statistics", help: "protocol statistics (/proc/net/snmp and netstat; recorded since 2026-10-21)"},
			{short: 'w', long: "raw", help: "with -s: IP and ICMP statistics"},
		},
		window: true,
		notes: []string{
			"-s: the counters at the system sample at or before T, in net-tools 2.10's words; -t, -u, -w",
			"choose sections (sections net-tools has no table for are always shown, as by netstat).",
			"Same data as ss. Without -a or -l: TCP in every state but LISTEN, connected UDP only.",
			"Program names: argv[0] from the recording, by net-tools' rule (recordings before schema 2:",
			"approximated from the command line).",
			"--since: TCP connections by process over the range, as ss shows them.",
		},
		examples: []string{`clifr --at "02:45" "netstat -tulpn"`, `clifr --at "02:45" "netstat -tanp"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			tcp, udp := p.has("tcp"), p.has("udp")
			if p.has("statistics") {
				return prepareNetstatStats(p, c)
			}
			switch {
			case p.has("raw"):
				return nil, errors.New("netstat: -w (raw sockets) is not recorded; with -s it selects the IP and ICMP statistics")
			case !p.has("numeric"):
				return nil, errors.New("netstat: add -n: without it netstat looks up host names, which cannot be done for the past")
			case !tcp && !udp:
				return nil, errors.New("netstat: add -t and/or -u: clifr records TCP and UDP only")
			case p.has("all") && p.has("listening"):
				return nil, errors.New("netstat: use -a or -l, not both")
			case len(p.pos) > 0:
				return nil, fmt.Errorf("netstat: unexpected argument %q", p.pos[0])
			}
			v := query.NetstatView{All: p.has("all"), Listening: p.has("listening"), Program: p.has("programs"),
				Wide: p.has("wide"), V4: p.has("4"), V6: p.has("6")}
			return func() error {
				if ok, err := rangeView(c, netstatView(c, tcp, udp, v)); ok {
					return err
				}
				if c.w.IsRange() {
					return socketsRange(c, "netstat", udp, query.SockFilter{})
				}
				rows, meta, err := socketsAt(c, c.w.At, tcp, udp, query.SockFilter{})
				if err != nil {
					return err
				}
				kept := rows[:0]
				for i := range rows {
					if v.Keep(&rows[i]) {
						kept = append(kept, rows[i])
					}
				}
				var progs map[int]string
				if v.Program {
					if progs, err = query.ProgramNames(c.db, c.w.At); err != nil {
						return err
					}
				}
				return c.emit(kept, func(i int) rowMeta { return meta(&kept[i]) },
					func(w io.Writer) { query.PrintNetstat(w, kept, v, progs) })
			}, nil
		},
	}
}

func eventsTool() *tool {
	return &tool{
		name: "events", synopsis: "[--name REGEX] [--type KINDS]",
		about: "clifr only: a timeline of process starts and exits, OOM kills, mounts and recorder gaps",
		opts: []opt{
			{long: "name", arg: "REGEX", help: "only process events whose command line matches"},
			{long: "type", arg: "KINDS", help: "comma separated: " + strings.Join(query.EventKinds, ",")},
		},
		notes: []string{
			"Without --since: the whole recording. Times are exact (events) except exits marked ~:",
			"those happened between the sample shown and the next.",
		},
		examples: []string{`clifr --since "1 hour ago" events`, `clifr --since today "events --type oom,gap"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if !c.w.IsRange() {
				return nil, errors.New("events: needs a range (--since), or no time for the whole recording")
			}
			var re *regexp.Regexp
			if v, ok := p.set["name"]; ok {
				var err error
				if re, err = regexp.Compile(v); err != nil {
					return nil, fmt.Errorf("events: --name: %w", err)
				}
			}
			var kinds map[string]bool
			if v, ok := p.set["type"]; ok {
				kinds = map[string]bool{}
				for _, k := range splitList([]string{v}) {
					if !strings.Contains(","+strings.Join(query.EventKinds, ",")+",", ","+k+",") {
						return nil, fmt.Errorf("events: unknown type %q (%s)", k, strings.Join(query.EventKinds, ","))
					}
					kinds[k] = true
				}
			}
			return func() error {
				if c.w.From == 0 { // the whole recording: from its first sample
					c.w.From = query.RecordingStart(c.db)
				}
				evs, err := query.Events(c.db, c.w.From, c.w.To, re, kinds)
				if err != nil {
					return err
				}
				c.header("%d events %s .. %s", len(evs), query.FormatMS(c.w.From), query.FormatMS(c.w.To))
				return c.emit(evs, func(i int) rowMeta {
					if !evs[i].Exact {
						return rowMeta{Sampled: []string{"ts_ms"}}
					}
					return rowMeta{}
				}, func(w io.Writer) { query.PrintEvents(w, evs) })
			}, nil
		},
	}
}

func mountTool() *tool {
	return &tool{
		name: "mount", diff: true, synopsis: "[-l] [-t TYPES]",
		about: "the mount table",
		opts: []opt{{short: 't', long: "types", arg: "TYPES", help: "only these file-system types (comma separated; prefix all with no to exclude)"},
			{short: 'l', long: "show-labels", help: "file system labels (recorded since schema 9)"}},
		window: true,
		notes: []string{
			"The recorder's mount namespace, in mountinfo order; exact (mountinfo change events).",
			"Recordings before schema 2 lack the file-system options and order: mount shows the mount",
			"options only, sorted by mount point.",
			"--since: the mounts, unmounts and remounts in the range.",
			"-l: the label of the block device as last read at or before T (at a uevent, else every minute).",
		},
		examples: []string{`clifr --at "02:45" "mount -t ext4,xfs"`, `clifr --at "02:45" "mount -l -t ext4"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("mount: only listing is possible for the past (%q)", p.pos[0])
			}
			if p.has("show-labels") && c.w.IsRange() {
				return nil, errors.New("mount: -l needs --at")
			}
			var types query.MountTypes
			if v, ok := p.set["types"]; ok {
				types = splitList([]string{v})
				for _, t := range types[1:] {
					if strings.HasPrefix(t, "no") != strings.HasPrefix(types[0], "no") {
						return nil, errors.New("mount: -t: prefix all types with no, or none")
					}
				}
			}
			return func() error {
				if ok, err := rangeView(c, mountView(c, types)); ok {
					return err
				}
				var rows []query.MountRow
				var err error
				if c.w.IsRange() {
					rows, err = query.MountChanges(c.db, c.w.From, c.w.To)
					c.header("mount table changes %s .. %s (exact, from events)", query.FormatMS(c.w.From), query.FormatMS(c.w.To))
				} else {
					rows, err = query.MountsAt(c.db, c.w.At)
					c.header("mount table at %s (exact, from events)", query.FormatMS(c.w.At))
				}
				if err != nil {
					return err
				}
				kept := rows[:0]
				for _, m := range rows {
					if types.Keep(m.FSType) {
						kept = append(kept, m)
					}
				}
				if p.has("show-labels") && !c.w.IsRange() {
					if err := query.AddMountLabels(c.db, c.w.At, kept); err != nil {
						return err
					}
				}
				return c.emit(kept, func(int) rowMeta {
					if c.w.IsRange() {
						return rowMeta{From: c.w.From, To: c.w.To}
					}
					return rowMeta{TS: c.w.At}
				}, func(w io.Writer) {
					if c.w.IsRange() {
						query.PrintMounts(w, kept, true)
					} else {
						query.PrintMount(w, kept)
					}
				})
			}, nil
		},
	}
}

func dfTool() *tool {
	return &tool{
		name: "df", diff: true, synopsis: "[-h] [-T] [-i] [-a] [-l] [-x TYPE] [-t TYPE] [PATH...]",
		about: "file-system usage",
		opts: []opt{
			{short: 'h', long: "human-readable", help: "sizes in powers of 1024 (K, M, G), rounded up"},
			{short: 'T', long: "print-type", help: "also the file-system type"},
			{short: 'i', long: "inodes", help: "inodes instead of blocks"},
			{short: 'k', help: "1K blocks (the default)"},
			{short: 'a', long: "all", help: "also dummy, empty and duplicate file systems (with zeros where they have no blocks)"},
			{short: 'l', long: "local", help: "no network file systems (NFS, CIFS, ...)"},
			{short: 'x', long: "exclude-type", arg: "TYPE", help: "leave out this type (repeat -x for more)"},
			{short: 't', long: "type", arg: "TYPE", help: "only this type (repeat -t for more)"},
		},
		window: true,
		notes: []string{
			"Usage from the sample at or before T (sampled; recordings since schema 2). As GNU df: dummy",
			"and empty file systems, devtmpfs and squashfs are left out, a device mounted more than once is",
			"listed once (all of them with -a), in mountinfo order. PATH: the file system whose mount point",
			"holds it.",
			"--since: one report per sample with --samples (-e, -n).",
		},
		examples: []string{`clifr --at "02:45" "df -h"`, `clifr --at "02:45" "df -h /var/log"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			f := query.DFFormat{Human: p.has("human-readable"), Type: p.has("print-type"), Inodes: p.has("inodes")}
			sel := query.DFSelect{All: p.has("all"), Local: p.has("local"),
				Exclude: splitList(p.all["exclude-type"]), Only: splitList(p.all["type"])}
			if f.Human && f.Inodes {
				return nil, errors.New("df: -h with -i is not supported")
			}
			for _, a := range p.pos {
				if !strings.HasPrefix(a, "/") {
					return nil, fmt.Errorf("df: %q: give an absolute path (the recording has no working directory)", a)
				}
			}
			if c.w.IsRange() && !c.g.samples && !c.g.changes {
				return nil, errors.New("df: over a range, add --samples (one report per sample) or --changes")
			}
			return func() error {
				v := dfView(c, f, sel, p.pos)
				if ok, err := rangeView(c, v); ok {
					return err
				}
				rows, meta, err := v.at(c.w.At)
				if err != nil {
					return err
				}
				if len(p.pos) > 0 && len(rows) < len(p.pos) {
					return fmt.Errorf("df: no file system recorded for some of %s", strings.Join(p.pos, ", "))
				}
				c.header("df at %s, usage sampled", query.FormatMS(c.w.At))
				return c.emit(rows, func(i int) rowMeta { return meta(&rows[i]) }, func(w io.Writer) { v.print(w, rows) })
			}, nil
		},
	}
}

func prepareNetstatStats(p parsed, c *runCtx) (func() error, error) {
	for k := range p.set {
		switch k {
		case "statistics", "tcp", "udp", "raw", "6", "numeric":
		default:
			return nil, fmt.Errorf("netstat: -s takes -t, -u, -w and -6, not --%s", k)
		}
	}
	if len(p.pos) > 0 {
		return nil, fmt.Errorf("netstat: unexpected argument %q", p.pos[0])
	}
	if c.w.IsRange() {
		return nil, errors.New("netstat: -s needs --at (for increases over a range: clifr ... nstat)")
	}
	o := query.NetstatStatsOptions{Raw: p.has("raw"), TCP: p.has("tcp"), UDP: p.has("udp"), V6: p.has("6")}
	return func() error {
		text, ts, err := query.NetstatStats(c.db, c.w.At, o)
		if err != nil {
			return err
		}
		c.header("netstat -s at %s: the counters at the system sample at %s", query.FormatMS(c.w.At), query.FormatMS(ts))
		lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
		rows := make([]pstreeLine, len(lines))
		for i, l := range lines {
			rows[i] = pstreeLine{Line: l}
		}
		return c.emit(rows, func(int) rowMeta { return rowMeta{TS: c.w.At, SampleTS: ts} },
			func(w io.Writer) { io.WriteString(w, text) })
	}, nil
}
