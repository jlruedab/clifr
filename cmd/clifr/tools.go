package main

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"clifr/internal/query"
	"clifr/internal/store"
)

// tool is a command clifr reconstructs, with the options it supports in the
// real tool's syntax. prepare checks the options before the recording is
// opened and returns the function that prints the output.
type tool struct {
	name     string
	synopsis string // after the name, for help
	about    string
	opts     []opt
	notes    []string
	examples []string
	window   bool // needs --at or --since
	history  bool // reads the recording up to the window (last), not only around it
	diff     bool // has a view: --changes, --samples and diff work
	prepare  func(p parsed, c *runCtx) (func() error, error)
}

// runCtx is what a tool needs at run time.
type runCtx struct {
	g      *globals
	w      query.Window
	db     *store.DB
	quiet  bool    // range views: no per-snapshot headers
	diffAt []int64 // clifr diff: the two moments
}

func (c *runCtx) header(format string, args ...any) {
	if !c.quiet {
		query.Header(format, args...)
	}
}

var tools = map[string]*tool{}

var toolOrder []string

func addTool(t *tool) {
	tools[t.name] = t
	toolOrder = append(toolOrder, t.name)
}

func init() {
	addTool(psTool())
	addTool(topTool())
	addTool(pstreeTool())
	addTool(&tool{
		name: "ss", diff: true, synopsis: "-t|-u [-a|-l] [-n] [-p] [-4|-6] [-N CONTAINER|PID] [FILTER] | -s",
		about: "TCP and UDP sockets",
		opts: []opt{
			{short: 't', long: "tcp", help: "TCP sockets"},
			{short: 'u', long: "udp", help: "UDP sockets (recorded at keyframes, every 5 minutes by default)"},
			{short: 'a', long: "all", help: "listening and non-listening sockets"},
			{short: 'l', long: "listening", help: "only listening sockets (LISTEN, UNCONN)"},
			{short: 'n', long: "numeric", help: "do not resolve service names"},
			{short: 'p', long: "processes", help: "show the processes using each socket"},
			{short: '4', long: "ipv4", help: "only IPv4 sockets"},
			{short: '6', long: "ipv6", help: "only IPv6 sockets"},
			{short: 's', long: "summary", help: "socket counts by protocol (from /proc/net/sockstat, recorded since schema 3)"},
			{short: 'N', long: "net", arg: "CONTAINER|PID", help: "the sockets of a container's or process's network namespace instead of the host's"},
		},
		window: true,
		notes: []string{
			"FILTER: dst|src ADDR[/LEN][:PORT], dport|sport = :PORT, joined with \"and\".",
			"Without -N the host's network namespace, as ss on the host shows it. -N CONTAINER (an id or",
			"its first 4+ digits, or an LXC name, as clifr containers lists them) or -N PID: that one's",
			"namespace at T (recorded since 2026-11-08). In other namespaces Recv-Q/Send-Q come from",
			"/proc/PID/net: a listener's Send-Q (backlog) is 0 and IPv6-only listeners show as [::].",
			"Without -a or -l only connected sockets are shown, as by ss. Without -n port numbers are",
			"resolved with /etc/services of the machine running clifr.",
			"TCP from events: connections, states and owners exact; Recv-Q/Send-Q from the keyframe (sampled).",
			"A range has no single moment, so --since summarizes it: TCP connections by process.",
			"--list prints every TCP connection instead, one row each (however short, from events):",
			"Opened and Closed (- if still open at the end) replace the queues, State is its last in the range.",
			"-s: the counts from the system sample at or before T; estab (ESTABLISHED and CLOSE-WAIT) from",
			"the TCP records at T.",
		},
		examples: []string{`clifr --at "14:00" "ss -ltnp"`,
			`clifr --since "2026-10-02 02:00" --until "2026-10-02 03:00" "ss -tanp dst 10.0.4.21 and dport = :5432"`,
			`clifr --since "2026-10-02 02:00" --until "2026-10-02 03:00" --list "ss -tnp dport = :443"`},
		prepare: prepareSS,
	})
	addTool(lsofTool())
	addSystemTools()
	addTool(freeTool())
	addTool(netstatTool())
	addTool(eventsTool())
	addTool(containersTool())
	addTool(mountTool())
	addTool(dfTool())
	addTool(findmntTool())
	addTool(&tool{
		name: "life", synopsis: "[--name REGEX]",
		about: "clifr only: process starts and exits, including short-lived processes",
		opts:  []opt{{long: "name", arg: "REGEX", help: "regular expression matched against the command line"}},
		notes: []string{"Without --at or --since: the whole recording. Start and exit are exact (events)."},
		examples: []string{
			`clifr --since "1 hour ago" "life --name 'backup|rsync'"`,
		},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			var re *regexp.Regexp
			if v, ok := p.set["name"]; ok {
				var err error
				if re, err = regexp.Compile(v); err != nil {
					return nil, fmt.Errorf("life: --name: %w", err)
				}
			}
			return func() error { return runLife(c, re) }, nil
		},
	})
	addTool(&tool{
		name: "oom", synopsis: "[--top N]",
		about: "clifr only: OOM kills with the largest processes at the time",
		opts:  []opt{{long: "top", arg: "N", help: "processes to list by RSS for each kill (default 10)"}},
		notes: []string{"Without --at or --since: the whole recording; --at T: one minute either side of T."},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			top := 10
			if v, ok := p.set["top"]; ok {
				var err error
				if top, err = strconv.Atoi(v); err != nil || top < 0 {
					return nil, fmt.Errorf("oom: bad --top %q", v)
				}
			}
			return func() error { return runOOM(c, top) }, nil
		},
	})
	addTool(&tool{
		name: "pstore", synopsis: "",
		about: "clifr only: the kernel's crash records (panic, oops) saved across the reboot",
		notes: []string{
			"Without --since: the whole recording; a range: the records saved in it.",
			"The kernel saves its last messages in pstore (UEFI variables, or RAM reserved with ramoops) when it",
			"panics; clifrd stores them at its first start of the next boot (a pstore guard event says so).",
		},
		examples: []string{`clifr pstore`, `clifr --since "2026-11-04" "pstore"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			return func() error { return runPstore(c) }, nil
		},
	})
	addTool(&tool{
		name: "mounts", synopsis: "",
		about: "clifr only: the mount table at T, or mounts and unmounts over a range",
		notes: []string{"The recorder's mount namespace; exact (mountinfo change events)."},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			return func() error { return runMounts(c) }, nil
		},
	})
}

func prepareSS(p parsed, c *runCtx) (func() error, error) {
	if p.has("summary") {
		if len(p.set) > 1 || len(p.pos) > 0 {
			return nil, errors.New("ss: -s takes no other option or filter (its counts are the host's)")
		}
		if c.w.IsRange() {
			return nil, errors.New("ss: -s needs --at")
		}
		return func() error {
			s, err := query.SSSummaryAt(c.db, c.w.At)
			if err != nil {
				return err
			}
			c.header("ss -s at %s: counts from the system sample at %s", query.FormatMS(c.w.At), query.FormatMS(s.SampleTS))
			return c.emit(s, func(int) rowMeta {
				return rowMeta{TS: c.w.At, SampleTS: s.SampleTS, Sampled: []string{"total", "tcp", "transport"}}
			},
				func(w io.Writer) { query.PrintSSSummary(w, s) })
		}, nil
	}
	tcp, udp := p.has("tcp"), p.has("udp")
	if !tcp && !udp {
		return nil, errors.New("ss: add -t and/or -u: without them ss lists every socket type (unix, netlink, ...), and clifr records TCP and UDP")
	}
	if p.has("all") && p.has("listening") {
		return nil, errors.New("ss: use -a or -l, not both")
	}
	filter, err := query.ParseSockFilter(p.pos)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	v := query.SSView{All: p.has("all"), Listening: p.has("listening"), Process: p.has("processes"),
		Numeric: p.has("numeric"), V4: p.has("ipv4"), V6: p.has("ipv6")}
	spec := p.set["net"]
	return func() error {
		if spec != "" { // another network namespace: resolved at T (a range: its end)
			at := c.w.At
			if c.w.IsRange() {
				at = c.w.To
			}
			ns, label, err := query.NetNSOf(c.db, at, spec)
			if err != nil {
				return fmt.Errorf("ss: %w", err)
			}
			filter.NetNS = ns
			c.header("network namespace %s: %s", query.NetNSText(ns), label)
		}
		return runSS(c, tcp, udp, filter, v)
	}, nil
}

func runSS(c *runCtx, tcp, udp bool, filter query.SockFilter, v query.SSView) error {
	if ok, err := rangeView(c, ssView(c, tcp, udp, filter, v)); ok {
		return err
	}
	if c.w.IsRange() && c.g.list {
		return connList(c, "ss", udp, filter, func(w io.Writer, conns []query.ConnSpan) {
			query.PrintSSList(w, conns, v)
		}, func(r *query.SSRow) bool { return v.Keep(r) })
	}
	if c.w.IsRange() {
		return socketsRange(c, "ss", udp, filter)
	}
	rows, meta, err := socketsAt(c, c.w.At, tcp, udp, filter)
	if err != nil {
		return err
	}
	rows = v.Filter(rows)
	return c.emit(rows, func(i int) rowMeta { return meta(&rows[i]) },
		func(w io.Writer) { query.PrintSSView(w, rows, v, tcp && udp) })
}

// socketsRange prints the connections over a range by process (ss and
// netstat): from events every TCP connection, however short.
func socketsRange(c *runCtx, name string, udp bool, filter query.SockFilter) error {
	db, w := c.db, c.w
	events := query.TCPFromEvents(db)
	if udp && events {
		return errors.New(name + ": a range covers TCP only (UDP is recorded at keyframes); use -t")
	}
	var groups []query.SSGroup
	var err error
	if events {
		groups, err = query.ConnsInRange(db, w.From, w.To, filter)
		c.header("TCP connections by process, %s .. %s, from events (every connection, however short, in any state)",
			query.FormatMS(w.From), query.FormatMS(w.To))
		if n := query.BudgetNote(db, w.From, w.To, "tcp"); n != "" {
			c.header("%s", n)
		}
		if n := query.TCPLossNote(db, w.From, w.To); n != "" {
			c.header("%s", n)
		}
	} else {
		proto := "tcp"
		if udp {
			proto = "udp"
		}
		groups, err = query.SocketsInRange(db, w.From, w.To, proto, filter)
		c.header("%s sockets by process, %s .. %s", proto, query.FormatMS(w.From), query.FormatMS(w.To))
	}
	if err != nil {
		return err
	}
	return c.emit(groups, func(int) rowMeta {
		m := rowMeta{From: w.From, To: w.To}
		if !events { // v1 recordings: sockets seen at samples
			m.Sampled = jsonKeys(query.SSGroup{})
		}
		return m
	}, func(w io.Writer) { query.PrintSSGroups(w, groups) })
}

// connList prints every TCP connection over the range, one row each (--list;
// ss and netstat), from events. keep is the command's state and family
// selection, applied to each connection's last state in the range.
func connList(c *runCtx, name string, udp bool, filter query.SockFilter,
	print func(io.Writer, []query.ConnSpan), keep func(*query.SSRow) bool) error {
	if udp {
		return errors.New(name + ": --list covers TCP only (UDP is recorded at keyframes); use -t")
	}
	if !query.TCPFromEvents(c.db) {
		return errors.New(name + ": --list needs TCP events (this recording sampled sockets: --tcp sample); use --samples")
	}
	all, err := query.ConnList(c.db, c.w.From, c.w.To, filter)
	if err != nil {
		return err
	}
	conns := all[:0]
	for i := range all {
		if keep(all[i].Row()) {
			conns = append(conns, all[i])
		}
	}
	c.header("%s: %d TCP connections %s .. %s, from events (every connection, however short; State: the last in the range)",
		name, len(conns), query.FormatMS(c.w.From), query.FormatMS(c.w.To))
	if n := query.BudgetNote(c.db, c.w.From, c.w.To, "tcp"); n != "" {
		c.header("%s", n)
	}
	if n := query.TCPLossNote(c.db, c.w.From, c.w.To); n != "" {
		c.header("%s", n)
	}
	return c.emit(conns, func(int) rowMeta { return rowMeta{From: c.w.From, To: c.w.To} },
		func(w io.Writer) { print(w, conns) })
}

// socketsAt returns the TCP and/or UDP sockets at c.w.At (UDP first, as ss
// lists them) with each row's provenance, and prints where they come from.
// TCP from events: all exact but the queues (keyframe) and holders found by
// fd walks; UDP and v1 recordings: everything from a dump.
func socketsAt(c *runCtx, t int64, tcp, udp bool, filter query.SockFilter) ([]query.SSRow, func(*query.SSRow) rowMeta, error) {
	db, w := c.db, query.Window{At: t}
	events := query.TCPFromEvents(db)
	var rows []query.SSRow
	sampleTS := map[string]int64{}
	meta := func(r *query.SSRow) rowMeta {
		m := rowMeta{TS: w.At, SampleTS: sampleTS[r.Proto]}
		switch {
		case !events || r.Proto == "udp":
			m.Sampled = jsonKeys(*r)
		case len(r.Owners) > 1:
			m.Sampled = []string{"recv_q", "send_q", "owners"}
		default:
			m.Sampled = []string{"recv_q", "send_q"}
		}
		return m
	}
	for _, proto := range []string{"udp", "tcp"} { // ss's order
		if (proto == "tcp" && !tcp) || (proto == "udp" && !udp) {
			continue
		}
		var r []query.SSRow
		if events {
			var kf int64
			var err error
			if r, kf, err = query.ConnsAt(db, w.At, proto, filter); err != nil {
				return nil, nil, err
			}
			sampleTS[proto] = kf
			if proto == "tcp" {
				tw := "time-wait end exact"
				if !query.TimeWaitExact(db) {
					tw = "time-wait shown until 60 s after the close (the kernel ends it 0-5 s later)"
				}
				c.header("TCP at %s: connections, states and owners exact (events); Recv-Q/Send-Q from the keyframe at %s; %s",
					query.FormatMS(w.At), query.FormatMS(kf), tw)
				if n := query.TCPLossNote(db, w.At, w.At); n != "" {
					c.header("%s", n)
				}
			} else {
				c.header("UDP at %s from the keyframe at %s (UDP is recorded at keyframes only)", query.FormatMS(w.At), query.FormatMS(kf))
			}
		} else {
			s, err := query.SnapshotAt(db, w.At, false)
			if err != nil {
				return nil, nil, err
			}
			if r, err = query.SocketsAt(db, s, proto, filter); err != nil {
				return nil, nil, err
			}
			sampleTS[proto] = s
			c.header("%s at %s, reconstructed from sample at %s", proto, query.FormatMS(w.At), query.FormatMS(s))
		}
		rows = append(rows, r...)
	}
	return rows, meta, nil
}

func runLife(c *runCtx, re *regexp.Regexp) error {
	w := c.w
	if !w.IsRange() {
		w.From, w.To = w.At, w.At
	}
	rows, err := query.Life(c.db, w.From, w.To, re)
	if err != nil {
		return err
	}
	c.header("%d processes; END \">t\" means it exited after t and before the next sample", len(rows))
	if n := query.BudgetNote(c.db, w.From, w.To, "processes"); n != "" {
		c.header("%s", n)
	}
	return c.emit(rows, func(i int) rowMeta {
		m := rowMeta{From: w.From, To: w.To}
		if rows[i].EndKind != "exact" {
			m.Sampled = []string{"end_ms", "duration_ms"} // bounded by samples, or still running
		}
		return m
	}, func(w io.Writer) { query.PrintLife(w, rows) })
}

func runOOM(c *runCtx, top int) error {
	w := c.w
	if !w.IsRange() {
		w.From, w.To = w.At-60_000, w.At+60_000
	}
	kills, err := query.OOMKills(c.db, w.From, w.To, top)
	if err != nil {
		return err
	}
	c.header("OOM kills %s .. %s; RSS of the others: their last sample at or before the kill (sampled, not exact)",
		query.FormatMS(w.From), query.FormatMS(w.To))
	return c.emit(kills, func(int) rowMeta {
		return rowMeta{From: w.From, To: w.To, Sampled: []string{"top_rss"}} // the others' RSS from their last sample
	}, func(w io.Writer) { query.PrintOOM(w, kills) })
}

func runPstore(c *runCtx) error {
	var from, to int64
	if c.w.IsRange() && c.w.From > 0 { // without --since: the whole recording
		from, to = c.w.From, c.w.To
	}
	recs, err := query.PstoreRecords(c.db, from, to)
	if err != nil {
		return err
	}
	if to == 0 {
		c.header("kernel crash records (pstore) in the recording: %d", len(recs))
	} else {
		c.header("kernel crash records (pstore) saved %s .. %s: %d", query.FormatMS(from), query.FormatMS(to), len(recs))
	}
	return c.emit(recs, func(i int) rowMeta { return rowMeta{TS: recs[i].SavedMS} },
		func(w io.Writer) { query.PrintPstore(w, recs) })
}

func runMounts(c *runCtx) error {
	var rows []query.MountRow
	var err error
	if c.w.IsRange() {
		rows, err = query.MountChanges(c.db, c.w.From, c.w.To)
		c.header("mount table changes %s .. %s (the recorder's mount namespace; exact, from events)", query.FormatMS(c.w.From), query.FormatMS(c.w.To))
	} else {
		rows, err = query.MountsAt(c.db, c.w.At)
		c.header("mounts at %s (%d)", query.FormatMS(c.w.At), len(rows))
	}
	if err != nil {
		return err
	}
	return c.emit(rows, func(int) rowMeta {
		if c.w.IsRange() {
			return rowMeta{From: c.w.From, To: c.w.To}
		}
		return rowMeta{TS: c.w.At}
	}, func(w io.Writer) { query.PrintMounts(w, rows, c.w.IsRange()) })
}
