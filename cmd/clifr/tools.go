package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

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
	prepare  func(p parsed, c *runCtx) (func() error, error)
}

// runCtx is what a tool needs at run time.
type runCtx struct {
	g  *globals
	w  query.Window
	db *store.DB
}

func (c *runCtx) header(format string, args ...any) { query.Header(format, args...) }

func (c *runCtx) out(v any, text func()) error {
	if c.g.json {
		return query.PrintJSON(os.Stdout, v)
	}
	text()
	return nil
}

// summaryOnly rejects --changes and --samples for tools whose range output
// is a summary.
func summaryOnly(name string, c *runCtx) error {
	if c.w.IsRange() && (c.g.changes || c.g.samples) {
		return fmt.Errorf("%s: --changes and --samples are not available yet; a range shows the summary (one row per object)", name)
	}
	return nil
}

var tools = map[string]*tool{}

var toolOrder []string

func addTool(t *tool) {
	tools[t.name] = t
	toolOrder = append(toolOrder, t.name)
}

var bsdPS = regexp.MustCompile(`^[auxw]+$`)

func init() {
	addTool(&tool{
		name: "ps", synopsis: "aux",
		about:  "processes and their CPU, memory, state and command line",
		window: true,
		notes: []string{
			"Only the BSD form aux is supported (w, ww are accepted: lines are never cut).",
			"--at: the processes alive at T with their values from the sample at or before T (sampled).",
			"--since: every process seen in the range, identical commands collapsed, with first/last seen and peaks.",
		},
		examples: []string{`clifr --at "02:45" "ps aux"`, `clifr --since yesterday --until today "ps aux"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) != 1 || !bsdPS.MatchString(p.pos[0]) || !strings.Contains(p.pos[0], "a") ||
				!strings.Contains(p.pos[0], "u") || !strings.Contains(p.pos[0], "x") {
				return nil, errors.New(`ps: only "ps aux" is supported (see: clifr help ps)`)
			}
			if err := summaryOnly("ps", c); err != nil {
				return nil, err
			}
			return func() error { return runPS(c) }, nil
		},
	})
	addTool(&tool{
		name: "ss", synopsis: "-t|-u [-a|-l] [-n] [-p] [-4|-6] [FILTER]",
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
		},
		window: true,
		notes: []string{
			"FILTER: dst|src ADDR[/LEN][:PORT], dport|sport = :PORT, joined with \"and\".",
			"Without -a or -l only connected sockets are shown, as by ss. Without -n port numbers are",
			"resolved with /etc/services of the machine running clifr.",
			"TCP from events: connections, states and owners exact; Recv-Q/Send-Q from the keyframe (sampled).",
			"--since: TCP connections by process over the range (every connection, however short).",
		},
		examples: []string{`clifr --at "14:00" "ss -ltnp"`,
			`clifr --since "2026-10-02 02:00" --until "2026-10-02 03:00" "ss -tanp dst 10.0.4.21 and dport = :5432"`},
		prepare: prepareSS,
	})
	addTool(&tool{
		name: "lsof", synopsis: "[-n] [-P] [-i] [-p PID]",
		about: "open files and sockets of every process",
		opts: []opt{
			{short: 'p', arg: "PID", help: "only this process"},
			{short: 'i', help: "only internet sockets"},
			{short: 'n', help: "accepted: addresses are never resolved"},
			{short: 'P', help: "accepted: ports are never resolved"},
		},
		window: true,
		notes: []string{
			"Files: those held across two fd walks (2 minutes by default) and deleted files (sampled).",
			"TCP sockets exact (events); UDP sockets from the keyframe.",
		},
		examples: []string{`clifr --at "02:45" "lsof -p 58841"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			var o query.LsofOptions
			if v, ok := p.set["p"]; ok {
				pid, err := strconv.Atoi(v)
				if err != nil || pid <= 0 {
					return nil, fmt.Errorf("lsof: bad PID %q", v)
				}
				o.PID = pid
			}
			o.InetOnly = p.has("i")
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("lsof: file arguments are not supported (%q)", p.pos[0])
			}
			if err := summaryOnly("lsof", c); err != nil {
				return nil, err
			}
			return func() error { return runLsof(c, o) }, nil
		},
	})
	addSystemTools()
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
		name: "mounts", synopsis: "",
		about: "clifr only: the mount table at T, or mounts and unmounts over a range",
		notes: []string{"The recorder's mount namespace; exact (mountinfo change events)."},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			return func() error { return runMounts(c) }, nil
		},
	})
}

func runPS(c *runCtx) error {
	db, w := c.db, c.w
	if w.IsRange() {
		rows, err := query.PSRange(db, w.From, w.To)
		if err != nil {
			return err
		}
		c.header("processes between %s and %s, identical commands collapsed (SRC ev: only seen through exec/exit events)",
			query.FormatMS(w.From), query.FormatMS(w.To))
		return c.out(rows, func() { query.PrintPSRange(os.Stdout, rows) })
	}
	rows, s, err := query.PSAt(db, w.At)
	if err != nil {
		return err
	}
	c.header("ps aux at %s, reconstructed from sample at %s (%d processes)", query.FormatMS(w.At), query.FormatMS(s), len(rows))
	// OOM kills soon after T are not in the sample; point them out.
	if kills, err := query.OOMKills(db, s, w.At+query.IntervalMS(db), 0); err == nil {
		for _, k := range kills {
			c.header("OOM kill at %s: pid %d, RSS at the kill %d kB (%s); see clifr ... \"oom\"", query.FormatMS(k.TS), k.PID, k.RSSKB, k.Command)
		}
	}
	if c.g.json {
		return query.PrintPSJSON(os.Stdout, rows)
	}
	query.PrintPS(os.Stdout, rows)
	return nil
}

func prepareSS(p parsed, c *runCtx) (func() error, error) {
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
	if err := summaryOnly("ss", c); err != nil {
		return nil, err
	}
	return func() error { return runSS(c, tcp, udp, filter, v) }, nil
}

func runSS(c *runCtx, tcp, udp bool, filter query.SockFilter, v query.SSView) error {
	db, w := c.db, c.w
	events := query.TCPFromEvents(db)
	if w.IsRange() {
		if udp && events {
			return errors.New("ss: a range covers TCP only (UDP is recorded at keyframes)")
		}
		var groups []query.SSGroup
		var err error
		if events {
			groups, err = query.ConnsInRange(db, w.From, w.To, filter)
			c.header("TCP connections by process, %s .. %s, from events (every connection, however short, in any state)",
				query.FormatMS(w.From), query.FormatMS(w.To))
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
		return c.out(groups, func() { query.PrintSSGroups(os.Stdout, groups) })
	}
	var rows []query.SSRow
	for _, proto := range []string{"udp", "tcp"} { // ss's order
		if (proto == "tcp" && !tcp) || (proto == "udp" && !udp) {
			continue
		}
		var r []query.SSRow
		if events {
			var kf int64
			var err error
			if r, kf, err = query.ConnsAt(db, w.At, proto, filter); err != nil {
				return err
			}
			if proto == "tcp" {
				tw := "time-wait end exact"
				if !query.TimeWaitExact(db) {
					tw = "time-wait shown until 60 s after the close (the kernel ends it 0-5 s later)"
				}
				c.header("TCP at %s: connections, states and owners exact (events); Recv-Q/Send-Q from the keyframe at %s; %s",
					query.FormatMS(w.At), query.FormatMS(kf), tw)
			} else {
				c.header("UDP at %s from the keyframe at %s (UDP is recorded at keyframes only)", query.FormatMS(w.At), query.FormatMS(kf))
			}
		} else {
			s, err := query.SnapshotAt(db, w.At, false)
			if err != nil {
				return err
			}
			if r, err = query.SocketsAt(db, s, proto, filter); err != nil {
				return err
			}
			c.header("%s at %s, reconstructed from sample at %s", proto, query.FormatMS(w.At), query.FormatMS(s))
		}
		rows = append(rows, v.Filter(r)...)
	}
	return c.out(rows, func() { query.PrintSSView(os.Stdout, rows, v, tcp && udp) })
}

func runLsof(c *runCtx, o query.LsofOptions) error {
	db, w := c.db, c.w
	if w.IsRange() {
		rows, err := query.LsofRange(db, w.From, w.To, o)
		if err != nil {
			return err
		}
		c.header("files held between %s and %s (%d)", query.FormatMS(w.From), query.FormatMS(w.To), len(rows))
		return c.out(rows, func() { query.PrintLsof(os.Stdout, rows, true) })
	}
	rows, s, sfd, err := query.LsofAt(db, w.At, o)
	if err != nil {
		return err
	}
	if query.TCPFromEvents(db) {
		c.header("lsof at %s: files from the full fd walk at %s (sampled); TCP sockets exact (events); UDP from the keyframe (%d rows)",
			query.FormatMS(w.At), query.FormatMS(sfd), len(rows))
	} else {
		c.header("lsof at %s: files from full fd walk at %s, inet sockets from sample at %s (%d rows)",
			query.FormatMS(w.At), query.FormatMS(sfd), query.FormatMS(s), len(rows))
	}
	return c.out(rows, func() { query.PrintLsof(os.Stdout, rows, false) })
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
	return c.out(rows, func() { query.PrintLife(os.Stdout, rows) })
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
	return c.out(kills, func() { query.PrintOOM(os.Stdout, kills) })
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
	return c.out(rows, func() { query.PrintMounts(os.Stdout, rows, c.w.IsRange()) })
}
