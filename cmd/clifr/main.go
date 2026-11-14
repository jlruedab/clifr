// Command clifr shows what a Linux diagnostic command would have printed at a
// past moment, from data recorded by clifrd. It never runs the command: it
// rebuilds the output from the recording, a Parquet data directory read
// through DuckDB.
package main

import (
	"clifr/internal/bundle"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" // --tz works where the system has no zoneinfo

	"clifr/internal/duck"
	"clifr/internal/pqstore"
	"clifr/internal/query"
	"clifr/internal/store"
)

const defaultDataDir = "/var/lib/clifr"

// globals are clifr's own options, given before or after the quoted command.
type globals struct {
	at, since, until, tz      string
	ats                       atList // every --at: diff takes two
	summary, changes, samples bool
	list                      bool // ss, netstat: every connection over a range
	every                     string
	everyMS                   int64
	number                    int
	json, interactive, plain  bool
	dataDir, style            string
	host, token, tlsCA        string
	tlsFP                     string // --tls-fingerprint: the expected certificate of --host on first use
	version, help, verbose    bool
	salvage                   bool // --salvage: read a damaged bundle without its bad files
	integrity                 bool // verify --integrity: check the data files, not the tools
}

func newFlags(g *globals, out io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("clifr", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() {}
	str := func(p *string, short, long, def string) {
		if short != "" {
			fs.StringVar(p, short, def, "")
		}
		fs.StringVar(p, long, def, "")
	}
	boolean := func(p *bool, short, long string) {
		if short != "" {
			fs.BoolVar(p, short, false, "")
		}
		fs.BoolVar(p, long, false, "")
	}
	fs.Var(&g.ats, "a", "")
	fs.Var(&g.ats, "at", "")
	str(&g.since, "S", "since", os.Getenv("CLIFR_SINCE"))
	str(&g.until, "U", "until", os.Getenv("CLIFR_UNTIL"))
	str(&g.tz, "T", "tz", os.Getenv("CLIFR_TZ"))
	boolean(&g.summary, "", "summary")
	boolean(&g.changes, "", "changes")
	boolean(&g.samples, "", "samples")
	boolean(&g.list, "", "list")
	str(&g.every, "e", "every", "")
	fs.IntVar(&g.number, "n", 0, "")
	fs.IntVar(&g.number, "number", 0, "")
	boolean(&g.json, "j", "json")
	boolean(&g.interactive, "I", "interactive")
	boolean(&g.plain, "", "plain")
	dd := os.Getenv("CLIFR_DATA_DIR")
	if dd == "" {
		dd = defaultDataDir
	}
	str(&g.dataDir, "D", "data-dir", dd)
	str(&g.style, "", "style", os.Getenv("CLIFR_STYLE"))
	str(&g.host, "H", "host", os.Getenv("CLIFR_HOST"))
	str(&g.token, "", "token", os.Getenv("CLIFR_TOKEN"))
	str(&g.tlsCA, "", "tls-ca", os.Getenv("CLIFR_TLS_CA"))
	str(&g.tlsFP, "", "tls-fingerprint", os.Getenv("CLIFR_TLS_FINGERPRINT"))
	boolean(&g.version, "v", "version")
	boolean(&g.help, "h", "help")
	fs.BoolVar(&g.verbose, "verbose", false, "") // verify: examples for every checkpoint
	fs.BoolVar(&g.salvage, "salvage", false, "")
	fs.BoolVar(&g.integrity, "integrity", false, "")
	return fs
}

func main() {
	clean := setupTemp()
	err := run(os.Args[1:])
	clean() // os.Exit skips deferred calls
	if err != nil {
		fmt.Fprintln(os.Stderr, "clifr:", err)
		var u usageError
		if errors.As(err, &u) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

type usageError struct{ error }

// subcommands are clifr's own commands; everything else names a recorded tool.
var subcommands = map[string]bool{"help": true, "info": true, "stats": true, "verify": true, "export": true,
	"diff": true, "list": true}

func run(args []string) error {
	var g globals
	fs := newFlags(&g, io.Discard)
	var words []string // the recorded command and its arguments
	sub := ""
	var subArgs []string
	for {
		if err := fs.Parse(args); err != nil {
			return usageError{fmt.Errorf("%v (see: clifr --help)", err)}
		}
		if fs.NArg() == 0 {
			break
		}
		first, rest := fs.Arg(0), fs.Args()[1:]
		switch {
		case sub != "":
			subArgs = append(subArgs, first)
			args = rest
			continue
		case words != nil:
			return usageError{fmt.Errorf("unexpected %q after the command; quote the whole command: \"ps aux\"", first)}
		case subcommands[first]:
			sub, args = first, rest
			continue
		case strings.ContainsAny(first, " \t"):
			w, err := splitWords(first)
			if err != nil {
				return usageError{err}
			}
			words, args = w, rest
			continue
		}
		// Unquoted: the command and everything after it, verbatim.
		words = append([]string{first}, rest...)
		break
	}
	switch {
	case g.version:
		fmt.Println("clifr", version())
		return nil
	case g.help && sub == "" && words == nil:
		fmt.Print(mainHelp)
		return nil
	case g.help && words != nil:
		return helpTool(words[0])
	case sub == "" && words == nil:
		fmt.Fprint(os.Stderr, mainHelp)
		return usageError{errors.New("no command given")}
	}
	if err := checkLater(&g); err != nil {
		return err
	}
	if g.style != "" {
		if _, ok := query.Styles[g.style]; !ok {
			names := slices.Sorted(maps.Keys(query.Styles))
			return usageError{fmt.Errorf("--style: unknown style %q (%s)", g.style, strings.Join(names, ", "))}
		}
		query.StyleOverride = g.style
	}
	if g.host != "" {
		dataDirGiven := os.Getenv("CLIFR_DATA_DIR") != ""
		fs.Visit(func(f *flag.Flag) { dataDirGiven = dataDirGiven || f.Name == "D" || f.Name == "data-dir" })
		if dataDirGiven {
			return usageError{errors.New("--host and --data-dir: give one (a remote host, or a local recording or bundle)")}
		}
	}
	defer cleanupRemote()
	cleanup, err := openBundle(&g)
	if err != nil {
		return err
	}
	defer cleanup()
	if sub != "" {
		return runSub(&g, sub, subArgs)
	}
	return runTool(&g, words)
}

// openBundle lets --data-dir name a bundle (clifrd bundle): it is unpacked
// into a temporary directory, removed when clifr ends.
func openBundle(g *globals) (func(), error) {
	st, err := os.Stat(g.dataDir)
	if err != nil || !st.Mode().IsRegular() {
		return func() {}, nil
	}
	f, err := os.Open(g.dataDir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tmp, err := os.MkdirTemp("", "clifr-bundle-")
	if err != nil {
		return nil, err
	}
	var dir string
	if g.salvage {
		var bad []string
		var m *bundle.Manifest
		dir, m, bad, err = bundle.Salvage(f, tmp, st.Size())
		if err == nil && m == nil {
			fmt.Fprintln(os.Stderr, "clifr: --salvage: no bundle.json (the bundle was cut short): the files that arrived whole are read, unverified")
		}
		for _, p := range bad {
			fmt.Fprintln(os.Stderr, "clifr: --salvage: left out "+salvageNote(p))
		}
	} else {
		dir, _, err = bundle.Extract(f, tmp, st.Size())
	}
	if err != nil {
		os.RemoveAll(tmp)
		return nil, fmt.Errorf("%s: %w", g.dataDir, err)
	}
	g.dataDir = dir
	return func() { os.RemoveAll(tmp) }, nil
}

// salvageNote names a bundle file left out (data/DIR/DAY/NAME) and the
// times that lack its rows (at the default flush interval).
func salvageNote(p string) string {
	parts := strings.Split(p, "/")
	note := p + ", damaged or missing"
	if len(parts) == 4 && parts[0] == "data" {
		if t := pqstore.TableOf(parts[1]); t != "" {
			note += " (table " + t + ")"
		}
		if lo, hi, ok := pqstore.FileSpan(p, 5*time.Minute); ok {
			const f = "2006-01-02 15:04"
			note += ": results lack its rows, from about " + time.UnixMilli(lo).Format(f) + " to " + time.UnixMilli(hi).Format(f)
		} else if parts[2] == "open" {
			note += ": results lack the rows still open in that run"
		}
	}
	return note
}

// checkLater rejects options of features that are not in this release.
func checkLater(g *globals) error {
	switch {
	case g.host == "" && g.tlsFP != "":
		return usageError{errors.New("--tls-fingerprint is for --host")}
	case g.host == "" && g.tlsCA != "":
		return usageError{errors.New("--tls-ca is for --host")}
	case g.tlsCA != "" && g.tlsFP != "":
		return usageError{errors.New("--tls-ca and --tls-fingerprint: give one (a CA-signed certificate, or clifrd's own pinned)")}
	}
	return nil
}

// releaseVersion is set by the packages' build (-ldflags -X main.releaseVersion=...).
var releaseVersion string

func version() string {
	if releaseVersion != "" {
		return releaseVersion
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		rev, dirty := "", ""
		for _, s := range bi.Settings {
			switch {
			case s.Key == "vcs.revision" && len(s.Value) >= 12:
				rev = s.Value[:12]
			case s.Key == "vcs.modified" && s.Value == "true":
				dirty = "-dirty"
			}
		}
		if rev != "" {
			return rev + dirty
		}
		return bi.Main.Version
	}
	return "unknown"
}

// resolve turns --at/--since/--until into a window and prints it on stderr.
func resolve(g *globals, need bool) (query.Window, error) {
	switch len(g.ats) {
	case 0:
	case 1:
		g.at = g.ats[0]
	default:
		return query.Window{}, usageError{errors.New("--at given more than once; to compare two moments: clifr diff --at A --at B \"COMMAND\"")}
	}
	if g.tz != "" {
		loc, err := time.LoadLocation(g.tz)
		if err != nil {
			return query.Window{}, usageError{fmt.Errorf("--tz: %v", err)}
		}
		time.Local = loc
	}
	now := time.Now()
	parse := func(name, s string) (int64, error) {
		t, err := query.ParseWhen(s, now)
		if err != nil {
			return 0, usageError{fmt.Errorf("--%s: %v", name, err)}
		}
		return t.UnixMilli(), nil
	}
	var w query.Window
	var err error
	switch {
	case g.at != "" && g.since != "":
		return w, usageError{errors.New("use either --at or --since/--until")}
	case g.until != "" && g.since == "":
		return w, usageError{errors.New("--until needs --since")}
	case g.at != "":
		if w.At, err = parse("at", g.at); err != nil {
			return w, err
		}
		query.Header("time: at %s %s", query.FormatMS(w.At), query.ZoneLabel(time.UnixMilli(w.At)))
	case g.since != "":
		if w.From, err = parse("since", g.since); err != nil {
			return w, err
		}
		w.To = now.UnixMilli()
		if g.until != "" {
			if w.To, err = parse("until", g.until); err != nil {
				return w, err
			}
		}
		if w.To <= w.From {
			return w, usageError{fmt.Errorf("--until (%s) is not after --since (%s)", query.FormatMS(w.To), query.FormatMS(w.From))}
		}
		query.Header("time: %s .. %s %s", query.FormatMS(w.From), query.FormatMS(w.To), query.ZoneLabel(time.UnixMilli(w.From)))
	case need:
		return w, usageError{errors.New("--at or --since is required")}
	default:
		w.From, w.To = 0, now.UnixMilli() // the whole recording
	}
	if !w.IsRange() && (g.summary || g.changes || g.samples || g.list || g.every != "" || g.number != 0) {
		return w, usageError{errors.New("--summary, --changes, --samples, --list, --every and --number need a range (--since)")}
	}
	if btoi(g.summary)+btoi(g.changes)+btoi(g.samples)+btoi(g.list) > 1 {
		return w, usageError{errors.New("use one of --summary, --changes, --samples, --list")}
	}
	if g.every != "" {
		d, err := query.ParseDuration(g.every)
		if err != nil || d <= 0 {
			return w, usageError{fmt.Errorf("--every: bad duration %q", g.every)}
		}
		g.everyMS = d.Milliseconds()
	}
	return w, nil
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func openDB(g *globals) (*store.DB, error) { return openWindow(g, duck.Window{}) }

// openWindow opens the recording with the TCP tables limited to w (the zero
// Window: everything).
func openWindow(g *globals, w duck.Window) (*store.DB, error) {
	if os.Getenv("CLIFR_FULL_LOAD") != "" { // check: the window must not change any answer
		w = duck.Window{}
	}
	dir := g.dataDir
	if g.host != "" {
		// The files the window needs, from the remote host (cached); the
		// zero window: the whole recording.
		d, err := fetchWindow(g, w.From, w.To)
		if err != nil {
			return nil, err
		}
		dir = d
	}
	return duck.OpenWindow(dir, w)
}

func runTool(g *globals, words []string) error { return runToolAt(g, words, nil) }

// runToolAt runs a command; with diff set (two --at values) it compares the
// two moments instead (clifr diff).
func runToolAt(g *globals, words []string, diff []string) error {
	t, ok := tools[words[0]]
	if !ok {
		if later[words[0]] != "" {
			return fmt.Errorf("%s: %s", words[0], later[words[0]])
		}
		return usageError{fmt.Errorf("%q is not a supported command; supported: %s (see: clifr help)", words[0], strings.Join(toolOrder, ", "))}
	}
	p, err := parseOpts(t.name, t.opts, words[1:])
	if err != nil {
		for _, a := range words[1:] {
			if misplaced(a) {
				return usageError{fmt.Errorf("%v\n(clifr's own options such as %s go before the command, or quote the command: clifr --at T \"ps aux\")", err, a)}
			}
		}
		return usageError{err}
	}
	if g.list && t.name != "ss" && t.name != "netstat" {
		return usageError{fmt.Errorf("--list is for ss and netstat (every TCP connection over a range); %s has no connection list", t.name)}
	}
	c := &runCtx{g: g}
	if diff != nil {
		if !t.diff {
			return usageError{fmt.Errorf("diff: %s has no rows to compare (it is for %s)", t.name, diffCommands)}
		}
		for _, a := range diff {
			g.ats = atList{a}
			w, err := resolve(g, true)
			if err != nil {
				return err
			}
			c.diffAt = append(c.diffAt, w.At)
		}
		if c.diffAt[1] <= c.diffAt[0] {
			return usageError{errors.New("diff: the second --at must be after the first")}
		}
		c.w = query.Window{At: c.diffAt[1]}
	} else {
		w, err := resolve(g, t.window)
		if err != nil {
			return err
		}
		c.w = w
	}
	exec, err := t.prepare(p, c)
	if err != nil {
		return usageError{err}
	}
	var win duck.Window
	switch {
	case c.diffAt != nil:
		win = duck.Window{From: c.diffAt[0], To: c.diffAt[1]}
	case !c.w.IsRange():
		win = duck.Window{From: c.w.At, To: c.w.At}
	case c.w.From > 0:
		win = duck.Window{From: c.w.From, To: c.w.To}
	}
	if c.db, err = openWindow(g, win); err != nil {
		return err
	}
	defer c.db.Close()
	// User names as the recorded host had them (not this machine's).
	at := c.w.At
	if c.w.IsRange() {
		at = c.w.To
	}
	if _, err := query.LoadUsers(c.db, at); err != nil {
		return err
	}
	// Which host this is, and whether the moment is past the data on disk.
	query.RecordingHeaders(c.db, c.w, g.host != "")
	// The commands whose output differs between tool versions say which
	// version's they follow, unless it is the current one.
	if styled[t.name] {
		at := c.w.At
		if c.w.IsRange() {
			at = c.w.To
		}
		if note := query.StyleNote(c.db, at); note != "" {
			query.Header("%s", note)
		}
	}
	if c.w.IsRange() {
		if note := query.LossNote(c.db, c.w.From, c.w.To); note != "" {
			query.Header("%s", note)
		}
	}
	// A moment the recording has nothing for is an error, not an empty or
	// stale answer.
	for _, at := range append([]int64{c.w.At}, c.diffAt...) {
		if at != 0 {
			if err := query.Covered(c.db, at); err != nil {
				return err
			}
		}
	}
	return exec()
}

// styled are the commands ToolStyle changes.
var styled = map[string]bool{"free": true, "top": true, "df": true, "lsof": true}

// misplaced reports a clifr option given after an unquoted command.
func misplaced(a string) bool {
	name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
	if !strings.HasPrefix(a, "--") {
		return false
	}
	switch name {
	case "at", "since", "until", "tz", "data-dir", "style", "json", "summary", "changes", "samples", "list", "every", "number":
		return true
	}
	return false
}

// later names the commands of the spec that are not built yet.
var later = map[string]string{}

func runSub(g *globals, sub string, args []string) error {
	switch sub {
	case "help":
		if len(args) == 0 {
			fmt.Print(mainHelp)
			return nil
		}
		return helpTool(args[0])
	case "list":
		return usageError{errors.New(`"clifr list" is not available; "clifr help" lists the commands and "clifr help COMMAND" their options`)}
	case "diff":
		if len(g.ats) != 2 || g.since != "" {
			return usageError{errors.New(`usage: clifr diff --at A --at B "COMMAND [ARGS]"`)}
		}
		words := args
		if len(args) == 1 && strings.ContainsAny(args[0], " \t") {
			var err error
			if words, err = splitWords(args[0]); err != nil {
				return usageError{err}
			}
		}
		if len(words) == 0 {
			return usageError{errors.New(`usage: clifr diff --at A --at B "COMMAND [ARGS]"`)}
		}
		return runToolAt(g, words, append([]string(nil), g.ats...))
	}
	if len(args) > 0 && sub != "export" {
		return usageError{fmt.Errorf("%s: unexpected argument %q", sub, args[0])}
	}
	if g.integrity {
		if sub != "verify" {
			return usageError{errors.New("--integrity is for clifr verify")}
		}
		if g.host != "" {
			return usageError{errors.New("--integrity checks a local recording or bundle: run it on the host itself (clifr verify --integrity)")}
		}
		return cmdIntegrity(g)
	}
	db, err := openDB(g)
	if err != nil {
		return err
	}
	defer db.Close()
	switch sub {
	case "info", "stats":
		return cmdInfo(g, db)
	case "verify":
		return cmdVerify(g, db)
	case "export":
		if len(args) != 1 {
			return usageError{errors.New("usage: clifr export TABLE")}
		}
		return cmdExport(db, args[0])
	}
	return nil
}

// atList collects --at, which diff takes twice.
type atList []string

func (l *atList) String() string { return strings.Join(*l, ", ") }

func (l *atList) Set(v string) error {
	*l = append(*l, v)
	return nil
}
