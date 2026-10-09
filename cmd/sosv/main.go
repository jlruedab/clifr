// Command sosv queries what sosv-record recorded: it reconstructs ps/lsof/ss
// output and process lifetimes for a past moment or range. It reads a Parquet
// data directory through DuckDB (--data-dir, the default) or a v1 SQLite
// database (--db).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"sosv/internal/duck"
	"sosv/internal/query"
	"sosv/internal/store"
	"sosv/internal/verify"
)

const defaultDataDir = "/var/lib/sosv/data"

const usage = `usage: sosv <command> [flags]

commands (record with sosv-record):
  ps       sosv ps aux --at T | --start_from A --end_at B
  lsof     sosv lsof [-p PID] [-i] --at T | --start_from A --end_at B
  ss       sosv ss -tanp [filter] --at T | --start_from A --end_at B
           filter: dst IP[/len][:port], src ..., dport = :N, sport = :N, joined with "and"
  life     sosv life [--name REGEX] [--start_from A --end_at B]
  oom      sosv oom [--start_from A --end_at B]: OOM kills with the top processes by RSS
  verify   compare saved real ps/ss/lsof output (record --verify-every) with reconstructions
  stats    recorder cost and database summary

data: --data-dir DIR (Parquet, default ` + defaultDataDir + `) or --db FILE (v1 SQLite).
times are local: "YYYY-MM-DD HH:MM:SS"; informational headers go to stderr.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "record":
		err = errors.New("recording moved to the sosv-record command")
	case "ps":
		err = cmdPS(args)
	case "ss":
		err = cmdSS(args)
	case "lsof":
		err = cmdLsof(args)
	case "life":
		err = cmdLife(args)
	case "oom":
		err = cmdOOM(args)
	case "verify":
		err = cmdVerify(args)
	case "stats":
		err = cmdStats(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		err = fmt.Errorf("unknown command %q\n%s", cmd, usage)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sosv:", err)
		os.Exit(1)
	}
}

// parse parses flags that may appear before, between or after positional
// arguments, and returns the positional ones.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// queryFlags are shared by all query commands.
type queryFlags struct {
	db, dataDir  string
	at, from, to string
	json         bool
}

func (q *queryFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&q.dataDir, "data-dir", defaultDataDir, "Parquet data directory written by sosv-record")
	fs.StringVar(&q.db, "db", "", "read this v1 SQLite database instead of --data-dir")
	fs.StringVar(&q.at, "at", "", `point in time "YYYY-MM-DD HH:MM:SS"`)
	fs.StringVar(&q.from, "start_from", "", "range start")
	fs.StringVar(&q.to, "end_at", "", "range end (default: now)")
	fs.BoolVar(&q.json, "json", false, "JSON output")
}

func (q *queryFlags) window(required bool) (query.Window, error) {
	var w query.Window
	var err error
	switch {
	case q.at != "" && q.from != "":
		return w, errors.New("use either --at or --start_from/--end_at")
	case q.at != "":
		w.At, err = query.ParseTime(q.at)
	case q.from != "":
		if w.From, err = query.ParseTime(q.from); err != nil {
			return w, err
		}
		w.To = time.Now().UnixMilli()
		if q.to != "" {
			w.To, err = query.ParseTime(q.to)
		}
	case required:
		return w, errors.New("--at or --start_from is required")
	default:
		w.From, w.To = 0, time.Now().UnixMilli()
	}
	return w, err
}

func (q *queryFlags) open() (*store.DB, error) {
	if q.db != "" {
		return store.Open(q.db, true)
	}
	return duck.Open(q.dataDir)
}

func cmdPS(args []string) error {
	fs := flag.NewFlagSet("ps", flag.ExitOnError)
	var q queryFlags
	q.register(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || pos[0] != "aux" {
		return errors.New("only `sosv ps aux` is supported")
	}
	w, err := q.window(true)
	if err != nil {
		return err
	}
	db, err := q.open()
	if err != nil {
		return err
	}
	defer db.Close()
	if w.IsRange() {
		rows, err := query.PSRange(db, w.From, w.To)
		if err != nil {
			return err
		}
		query.Header("processes between %s and %s, identical commands collapsed (SRC ev: only seen through exec/exit events)",
			query.FormatMS(w.From), query.FormatMS(w.To))
		if q.json {
			return query.PrintJSON(os.Stdout, rows)
		}
		query.PrintPSRange(os.Stdout, rows)
		return nil
	}
	rows, s, err := query.PSAt(db, w.At)
	if err != nil {
		return err
	}
	query.Header("ps aux at %s, reconstructed from sample at %s (%d processes)",
		query.FormatMS(w.At), query.FormatMS(s), len(rows))
	// OOM kills soon after T are not in the sample; point them out.
	if kills, err := query.OOMKills(db, s, w.At+query.IntervalMS(db), 0); err == nil {
		for _, k := range kills {
			query.Header("OOM kill at %s: pid %d, RSS at the kill %d kB (%s); see sosv oom", query.FormatMS(k.TS), k.PID, k.RSSKB, k.Command)
		}
	}
	if q.json {
		return query.PrintPSJSON(os.Stdout, rows)
	}
	query.PrintPS(os.Stdout, rows)
	return nil
}

func cmdStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	var q queryFlags
	q.register(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	db, err := q.open()
	if err != nil {
		return err
	}
	defer db.Close()
	s, err := query.ComputeStats(db)
	if err != nil {
		return err
	}
	if q.json {
		return query.PrintStatsJSON(os.Stdout, s)
	}
	query.PrintStats(os.Stdout, s)
	return nil
}

func cmdSS(args []string) error {
	// Pull out ss-style short options (-tanp, -uanp); t/u choose the protocol,
	// the others are always on.
	proto := "tcp"
	var rest []string
	for _, a := range args {
		if len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.Trim(a[1:], "tuanpl46") == "" {
			if strings.Contains(a, "u") {
				proto = "udp"
			}
			continue
		}
		rest = append(rest, a)
	}
	fs := flag.NewFlagSet("ss", flag.ExitOnError)
	var q queryFlags
	q.register(fs)
	pos, err := parse(fs, rest)
	if err != nil {
		return err
	}
	filter, err := query.ParseSockFilter(pos)
	if err != nil {
		return err
	}
	w, err := q.window(true)
	if err != nil {
		return err
	}
	db, err := q.open()
	if err != nil {
		return err
	}
	defer db.Close()
	if query.TCPFromEvents(db) {
		return ssEvents(db, q, w, proto, filter)
	}
	if w.IsRange() {
		groups, err := query.SocketsInRange(db, w.From, w.To, proto, filter)
		if err != nil {
			return err
		}
		query.Header("%s sockets by process, %s .. %s", proto, query.FormatMS(w.From), query.FormatMS(w.To))
		if q.json {
			return query.PrintJSON(os.Stdout, groups)
		}
		query.PrintSSGroups(os.Stdout, groups)
		return nil
	}
	s, err := query.SnapshotAt(db, w.At, false)
	if err != nil {
		return err
	}
	rows, err := query.SocketsAt(db, s, proto, filter)
	if err != nil {
		return err
	}
	query.Header("ss at %s, reconstructed from sample at %s (%d sockets)",
		query.FormatMS(w.At), query.FormatMS(s), len(rows))
	if q.json {
		return query.PrintJSON(os.Stdout, rows)
	}
	query.PrintSS(os.Stdout, rows)
	return nil
}

func cmdLsof(args []string) error {
	fs := flag.NewFlagSet("lsof", flag.ExitOnError)
	var q queryFlags
	q.register(fs)
	var o query.LsofOptions
	fs.IntVar(&o.PID, "p", 0, "only this PID")
	fs.BoolVar(&o.InetOnly, "i", false, "only internet sockets")
	fs.Bool("n", true, "accepted for compatibility (addresses are never resolved)")
	fs.Bool("P", true, "accepted for compatibility (ports are never resolved)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	w, err := q.window(true)
	if err != nil {
		return err
	}
	db, err := q.open()
	if err != nil {
		return err
	}
	defer db.Close()
	if w.IsRange() {
		rows, err := query.LsofRange(db, w.From, w.To, o)
		if err != nil {
			return err
		}
		query.Header("files held between %s and %s (%d)", query.FormatMS(w.From), query.FormatMS(w.To), len(rows))
		if q.json {
			return query.PrintJSON(os.Stdout, rows)
		}
		query.PrintLsof(os.Stdout, rows, true)
		return nil
	}
	rows, s, sfd, err := query.LsofAt(db, w.At, o)
	if err != nil {
		return err
	}
	if query.TCPFromEvents(db) {
		query.Header("lsof at %s: files from the full fd walk at %s (sampled); TCP sockets exact (events); UDP from the keyframe (%d rows)",
			query.FormatMS(w.At), query.FormatMS(sfd), len(rows))
	} else {
		query.Header("lsof at %s: files from full fd walk at %s, inet sockets from sample at %s (%d rows)",
			query.FormatMS(w.At), query.FormatMS(sfd), query.FormatMS(s), len(rows))
	}
	if q.json {
		return query.PrintJSON(os.Stdout, rows)
	}
	query.PrintLsof(os.Stdout, rows, false)
	return nil
}

func cmdLife(args []string) error {
	fs := flag.NewFlagSet("life", flag.ExitOnError)
	var q queryFlags
	q.register(fs)
	name := fs.String("name", "", "regular expression matched against the command line")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if q.at != "" {
		q.from, q.to, q.at = q.at, q.at, ""
	}
	w, err := q.window(false)
	if err != nil {
		return err
	}
	var re *regexp.Regexp
	if *name != "" {
		if re, err = regexp.Compile(*name); err != nil {
			return err
		}
	}
	db, err := q.open()
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := query.Life(db, w.From, w.To, re)
	if err != nil {
		return err
	}
	query.Header("%d processes; END \">t\" means it exited after t and before the next sample", len(rows))
	if q.json {
		return query.PrintJSON(os.Stdout, rows)
	}
	query.PrintLife(os.Stdout, rows)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	var q queryFlags
	q.register(fs)
	verbose := fs.Bool("v", false, "show examples for every checkpoint")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	db, err := q.open()
	if err != nil {
		return err
	}
	defer db.Close()
	rep, err := verify.Run(db)
	if err != nil {
		return err
	}
	if q.json {
		return query.PrintJSON(os.Stdout, rep)
	}
	verify.Print(os.Stdout, rep, *verbose)
	return nil
}

func cmdOOM(args []string) error {
	fs := flag.NewFlagSet("oom", flag.ExitOnError)
	var q queryFlags
	q.register(fs)
	top := fs.Int("top", 10, "processes to list by RSS for each kill")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	w, err := q.window(false)
	if err != nil {
		return err
	}
	if !w.IsRange() {
		w.From, w.To = w.At-60_000, w.At+60_000
	}
	db, err := q.open()
	if err != nil {
		return err
	}
	defer db.Close()
	kills, err := query.OOMKills(db, w.From, w.To, *top)
	if err != nil {
		return err
	}
	query.Header("OOM kills %s .. %s; RSS of the others: their last sample at or before the kill (sampled, not exact)",
		query.FormatMS(w.From), query.FormatMS(w.To))
	if q.json {
		return query.PrintJSON(os.Stdout, kills)
	}
	query.PrintOOM(os.Stdout, kills)
	return nil
}

// ssEvents: ss from TCP events (v2 recordings).
func ssEvents(db *store.DB, q queryFlags, w query.Window, proto string, filter query.SockFilter) error {
	if w.IsRange() {
		if proto != "tcp" {
			return errors.New("range mode is for TCP (UDP is recorded at keyframes only)")
		}
		groups, err := query.ConnsInRange(db, w.From, w.To, filter)
		if err != nil {
			return err
		}
		query.Header("TCP connections by process, %s .. %s, from events (every connection, however short)",
			query.FormatMS(w.From), query.FormatMS(w.To))
		if q.json {
			return query.PrintJSON(os.Stdout, groups)
		}
		query.PrintSSGroups(os.Stdout, groups)
		return nil
	}
	rows, kf, err := query.ConnsAt(db, w.At, proto, filter)
	if err != nil {
		return err
	}
	if proto == "tcp" {
		tw := "time-wait end exact"
		if !query.TimeWaitExact(db) {
			tw = "time-wait shown until 60 s after the close (the kernel ends it 0-5 s later)"
		}
		query.Header("ss at %s (%d sockets): connections, states and owners exact (events); Recv-Q/Send-Q sampled, from the keyframe at %s; %s",
			query.FormatMS(w.At), len(rows), query.FormatMS(kf), tw)
	} else {
		query.Header("%s sockets at %s from the keyframe at %s (UDP is recorded at keyframes only)", proto, query.FormatMS(w.At), query.FormatMS(kf))
	}
	if q.json {
		return query.PrintJSON(os.Stdout, rows)
	}
	query.PrintSS(os.Stdout, rows)
	return nil
}
