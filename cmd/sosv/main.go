// Command sosv is a Linux flight recorder: `sosv record` stores processes,
// sockets and open files as time ranges; the other subcommands reconstruct
// ps/lsof/ss output and process lifetimes for a past moment or range.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sosv/internal/query"
	"sosv/internal/recorder"
	"sosv/internal/store"
)

const defaultDB = "/var/lib/sosv/sosv.db"

const usage = `usage: sosv <command> [flags]

commands:
  record   record processes, sockets and open files (root)
  ps       sosv ps aux --at T | --start_from A --end_at B
  stats    recorder cost and database summary

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
		err = cmdRecord(args)
	case "ps":
		err = cmdPS(args)
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
	db, at, from, to string
	json             bool
}

func (q *queryFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&q.db, "db", defaultDB, "database file")
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
	return store.Open(q.db, true)
}

func cmdRecord(args []string) error {
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	var c recorder.Config
	fs.StringVar(&c.DB, "db", defaultDB, "database file")
	fs.DurationVar(&c.Interval, "interval", 30*time.Second, "process and socket sample interval")
	fs.DurationVar(&c.FDInterval, "fd-interval", 120*time.Second, "full open-file walk interval")
	fs.DurationVar(&c.Duration, "duration", 0, "stop after this long (0 = until SIGINT/SIGTERM)")
	fs.StringVar(&c.ProcRoot, "proc-root", "/proc", "proc filesystem root (for fixtures)")
	budget := fs.String("cpu-budget", "2%", "recorder CPU budget, percent of one core")
	fs.DurationVar(&c.VerifyEvery, "verify-every", 0, "also save real ps/ss/lsof output this often")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if _, err := fmt.Sscanf(strings.TrimSuffix(*budget, "%"), "%g", &c.CPUBudget); err != nil {
		return fmt.Errorf("bad --cpu-budget %q", *budget)
	}
	c.CPUBudget /= 100
	if c.Interval < time.Second || c.FDInterval < c.Interval {
		return errors.New("need --interval >= 1s and --fd-interval >= --interval")
	}
	logger := log.New(os.Stderr, "sosv: ", log.LstdFlags)
	r, err := recorder.New(c, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Printf("recording to %s every %s (fd walk every %s)", c.DB, c.Interval, c.FDInterval)
	return r.Run(ctx)
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
		return errors.New("range mode arrives in milestone 4")
	}
	rows, s, err := query.PSAt(db, w.At)
	if err != nil {
		return err
	}
	query.Header("ps aux at %s, reconstructed from sample at %s (%d processes)",
		query.FormatMS(w.At), query.FormatMS(s), len(rows))
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
