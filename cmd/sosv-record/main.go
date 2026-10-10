// Command sosv-record is the sosv recorder: it stores processes, sockets and
// open files as time ranges, as Parquet files in a data directory (the
// default) or in a v1 SQLite database, or both for side-by-side comparisons.
// Query the result with the sosv command. Pure Go, statically linked.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sosv/internal/recorder"
)

const defaultDataDir = "/var/lib/sosv/data"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sosv-record:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 1 && args[0] == "--oom-hog" { // helpers of --test-ebpf
		oomHog()
	}
	if len(args) == 1 && args[0] == "--thread-exit" {
		threadExit()
	}
	fs := flag.NewFlagSet("sosv-record", flag.ExitOnError)
	var c recorder.Config
	fs.StringVar(&c.DataDir, "data-dir", defaultDataDir, `Parquet data directory ("" for none)`)
	fs.StringVar(&c.DB, "db", "", "also (or, with --data-dir \"\", only) write this v1 SQLite database")
	fs.DurationVar(&c.Interval, "interval", 30*time.Second, "process and socket sample interval")
	fs.DurationVar(&c.FDInterval, "fd-interval", 120*time.Second, "full open-file walk interval")
	fs.DurationVar(&c.Duration, "duration", 0, "stop after this long (0 = until SIGINT/SIGTERM)")
	fs.StringVar(&c.ProcRoot, "proc-root", "/proc", "proc filesystem root (for fixtures)")
	budget := fs.String("cpu-budget", "2%", "recorder CPU budget, percent of one core")
	fs.DurationVar(&c.BudgetWindow, "budget-window", 5*time.Minute, "CPU history the budget guard averages over")
	fs.DurationVar(&c.VerifyEvery, "verify-every", 0, "also save real ps/ss/lsof output this often")
	fs.DurationVar(&c.Parquet.FlushInterval, "flush-interval", 5*time.Minute, "write buffered rows to Parquet this often (a crash loses at most this much)")
	fs.DurationVar(&c.Parquet.Retention, "retention", 72*time.Hour, "delete Parquet data older than this (0 = keep)")
	fs.StringVar(&c.Events, "events", "auto", "process events: auto (eBPF, else the proc connector), ebpf, proc_connector or none")
	fs.StringVar(&c.FDMode, "fd-mode", "held", "open files: held (fds held across two walks, and deleted files) or all (v1: every fd)")
	fs.IntVar(&c.FDFullEvery, "fd-full-every", 5, "held mode: read every process's fds on every n-th walk (others only when their fd count changed)")
	fs.StringVar(&c.TCP, "tcp", "auto", "TCP: auto (eBPF events and keyframes, else v1 sampling), ebpf, or sample (v1: a socket dump every interval)")
	fs.DurationVar(&c.KeyframeInterval, "keyframe-interval", 5*time.Minute, "with TCP events: full socket dump (queues, UDP, reconciliation) this often")
	forcePerf := fs.Bool("ebpf-force-perf", false, "use perf event arrays even if the kernel has a BPF ring buffer (to test the fallback)")
	fs.BoolVar(&c.EBPF.ForceClassicFork, "ebpf-classic-fork", false, "use the classic fork, exec and exit tracepoints even if tp_btf works (to test the fallback)")
	fs.BoolVar(&c.TCPBPF.ForceKprobes, "ebpf-kprobes", false, "use kprobes and the classic state tracepoint even if fentry/fexit and tp_btf work (to test the fallback)")
	testMode := fs.Bool("test-ebpf", false, "load the eBPF programs, trigger every event type, report and exit (root)")
	maxSize := fs.String("max-size", "0", "size cap for the data directory, e.g. 2G or 500M (0 = none); the oldest hours go first")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	c.EBPF.ForcePerf, c.TCPBPF.ForcePerf = *forcePerf, *forcePerf
	if *testMode {
		return testEBPF(c.EBPF, c.TCPBPF)
	}
	if _, err := fmt.Sscanf(strings.TrimSuffix(*budget, "%"), "%g", &c.CPUBudget); err != nil {
		return fmt.Errorf("bad --cpu-budget %q", *budget)
	}
	c.CPUBudget /= 100
	var err error
	if c.Parquet.MaxBytes, err = parseSize(*maxSize); err != nil {
		return err
	}
	if c.Interval < time.Second || c.FDInterval < c.Interval {
		return errors.New("need --interval >= 1s and --fd-interval >= --interval")
	}
	logger := log.New(os.Stderr, "sosv-record: ", log.LstdFlags)
	r, err := recorder.New(c, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var to []string
	if c.DataDir != "" {
		to = append(to, c.DataDir+" (Parquet, flushed every "+c.Parquet.FlushInterval.String()+")")
	}
	if c.DB != "" {
		to = append(to, c.DB+" (SQLite)")
	}
	logger.Printf("recording to %s every %s (fd walk every %s)", strings.Join(to, " and "), c.Interval, c.FDInterval)
	return r.Run(ctx)
}

// parseSize parses "0", "1500000", "500M", "2G" (powers of 1024).
func parseSize(s string) (int64, error) {
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "K"):
		mult, s = 1<<10, strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, strings.TrimSuffix(s, "G")
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return int64(n * float64(mult)), nil
}
