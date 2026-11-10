// Command clifrd is the clifr recorder: it stores processes, sockets and
// open files as time ranges, as Parquet files in a data directory.
// Query the result with the clifr command. Pure Go, statically linked.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"clifr/internal/metrics"
	"clifr/internal/procfs"
	"clifr/internal/recorder"
	"clifr/internal/remote"
	"clifr/internal/webconfig"
)

const defaultDataDir = "/var/lib/clifr"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "clifrd:", err)
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
	if len(args) > 0 && args[0] == "bundle" {
		return bundleCmd(args[1:])
	}
	if len(args) > 0 && args[0] == "token" {
		return tokenCmd(args[1:])
	}
	doDoctor := len(args) > 0 && args[0] == "doctor"
	if doDoctor {
		args = args[1:]
	}
	fs := flag.NewFlagSet("clifrd", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "clifrd records processes, sockets, open files and system counters for clifr.\n\n"+
			"Usage:\n  clifrd [OPTIONS]          record (normally run by systemd)\n"+
			"  clifrd doctor [OPTIONS]   check what this system supports and show the recording level\n"+
			"  clifrd bundle [OPTIONS]   write the recording, or a window of it, as one file (clifrd bundle --help)\n"+
			"  clifrd token new|list|revoke   access tokens for --serve (clifrd token --help)\n\nOptions:\n")
		fs.PrintDefaults()
	}
	c := recorder.Config{Version: version()}
	configPath := fs.String("config", defaultConfig, "configuration file (settings in it apply unless given as flags)")
	fs.StringVar(configPath, "C", defaultConfig, "short for --config")
	fs.StringVar(&c.DataDir, "data-dir", defaultDataDir, "Parquet data directory")
	fs.StringVar(&c.DataDir, "D", defaultDataDir, "short for --data-dir")
	logLevel := fs.String("log-level", "info", "error, warn, info or debug")
	showVersion := fs.Bool("version", false, "show the version and exit")
	fs.BoolVar(showVersion, "v", false, "short for --version")
	fs.DurationVar(&c.Interval, "interval", 30*time.Second, "process and socket sample interval")
	fs.DurationVar(&c.SysInterval, "sys-interval", 10*time.Second, "system-wide counters (vmstat, mpstat, iostat, free, uptime), at most --interval")
	fs.DurationVar(&c.FDInterval, "fd-interval", 120*time.Second, "full open-file walk interval")
	fs.Var((*stringList)(&c.Redact), "redact", "regular expression to mask in command lines before they are stored (repeatable; with capture groups only the groups are masked)")
	fs.BoolVar(&c.ProcIO, "proc-io", true, "read each process's I/O counters (/proc/<pid>/io) when it used CPU, and at fd walks")
	fs.DurationVar(&c.Duration, "duration", 0, "stop after this long (0 = until SIGINT/SIGTERM)")
	fs.StringVar(&c.ProcRoot, "proc-root", "/proc", "proc filesystem root (for fixtures)")
	budget := fs.String("cpu-budget", "2%", "recorder CPU budget, percent of one core")
	fs.DurationVar(&c.BudgetWindow, "budget-window", 5*time.Minute, "CPU history the budget guard averages over")
	fs.DurationVar(&c.VerifyEvery, "verify-every", 0, "also save real ps/ss/lsof and uptime/vmstat/mpstat/iostat output this often")
	fs.DurationVar(&c.Parquet.FlushInterval, "flush-interval", 5*time.Minute, "write buffered rows to Parquet this often (a crash loses at most this much)")
	fs.IntVar(&c.Parquet.FlushRows, "flush-rows", 400_000, "also write them once this many rows are buffered: lowers the heap's peak under load, for more and smaller files (0 = only by time)")
	fs.DurationVar(&c.Parquet.Retention, "retention", 72*time.Hour, "delete Parquet data older than this (0 = keep)")
	fs.StringVar(&c.Events, "events", "auto", "process events: auto (eBPF, else the proc connector), ebpf, proc_connector or none")
	fs.StringVar(&c.FDMode, "fd-mode", "held", "open files: held (fds held across two walks, and deleted files) or all (v1: every fd)")
	fs.IntVar(&c.MaxFilesPerProcess, "max-files-per-process", 131072, "open files tracked per process: a process holding more is not tracked (a guard event names it; TCP connections and owners come from events and stay; 0 = no limit)")
	fs.IntVar(&c.FDFullEvery, "fd-full-every", 5, "held mode: read every process's fds on every n-th walk (others only when their fd count changed)")
	fs.StringVar(&c.TCP, "tcp", "auto", "TCP: auto (eBPF events and keyframes, else v1 sampling), ebpf, or sample (v1: a socket dump every interval)")
	fs.DurationVar(&c.KeyframeInterval, "keyframe-interval", 5*time.Minute, "with TCP events: full socket dump (queues, UDP, reconciliation) this often")
	forcePerf := fs.Bool("ebpf-force-perf", false, "use perf event arrays even if the kernel has a BPF ring buffer (to test the fallback)")
	fs.BoolVar(&c.EBPF.ForceClassicFork, "ebpf-classic-fork", false, "use the classic fork, exec and exit tracepoints even if tp_btf works (to test the fallback)")
	fs.BoolVar(&c.TCPBPF.ForceKprobes, "ebpf-kprobes", false, "use kprobes and the classic state tracepoint even if fentry/fexit and tp_btf work (to test the fallback)")
	bpfStats := fs.Bool("bpf-stats", false, "measure the eBPF programs' own run time (adds a little to every run); shown by clifr stats")
	pprofDir := fs.String("pprof-dir", "", "write the recorder's own CPU and heap profiles to this directory (for development)")
	testMode := fs.Bool("test-ebpf", false, "load the eBPF programs, trigger every event type, report and exit (root)")
	heapTarget := fs.String("gc-heap-target", "256M", "heap size up to which garbage is collected at Go's default rate (GOGC 100); above it more often, down to GOGC 50 (0 = always 50; GOGC or GOMEMLIMIT in the environment turn this off)")
	maxCmdline := fs.String("max-cmdline", "64K", "bytes of each command line stored; longer ones are cut (any user can start processes with megabytes of arguments; 0 = all)")
	memGuard := fs.String("memory-guard", "384M", "live heap above which the recorder sheds data instead of reaching the unit's MemoryMax: command lines cut to 4K, the open files of the processes holding the most no longer tracked; a guard event says so (0 = off)")
	maxSize := fs.String("max-size", "2G", "size cap for the data directory, e.g. 2G or 500M (0 = none); the oldest hours go first")
	metricsAddr := fs.String("metrics", "", "serve Prometheus metrics (Node Exporter names, and clifr_*) at ADDR/metrics, e.g. 127.0.0.1:9100; addresses other than loopback need --metrics-tls-config with TLS (off by default)")
	metricsWebConfig := fs.String("metrics-tls-config", "", "--metrics: TLS and basic authentication, in Node Exporter's web configuration format (its --web.config.file: tls_server_config, basic_auth_users)")
	serveAddr := fs.String("serve", "", "serve the recording's files to clifr --host at ADDR (e.g. :8443): every request needs a token (clifrd token new), TLS with clifrd's self-signed certificate except on loopback (off by default)")
	serveTokens := fs.String("serve-tokens", remote.DefaultTokenFile, "--serve: file of the accepted tokens' SHA-256 (clifrd token)")
	serveTLSDir := fs.String("serve-tls-dir", "", "--serve: directory of clifrd's TLS key and certificate, made at first start (default DATA-DIR/serve-tls)")
	serveWebConfig := fs.String("serve-tls-config", "", "--serve: your own TLS certificate instead of the self-signed one, in Node Exporter's web configuration format (its tls_server_config; may be the file of --metrics-tls-config); TLS on loopback too")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("clifrd", version())
		return nil
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if err := applyConfig(fs, *configPath, given["config"] || given["C"]); err != nil {
		return err
	}
	if d := os.Getenv("CLIFR_DATA_DIR"); d != "" && !given["data-dir"] && !given["D"] {
		c.DataDir = d
	}
	level, err := recorder.ParseLevel(*logLevel)
	if err != nil {
		return err
	}
	if doDoctor {
		return doctor(c.DataDir, *configPath)
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
	if c.Parquet.MaxBytes, err = parseSize(*maxSize); err != nil {
		return err
	}
	maxCmd, err := parseSize(*maxCmdline)
	if err != nil {
		return fmt.Errorf("--max-cmdline: %w", err)
	}
	c.MaxCmdline = int(maxCmd)
	if c.MemoryGuard, err = parseSize(*memGuard); err != nil {
		return fmt.Errorf("--memory-guard: %w", err)
	}
	if c.Interval < time.Second || c.FDInterval < c.Interval {
		return errors.New("need --interval >= 1s and --fd-interval >= --interval")
	}
	if c.SysInterval < time.Second || c.SysInterval > c.Interval && given["sys-interval"] {
		return errors.New("need 1s <= --sys-interval <= --interval")
	}
	logger := recorder.NewLogger(log.New(os.Stderr, "clifrd: ", log.LstdFlags), level)
	if os.Getenv("GOGC") == "" && os.Getenv("GOMEMLIMIT") == "" {
		target, err := parseSize(*heapTarget)
		if err != nil {
			return fmt.Errorf("--gc-heap-target: %w", err)
		}
		if target > 0 {
			stop := make(chan struct{})
			defer close(stop)
			go tuneGC(uint64(target), 5*time.Second, stop)
		} else {
			debug.SetGCPercent(gcPercentMin)
		}
		if cg, err := procfs.New("/proc").ReadCgroup(os.Getpid()); err == nil {
			if l := setSoftLimit(cg); l > 0 {
				logger.Printf("memory: Go memory limit %d MiB (%.0f%% of the cgroup's %d MiB)", l>>20, 100*softLimitShare, int64(float64(l)/softLimitShare)>>20)
			}
		}
	}
	if *bpfStats {
		// Kernel-wide while this descriptor is open (Linux 5.8+).
		st, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
		if err != nil {
			return fmt.Errorf("--bpf-stats: %w", err)
		}
		defer st.Close()
	}
	if *pprofDir != "" {
		stopProfile, err := startProfile(*pprofDir)
		if err != nil {
			return fmt.Errorf("--pprof-dir: %w", err)
		}
		defer stopProfile()
	}
	// A bad address is a configuration error: clifrd does not start. If the
	// port cannot be opened (taken, or no TCP under the unit), clifrd logs
	// it and records without metrics: the recording comes first.
	var serveWeb *webconfig.Web
	if *serveAddr == "" && *serveWebConfig != "" {
		return errors.New("--serve-tls-config needs --serve")
	}
	if *serveAddr != "" {
		if _, err := remote.CheckServeAddr(*serveAddr); err != nil {
			return err
		}
		if *serveWebConfig != "" {
			if serveWeb, err = webconfig.New("serve", *serveWebConfig, logger.Errorf); err != nil {
				return err
			}
			if !serveWeb.HasTLS() {
				return fmt.Errorf("--serve-tls-config %s: no tls_server_config (--serve uses only that part)", *serveWebConfig)
			}
		}
	}
	var metricsLn net.Listener
	var metricsWeb *webconfig.Web
	if *metricsAddr == "" && *metricsWebConfig != "" {
		return errors.New("--metrics-tls-config needs --metrics")
	}
	if *metricsAddr != "" {
		// The web configuration is checked at start like the address: an
		// invalid one stops clifrd (later changes that are invalid are
		// logged and the previous settings kept).
		if *metricsWebConfig != "" {
			if metricsWeb, err = webconfig.New("metrics", *metricsWebConfig, logger.Errorf); err != nil {
				return err
			}
		}
		if _, err := metrics.CheckAddr(*metricsAddr, metricsWeb != nil && metricsWeb.HasTLS()); err != nil {
			return err
		}
		if metricsLn, err = metrics.Listen(*metricsAddr, metricsWeb); err != nil {
			logger.Errorf("metrics: %v; recording without them", err)
			metricsLn = nil
		} else {
			c.Metrics = true
		}
	}
	r, err := recorder.New(c, logger)
	if err != nil {
		if metricsLn != nil {
			metricsLn.Close()
		}
		return err
	}
	if metricsLn != nil {
		srv := metrics.Serve(metricsLn, r.Metrics, metricsWeb)
		defer srv.Close()
		scheme, auth := "http", ""
		if metricsWeb != nil {
			if metricsWeb.HasTLS() {
				scheme = "https"
			}
			auth = metricsWeb.Describe()
		}
		logger.Printf("metrics at %s://%s/metrics%s", scheme, metricsLn.Addr(), auth)
	}
	if *serveAddr != "" {
		tlsDir := *serveTLSDir
		if tlsDir == "" {
			tlsDir = filepath.Join(c.DataDir, "serve-tls")
		}
		if srv := startServe(*serveAddr, *serveTokens, tlsDir, c.DataDir, c.Version, serveWeb, logger); srv != nil {
			defer srv.Close()
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var to []string
	if c.DataDir != "" {
		to = append(to, c.DataDir+" (Parquet, flushed every "+c.Parquet.FlushInterval.String()+")")
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

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, " ") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}
