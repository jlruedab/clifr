package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// cgsample samples cgroup v2 accounting for a set of named cgroups, plus
// system-wide CPU, memory, pressure and disk counters, until SIGTERM/SIGINT.
// All counters are written raw (cumulative where the kernel keeps them
// cumulative); the report computes rates over the measured window.
//
//	benchtool cgsample --out DIR [--interval 5s] [--disk sda,dm-0] [--free-path P]
//	                   [--min-free BYTES --stop-unit UNIT] NAME=CGROUP_PATH...
//
// CGROUP_PATH is relative to /sys/fs/cgroup (as `systemctl show -p
// ControlGroup` prints it). A cgroup that does not exist (yet, or any more)
// is skipped for that tick. Output: DIR/cgroup.csv, DIR/system.csv,
// DIR/disk.csv.
//
// With --min-free, when free space on --free-path drops below BYTES the
// sampler writes DIR/LOWDISK and runs `systemctl stop --no-block UNIT`
// (once), then keeps sampling. Used by passive.sh to protect a real server.
func cgsample(args []string) error {
	fs := flag.NewFlagSet("cgsample", flag.ExitOnError)
	out := fs.String("out", "", "output directory")
	interval := fs.Duration("interval", 5*time.Second, "sampling interval")
	disks := fs.String("disk", "", "comma-separated block devices to record from /proc/diskstats")
	freePath := fs.String("free-path", ".", "filesystem whose free space is recorded")
	minFree := fs.Uint64("min-free", 0, "stop --stop-unit when free bytes on --free-path drop below this")
	stopUnit := fs.String("stop-unit", "", "systemd unit to stop on low disk")
	fs.Parse(args)
	if *out == "" || fs.NArg() == 0 {
		return fmt.Errorf("usage: cgsample --out DIR [--interval 5s] [--disk sda] NAME=CGROUP_PATH...")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return fmt.Errorf("cgroup v2 not available (no /sys/fs/cgroup/cgroup.controllers)")
	}
	type group struct{ name, path string }
	var groups []group
	for _, a := range fs.Args() {
		name, path, ok := strings.Cut(a, "=")
		if !ok {
			return fmt.Errorf("bad cgroup argument %q, want NAME=PATH", a)
		}
		groups = append(groups, group{name, filepath.Join("/sys/fs/cgroup", path)})
	}
	devs := map[string]bool{}
	for _, d := range strings.Split(*disks, ",") {
		if d != "" {
			devs[d] = true
		}
	}

	cgw, cgf, err := createCSV(filepath.Join(*out, "cgroup.csv"), cgroupHeader)
	if err != nil {
		return err
	}
	defer cgf.Close()
	syw, syf, err := createCSV(filepath.Join(*out, "system.csv"), systemHeader)
	if err != nil {
		return err
	}
	defer syf.Close()
	dkw, dkf, err := createCSV(filepath.Join(*out, "disk.csv"), diskHeader)
	if err != nil {
		return err
	}
	defer dkf.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	stopped := false
	for {
		ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
		for _, g := range groups {
			if row, ok := readCgroup(g.path); ok {
				cgw.Write(append([]string{ts, g.name}, row...))
			}
		}
		sys := readSystem(*freePath)
		syw.Write(append([]string{ts}, sys...))
		if free, err := strconv.ParseUint(sys[len(sys)-1], 10, 64); err == nil && *minFree > 0 && free < *minFree && !stopped {
			stopped = true
			os.WriteFile(filepath.Join(*out, "LOWDISK"), []byte(ts+"\n"), 0o644)
			if *stopUnit != "" {
				exec.Command("systemctl", "stop", "--no-block", *stopUnit).Run()
			}
		}
		for _, row := range readDiskstats(devs) {
			dkw.Write(append([]string{ts}, row...))
		}
		for _, w := range []*csv.Writer{cgw, syw, dkw} {
			w.Flush()
		}
		select {
		case <-tick.C:
		case <-sig:
			return nil
		}
	}
}

func createCSV(path string, header []string) (*csv.Writer, *os.File, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	w := csv.NewWriter(f)
	w.Write(header)
	return w, f, nil
}

var cgroupHeader = []string{"ts_ms", "group",
	"cpu_usage_us", "cpu_user_us", "cpu_system_us", "nr_throttled", "throttled_us",
	"mem_current", "mem_peak", "mem_anon", "mem_file",
	"io_rbytes", "io_wbytes", "io_rios", "io_wios",
	"psi_cpu_some_us", "psi_mem_some_us", "psi_mem_full_us", "psi_io_some_us", "psi_io_full_us",
	"pids"}

// readCgroup returns the cgroupHeader columns after ts and group. Missing
// files (e.g. memory.peak before kernel 5.19) give empty fields.
func readCgroup(dir string) ([]string, bool) {
	cpu, err := readKV(filepath.Join(dir, "cpu.stat"))
	if err != nil {
		return nil, false
	}
	mem, _ := readKV(filepath.Join(dir, "memory.stat"))
	var io [4]uint64 // rbytes wbytes rios wios, summed over devices
	if data, err := os.ReadFile(filepath.Join(dir, "io.stat")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			for _, f := range strings.Fields(line) {
				k, v, ok := strings.Cut(f, "=")
				if !ok {
					continue
				}
				n, _ := strconv.ParseUint(v, 10, 64)
				switch k {
				case "rbytes":
					io[0] += n
				case "wbytes":
					io[1] += n
				case "rios":
					io[2] += n
				case "wios":
					io[3] += n
				}
			}
		}
	}
	cs, _ := readPressure(filepath.Join(dir, "cpu.pressure"))
	msome, mfull := readPressure(filepath.Join(dir, "memory.pressure"))
	isome, ifull := readPressure(filepath.Join(dir, "io.pressure"))
	return []string{
		cpu["usage_usec"], cpu["user_usec"], cpu["system_usec"], cpu["nr_throttled"], cpu["throttled_usec"],
		readFirst(filepath.Join(dir, "memory.current")), readFirst(filepath.Join(dir, "memory.peak")),
		mem["anon"], mem["file"],
		u(io[0]), u(io[1]), u(io[2]), u(io[3]),
		cs, msome, mfull, isome, ifull,
		readFirst(filepath.Join(dir, "pids.current")),
	}, true
}

var systemHeader = []string{"ts_ms",
	"cpu_user", "cpu_nice", "cpu_system", "cpu_idle", "cpu_iowait", "cpu_irq", "cpu_softirq", "cpu_steal",
	"mem_total_kb", "mem_available_kb", "mem_cached_kb", "mem_dirty_kb",
	"psi_cpu_some_us", "psi_mem_some_us", "psi_mem_full_us", "psi_io_some_us", "psi_io_full_us",
	"free_bytes"}

// readSystem returns the systemHeader columns after ts. CPU values are
// cumulative clock ticks from the "cpu" line of /proc/stat.
func readSystem(freePath string) []string {
	row := make([]string, 0, len(systemHeader)-1)
	cpu := make([]string, 8)
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		line, _, _ := strings.Cut(string(data), "\n")
		f := strings.Fields(line)
		for i := 0; i < 8 && i+1 < len(f); i++ {
			cpu[i] = f[i+1]
		}
	}
	row = append(row, cpu...)
	mi := map[string]string{}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) >= 2 {
				mi[strings.TrimSuffix(fs[0], ":")] = fs[1]
			}
		}
		f.Close()
	}
	row = append(row, mi["MemTotal"], mi["MemAvailable"], mi["Cached"], mi["Dirty"])
	cs, _ := readPressure("/proc/pressure/cpu")
	msome, mfull := readPressure("/proc/pressure/memory")
	isome, ifull := readPressure("/proc/pressure/io")
	row = append(row, cs, msome, mfull, isome, ifull)
	free := ""
	var st unix.Statfs_t
	if unix.Statfs(freePath, &st) == nil {
		free = u(st.Bavail * uint64(st.Bsize))
	}
	return append(row, free)
}

var diskHeader = []string{"ts_ms", "dev", "rd_ios", "rd_sectors", "rd_ms", "wr_ios", "wr_sectors", "wr_ms", "io_ms", "weighted_ms"}

// readDiskstats returns one row per selected device from /proc/diskstats.
func readDiskstats(devs map[string]bool) [][]string {
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return nil
	}
	var rows [][]string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 14 || !devs[f[2]] {
			continue
		}
		// fields after the name: rd_ios rd_merges rd_sectors rd_ms wr_ios wr_merges wr_sectors wr_ms in_flight io_ms weighted_ms
		rows = append(rows, []string{f[2], f[3], f[5], f[6], f[7], f[9], f[10], f[12], f[13]})
	}
	return rows
}

// readKV reads "key value" lines (cpu.stat, memory.stat).
func readKV(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok {
			m[k] = v
		}
	}
	return m, nil
}

// readPressure returns the cumulative stall totals (µs) of a PSI file:
// some, and full (empty when the file has no "full" line or is missing).
func readPressure(path string) (some, full string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		total := ""
		for _, kv := range f[1:] {
			if v, ok := strings.CutPrefix(kv, "total="); ok {
				total = v
			}
		}
		switch f[0] {
		case "some":
			some = total
		case "full":
			full = total
		}
	}
	return some, full
}

func readFirst(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func u(n uint64) string { return strconv.FormatUint(n, 10) }
