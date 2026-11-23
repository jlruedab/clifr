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

// The system-wide tools: at T the averages since boot (what the real tool
// prints without an interval); over a range one report for the whole range
// (--summary, the default) or one per interval (--samples, or an interval
// argument as for the real tool: "vmstat 60").

func addSystemTools() {
	common := []string{
		"--at: averages since boot at the sample at or before T, as the tool prints without an interval.",
		"--since: one report for the range; with --samples (or an INTERVAL argument) one per interval,",
		"at least INTERVAL (or -e) long and a multiple of the recording interval (30 s by default).",
	}
	addTool(vmstatTool(common))
	addTool(&tool{
		name: "mpstat", synopsis: "[-P ALL|N[,M...]] [INTERVAL [COUNT]]",
		about:  "CPU time by CPU",
		opts:   []opt{{short: 'P', arg: "CPUS", help: "ALL, or CPU numbers separated by commas (default: the total only)"}},
		window: true, notes: common,
		examples: []string{`clifr --at "02:45" "mpstat -P ALL"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			cpus := p.set["P"]
			return prepareSys("mpstat", p, c, func(spans []query.Span) error {
				rows, err := query.MPStat(c.db, spans, cpus)
				if err != nil {
					return err
				}
				return c.emit(rows, func(i int) rowMeta { return spanMeta(spans, rows[i].TS, rows[i], "cpu") },
					func(w io.Writer) { query.PrintMPStat(w, rows) })
			})
		},
	})
	addTool(&tool{
		name: "iostat", synopsis: "[-c] [-d] [-x] [-s] [-k|-m] [-z] [-N] [-t] [-y] [-p [ALL]] [INTERVAL [COUNT]]",
		about: "CPU and block device I/O",
		opts: []opt{
			{short: 'c', help: "the CPU report only"},
			{short: 'd', help: "the device report only (no avg-cpu)"},
			{short: 'x', help: "extended device statistics"},
			{short: 's', help: "short (narrow) device statistics"},
			{short: 'k', help: "kilobytes per second (the default)"},
			{short: 'm', help: "megabytes per second"},
			{short: 'z', help: "leave out devices without I/O in the interval"},
			{short: 'N', help: "device-mapper devices by their names"},
			{short: 't', help: "the time of each report"},
			{short: 'y', help: "no since-boot report (clifr prints none over a range anyway)"},
			{short: 'p', help: "also list partitions (ALL is accepted)"},
		},
		window:   true,
		notes:    append(append([]string{}, common...), "As iostat prints them, reports carry no time unless -t is given."),
		examples: []string{`clifr --since "02:00" --until "02:30" --samples -e 1m "iostat -x"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if p.has("k") && p.has("m") {
				return nil, errors.New("iostat: -k and -m: one unit")
			}
			if p.has("p") && len(p.pos) > 0 && p.pos[0] == "ALL" {
				p.pos = p.pos[1:]
			}
			return prepareSys("iostat", p, c, func(spans []query.Span) error {
				reps, err := query.IOStat(c.db, spans, p.has("p"))
				if err != nil {
					return err
				}
				o := query.IOStatOpts{Extended: p.has("x"), Short: p.has("s"), MB: p.has("m"), Zero: p.has("z"),
					DevMap: p.has("N"), Times: p.has("t"), CPU: !p.has("d") || p.has("c"), Disk: !p.has("c") || p.has("d")}
				return c.emit(reps, func(i int) rowMeta { return spanMeta(spans, reps[i].TS, reps[i]) },
					func(w io.Writer) { query.PrintIOStatOpts(w, reps, o) })
			})
		},
	})
	addTool(&tool{
		name: "uptime", about: "time since boot and load averages", window: true,
		notes: []string{"The number of logged-in users at the end of each interval, as procps counts them: utmp's",
			"user records (procps 3.3: RHEL 8/9, Ubuntu 22.04), logind's user sessions (procps 4); left out",
			"before 2026-11-20 (not recorded)."},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("uptime: unexpected argument %q", p.pos[0])
			}
			return prepareSys("uptime", p, c, func(spans []query.Span) error {
				rows, err := query.Uptime(c.db, spans)
				if err != nil {
					return err
				}
				for i := range rows {
					rows[i].Users = query.UsersAt(c.db, spans[i].To, query.Procps3(c.db, spans[i].To))
				}
				if !c.w.IsRange() { // uptime run at T: T's clock, the uptime at T
					rows[0].At(c.w.At)
					rows[0].Users = query.UsersAt(c.db, c.w.At, query.Procps3(c.db, c.w.At))
				}
				return c.emit(rows, func(i int) rowMeta { return spanMeta(spans, rows[i].TS, rows[i]) },
					func(w io.Writer) { query.PrintUptime(w, rows) })
			})
		},
	})
	addTool(pidstatTool(common))
	addTool(dateTool())
	addTool(hostnameTool())
	addTool(unameTool())
	addTool(dmesgTool())
	addTool(systemctlTool())
	addTool(cglsTool())
	addTool(swaponTool())
	addTool(lsmodTool())
	addTool(lsblkTool())
	addTool(lslocksTool())
	addTool(ipcsTool())
	addTool(lsipcTool())
	addTool(lscpuTool())
	addTool(lsmemTool())
	addTool(lsnsTool())
	addTool(sysctlTool())
	addTool(slabtopTool())
	addTool(numastatTool())
	addTool(conntrackTool())
	addTool(nfsstatTool())
	addTool(mountstatsTool())
	addTool(lastTool())
	addTool(whoTool())
	addTool(wTool())
	addTool(atopTool())
	addTool(iotopTool())
	addTool(htopTool())
	addTool(sarTool())
	addTool(nstatTool())
	addTool(ipTool())
}

// prepareSys reads INTERVAL [COUNT], chooses the spans and runs print.
func prepareSys(name string, p parsed, c *runCtx, print func([]query.Span) error) (func() error, error) {
	if len(p.pos) > 2 {
		return nil, fmt.Errorf("%s: unexpected argument %q", name, p.pos[2])
	}
	every, number := c.g.everyMS, c.g.number
	if len(p.pos) > 0 {
		n, err := strconv.Atoi(p.pos[0])
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("%s: bad interval %q (seconds)", name, p.pos[0])
		}
		every = int64(n) * 1000
	}
	if len(p.pos) > 1 {
		n, err := strconv.Atoi(p.pos[1])
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("%s: bad count %q", name, p.pos[1])
		}
		number = n
	}
	samples := c.g.samples || len(p.pos) > 0
	switch {
	case !c.w.IsRange() && (len(p.pos) > 0 || c.g.samples):
		return nil, fmt.Errorf("%s: an interval needs a range (--since)", name)
	case c.g.changes:
		return nil, fmt.Errorf("%s: --changes is not available for %s; use --samples", name, name)
	}
	return func() error {
		spanOf := query.SysSpans
		if name == "pidstat" {
			spanOf = query.ProcSpans
		}
		spans, err := spanOf(c.db, c.w, every)
		if err != nil {
			return err
		}
		switch {
		case !c.w.IsRange():
			if name == "uptime" {
				c.header("uptime at %s: load averages from the sample of %s", query.FormatMS(c.w.At), query.FormatMS(spans[0].To))
			} else if strings.HasPrefix(name, "vmstat -") { // -d, -p, -m: counters, not averages
				c.header("%s: the counters at the sample of %s", name, query.FormatMS(spans[0].To))
			} else {
				c.header("%s: averages since boot at the sample of %s", name, query.FormatMS(spans[0].To))
			}
		case samples:
			if number > 0 && len(spans) > number {
				spans = spans[:number]
			}
			c.header("%s: %d intervals between samples, %s .. %s", name, len(spans), query.FormatMS(spans[0].From), query.FormatMS(spans[len(spans)-1].To))
		default:
			for i := 1; i < len(spans); i++ {
				if spans[i].From != spans[i-1].To {
					return errors.New(name + ": the system rebooted within the range; use --samples")
				}
			}
			spans = []query.Span{{From: spans[0].From, To: spans[len(spans)-1].To}}
			c.header("%s: one report for %s .. %s (use --samples for one per interval)", name, query.FormatMS(spans[0].From), query.FormatMS(spans[0].To))
		}
		return print(spans)
	}, nil
}

// spanMeta: a counter row ends at a sample (its ts_ms); over a range it
// covers the interval from the previous one. Every value is sampled.
func spanMeta(spans []query.Span, ts int64, row any, exact ...string) rowMeta {
	m := rowMeta{Sampled: jsonKeys(row, append(exact, "ts_ms", "time", "since_boot")...)}
	for _, sp := range spans {
		if sp.To == ts && sp.From != 0 {
			m.From, m.To = sp.From, sp.To
		}
	}
	return m
}

func pidstatTool(common []string) *tool {
	return &tool{
		name: "pidstat", synopsis: "[-u] [-r] [-d] [-w] [-h] [-l] [-p PIDS|ALL] [-C REGEX] [INTERVAL [COUNT]]",
		about: "CPU, memory, I/O and context switches by process",
		opts: []opt{
			{short: 'u', help: "CPU (the default report)"},
			{short: 'r', help: "page faults and memory"},
			{short: 'd', help: "I/O (kB read, written, cancelled; block I/O delay)"},
			{short: 'w', help: "context switches"},
			{short: 'h', help: "every report on one line per process"},
			{short: 'l', help: "the command line instead of the name"},
			{short: 'p', arg: "PIDS", help: "these processes, even without activity (comma separated, or ALL)"},
			{short: 'C', arg: "REGEX", help: "processes whose command name matches"},
		},
		window: true,
		notes: append(common,
			"Processes are reported from the process samples (every --interval): a span ends at one, and",
			"processes that started and ended between two samples are not in it. Without -p, only processes",
			"with activity in the span, as pidstat. %wait from the run-queue time, iodelay from delay",
			"accounting (0 unless the kernel's task_delayacct is on). Recorded since 2026-10-22."),
		examples: []string{`clifr --at "02:45" "pidstat -u -r"`, `clifr --since "02:00" --until "02:10" "pidstat -d 60"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			var acts []int
			for i, f := range []string{"u", "r", "d", "w"} {
				if p.has(f) {
					acts = append(acts, i)
				}
			}
			if len(acts) == 0 {
				acts = []int{query.PidCPU}
			}
			sel := query.PidstatSelect{CmdLine: p.has("l")}
			for _, v := range splitList(p.all["p"]) {
				if v == "ALL" {
					sel.All = true
					continue
				}
				pid, err := strconv.Atoi(v)
				if err != nil || pid <= 0 {
					return nil, fmt.Errorf("pidstat: bad PID %q", v)
				}
				sel.PIDs = append(sel.PIDs, pid)
			}
			if re := p.all["C"]; len(re) > 0 {
				var err error
				if sel.Comm, err = regexp.Compile(re[len(re)-1]); err != nil {
					return nil, fmt.Errorf("pidstat: -C: %v", err)
				}
			}
			return prepareSys("pidstat", p, c, func(spans []query.Span) error {
				rows, err := query.Pidstat(c.db, spans, acts, sel)
				if err != nil {
					return err
				}
				return c.emit(rows, func(i int) rowMeta {
					return spanMeta(spans, rows[i].TS, rows[i], "uid", "pid", "command", "comm")
				}, func(w io.Writer) { query.PrintPidstat(w, rows, acts, p.has("h")) })
			})
		},
	}
}
