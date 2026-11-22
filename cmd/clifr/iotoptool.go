package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"clifr/internal/query"
)

func iotopTool() *tool {
	return &tool{
		name: "iotop", synopsis: "[-b] [-o] [-P] [-a] [-k] [-t] [-q...] [-n NUM] [-d SEC] [-p PID]... [-u USER]...",
		opts: []opt{
			{short: 'b', long: "batch", help: "batch mode (clifr always prints iotop's batch output)"},
			{short: 'o', long: "only", help: "only processes that did I/O"},
			{short: 'P', long: "processes", help: "processes, not threads (clifr has processes only)"},
			{short: 'a', long: "accumulated", help: "bytes since iotop first saw the process, not per second"},
			{short: 'k', long: "kilobytes", help: "kilobytes"},
			{short: 't', long: "time", help: "the time in front of every line"},
			{short: 'q', long: "quiet", help: "-q: the column titles once; -qq: none; -qqq: no header lines"},
			{short: 'n', long: "iter", arg: "NUM", help: "NUM screens (the first is iotop's first: no interval yet)"},
			{short: 'd', long: "delay", arg: "SEC", help: "seconds between screens (snapped to the process samples)"},
			{short: 'p', long: "pid", arg: "PID", help: "only this process (more than once: these)"},
			{short: 'u', long: "user", arg: "USER", help: "only this user's processes (more than once: these)"},
		},
		about:  "processes' disk reads and writes as iotop -b (the Python iotop 0.6) prints them",
		window: true,
		notes: []string{
			"iotop 0.6 (the Python iotop every distribution installs as iotop) in batch mode as root, as the",
			"recorded host's build prints it: RHEL 8 and 9 (\"Actual DISK READ\", each line as b'...'),",
			"Ubuntu 22.04 (0.6-24), 0.6-42 otherwise. clifr records processes, not threads: every line is a",
			"process, as with -P (without -P a header line says so). The values are the increase, between two",
			"process samples (--interval), of the sum of each process's threads' own I/O counters, as iotop",
			"adds them up (recorded since schema 13; before, /proc/PID/io's, which also hold the I/O of exited",
			"threads and reaped children: a header line says so). DISK WRITE leaves out cancelled",
			"writes; Total DISK READ/WRITE adds up all processes watched, Current/Actual DISK READ/WRITE is",
			"the page-in and page-out of /proc/vmstat. PRIO is the I/O priority recorded since schema 13",
			"(?dif: the threads differ); older recordings derive it from the policy and nice value.",
			"IO % (and the sort by it) only where the host had delay accounting (kernel.task_delayacct = 1,",
			"or a kernel without it, as RHEL 8's): the block I/O wait over all threads averaged per thread, at",
			"10 ms resolution. SWAPIN is not recorded (it is in the kernel's taskstats only): shown as ?.",
			"At --at T: one screen, the interval between the two process samples at or before T. Over a",
			"range: iotop's first screen (zeros) at the first process sample, then one per -d SEC (default:",
			"every process sample), at most -n NUM screens in all. A process is listed when it was alive at",
			"both ends of an interval (new ones with zeros), as iotop sees processes at its refreshes.",
		},
		examples: []string{`clifr --at "02:45" "iotop -b -o -P"`, `clifr --since "02:40" --until "02:50" "iotop -b -o -P -d 60"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("iotop: unexpected argument %q", p.pos[0])
			}
			o := query.IotopOpts{Only: p.has("only"), Processes: p.has("processes"), Accumulated: p.has("accumulated"),
				Kilobytes: p.has("kilobytes"), Time: p.has("time"), Quiet: len(p.all["quiet"])}
			for _, v := range p.all["pid"] {
				for _, f := range strings.Split(v, ",") {
					n, err := strconv.Atoi(f)
					if err != nil || n < 1 {
						return nil, fmt.Errorf("iotop: bad PID %q", f)
					}
					o.PIDs = append(o.PIDs, n)
				}
			}
			var stepMS int64
			if p.has("delay") {
				d, err := strconv.ParseFloat(p.set["delay"], 64)
				if err != nil || d <= 0 || math.IsInf(d, 0) {
					return nil, fmt.Errorf("iotop: bad delay %q (seconds)", p.set["delay"])
				}
				stepMS = int64(d * 1000)
			}
			count := 0
			if p.has("iter") {
				n, err := strconv.Atoi(p.set["iter"])
				if err != nil || n < 1 {
					return nil, fmt.Errorf("iotop: bad number of iterations %q", p.set["iter"])
				}
				count = n
			}
			if !c.w.IsRange() && (p.has("delay") || p.has("iter")) {
				return nil, errors.New("iotop: with --at, one interval (the two process samples at or before it); for -d and -n use --since and --until")
			}
			return func() error {
				if query.MetaAt(c.db, "proc_io", c.w.From) == "false" {
					return errors.New("iotop: recorded without per-process I/O counters (clifrd --proc-io=false)")
				}
				ts, err := query.IotopTimes(c.db, c.w, stepMS, count)
				if err != nil {
					return err
				}
				if _, err := query.LoadUsers(c.db, ts[len(ts)-1]); err != nil {
					return err
				}
				for _, u := range p.all["user"] {
					uid, ok := query.UserID(u)
					if !ok {
						return fmt.Errorf("iotop: unknown user %q", u)
					}
					o.UIDs = append(o.UIDs, uid)
				}
				screens, err := query.Iotop(c.db, ts, o)
				if err != nil {
					return err
				}
				if !c.w.IsRange() {
					screens = screens[1:]
					c.header("iotop: the interval between the process samples of %s and %s (%.0f s)",
						query.FormatMS(ts[0]), query.FormatMS(ts[1]), screens[0].Seconds)
				} else {
					c.header("iotop: %d screens, %s .. %s: iotop's first (no interval yet), then the intervals between process samples",
						len(screens), query.FormatMS(ts[0]), query.FormatMS(ts[len(ts)-1]))
				}
				for _, sc := range screens {
					if sc.WholeIO {
						c.header("iotop: recorded before schema 13: each process's I/O includes its exited threads and reaped children (iotop counts neither)")
						break
					}
				}
				if !o.Processes {
					c.header("iotop: threads are not recorded: one line per process (as iotop -P)")
				}
				delay := query.IotopDelayAcct(c.db, ts[len(ts)-1])
				if delay {
					c.header("iotop: SWAPIN is not recorded: shown as ?")
				}
				st := query.StyleAt(c.db, ts[len(ts)-1])
				width := query.IotopPIDWidth(c.db, ts[len(ts)-1])
				shown := query.IotopShown(screens, o, st, delay)
				return c.emit(shown, func(i int) rowMeta { return rowMeta{TS: screens[i].TS, From: screens[i].From, To: screens[i].TS} },
					func(w io.Writer) {
						query.PrintIotop(w, screens, o, st, delay, width, func(ts int64) string { return time.UnixMilli(ts).Format("15:04:05") })
					})
			}, nil
		},
	}
}
