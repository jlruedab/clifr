package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/query"
)

// sarLater: sar's reports whose data clifrd does not record yet.
var sarLater = map[string]string{
	"B": "-B (pgfree and the pgsteal_anon/_file counters)", "b": "-b (each disk's position and the virtual ones)",
	"d": "-d (each disk's position and the idle ones)", "m": "-m (CPU frequency, sensors)", "y": "-y (serial lines)",
}

func sarTool() *tool {
	return &tool{
		name: "sar", synopsis: "[-A] [-u [ALL]] [-P ALL|CPUS] [-w] [-W] [-r] [-S] [-H] [-v] [-q [CPU|LOAD|ALL]] [-I SUM] [-n KEYWORD[,...]] [-F [MOUNT]] [-i SEC] [INTERVAL]",
		opts: []opt{
			{short: 'A', help: "every report clifr can make"},
			{short: 'u', arg: "ALL", optional: true, words: []string{"ALL"}, help: "CPU use (ALL: every column)"},
			{short: 'P', arg: "CPUS", help: "per CPU: ALL, or CPU numbers separated by commas"},
			{short: 'w', help: "processes created and context switches"},
			{short: 'W', help: "swapping"},
			{short: 'r', arg: "ALL", optional: true, words: []string{"ALL"}, help: "memory (ALL: not recorded yet)"},
			{short: 'S', help: "swap space"},
			{short: 'H', help: "huge pages (sysstat 11 only: later releases add columns not recorded yet)"},
			{short: 'v', help: "dentries, files, inodes, ptys (from a read every minute)"},
			{short: 'q', arg: "KEYWORD", optional: true, words: []string{"CPU", "LOAD", "ALL", "IO", "MEM", "PSI"},
				help: "run queue and load (CPU: CPU pressure; ALL: both)"},
			{short: 'I', arg: "SUM", words: []string{"SUM", "ALL"}, help: "interrupts: SUM (sysstat 11 and 12.5)"},
			{short: 'n', arg: "KEYWORD", help: "network: DEV EDEV NFS NFSD SOCK IP EIP ICMP EICMP TCP ETCP UDP SOCK6 IP6 EIP6 ICMP6 EICMP6 UDP6 ALL"},
			{short: 'F', arg: "MOUNT", optional: true, words: []string{"MOUNT"}, help: "file systems (MOUNT: by mount point)"},
			{short: 'i', arg: "SEC", help: "seconds between records (default 600, as sa1's)"},
			{short: 'B', help: "paging (not recorded yet)"}, {short: 'b', help: "I/O (not recorded yet)"},
			{short: 'd', help: "disks (not recorded yet)"}, {short: 'm', arg: "KEYWORD", help: "power (not recorded)"},
			{short: 'y', help: "TTYs (not recorded)"},
		},
		about:  "sar's reports over a period, as sar -f prints them from a daily file",
		window: true,
		notes: []string{
			"sar -f FILE -s A -e B, as the recorded host's sysstat prints it (C locale): 12.7.7; 12.6.1",
			"(Ubuntu 24.04), 12.5.x (RHEL 9, Ubuntu 22.04), 11.7.3 (RHEL 8). The records are the system",
			"samples at each multiple of -i SEC (default 600 s, the clock's, as sa1 runs; INTERVAL is the",
			"same), each report in turn with its Average, LINUX RESTART at a reboot. -v and -n NFS/NFSD",
			"come from reads every minute. Not recorded yet: -B, -b, -d, -r ALL, -H (sysstat 12), -I ALL,",
			"-I SUM (sysstat 12.6 and later), -n SOFT, -q IO/MEM; not recorded: -m, -y, -n FC.",
		},
		examples: []string{`clifr --since "02:00" --until "04:00" sar`, `clifr --since "02:00" --until "04:00" "sar -r -S"`,
			`clifr --since "02:00" --until "02:10" "sar -n DEV -i 60"`},
		prepare: prepareSar,
	}
}

func prepareSar(p parsed, c *runCtx) (func() error, error) {
	if !c.w.IsRange() {
		return nil, errors.New("sar: reports a period, as sar -f does: use --since and --until")
	}
	for k, why := range sarLater {
		if p.has(k) {
			return nil, fmt.Errorf("sar: %s is not available: clifrd does not record it yet", why)
		}
	}
	step := int64(600_000)
	if v, ok := p.set["i"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("sar: bad interval %q (seconds)", v)
		}
		step = int64(n) * 1000
	}
	switch len(p.pos) {
	case 0:
	case 1:
		n, err := strconv.Atoi(p.pos[0])
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("sar: unexpected argument %q", p.pos[0])
		}
		step = int64(n) * 1000
	default:
		return nil, fmt.Errorf("sar: unexpected argument %q (a count is not supported: the period is --since .. --until)", p.pos[1])
	}
	return func() error {
		st := query.StyleAt(c.db, c.w.From)
		v := st.Sar
		var acts []query.SarAct
		var skipped []string
		add := func(a query.SarAct) {
			for i := range acts {
				if acts[i].Key == a.Key {
					acts[i].All = acts[i].All || a.All
					if a.CPUs != nil {
						acts[i].CPUs = append(acts[i].CPUs, a.CPUs...)
					}
					acts[i].Mount = acts[i].Mount || a.Mount
					return
				}
			}
			acts = append(acts, a)
		}
		v12 := v != "11.7"
		allNet := []string{"DEV", "EDEV", "NFS", "NFSD", "SOCK", "IP", "EIP", "ICMP", "EICMP", "TCP", "ETCP", "UDP", "SOCK6", "IP6", "EIP6", "ICMP6", "EICMP6", "UDP6"}
		actKey := func(n string) string {
			switch n {
			case "DEV":
				return "netdev"
			case "EDEV":
				return "netedev"
			}
			return strings.ToLower(n)
		}
		netKey := func(k string) error {
			switch k {
			case "ALL":
				for _, n := range allNet {
					add(query.SarAct{Key: actKey(n)})
				}
				skipped = append(skipped, "-n SOFT", "-n FC")
			case "SOFT":
				return errors.New("sar: -n SOFT is not available: clifrd does not record /proc/net/softnet_stat yet")
			case "FC":
				return errors.New("sar: -n FC (Fibre Channel) is not recorded")
			default:
				for _, n := range allNet {
					if n == k {
						add(query.SarAct{Key: actKey(n)})
						return nil
					}
				}
				return fmt.Errorf("sar: unknown -n keyword %q", k)
			}
			return nil
		}
		if p.has("A") {
			add(query.SarAct{Key: "cpu", All: true, CPUs: []int{query.SarAllCPU}})
			for _, k := range []string{"pcsw", "swap", "mem", "swapmem", "ktables", "queue", "fs"} {
				add(query.SarAct{Key: k})
			}
			if v == "11.7" || v == "12.5" {
				add(query.SarAct{Key: "irq"})
			} else {
				skipped = append(skipped, "-I")
			}
			if v12 {
				add(query.SarAct{Key: "psicpu"})
				skipped = append(skipped, "-H", "-q IO", "-q MEM")
			} else {
				add(query.SarAct{Key: "huge"})
			}
			netKey("ALL")
			skipped = append(skipped, "-B", "-b", "-d", "-r ALL", "-m", "-y")
		}
		if p.has("u") {
			add(query.SarAct{Key: "cpu", All: p.set["u"] == "ALL"})
		}
		if v, ok := p.set["P"]; ok {
			a := query.SarAct{Key: "cpu", All: p.has("u") && p.set["u"] == "ALL"}
			if v == "ALL" {
				a.CPUs = []int{query.SarAllCPU}
			} else {
				for _, f := range strings.Split(v, ",") {
					n, err := strconv.Atoi(f)
					if err != nil || n < 0 {
						return fmt.Errorf("sar: bad CPU %q", f)
					}
					a.CPUs = append(a.CPUs, n)
				}
			}
			add(a)
		}
		for flag, key := range map[string]string{"w": "pcsw", "W": "swap", "S": "swapmem", "v": "ktables"} {
			if p.has(flag) {
				add(query.SarAct{Key: key})
			}
		}
		if p.has("r") {
			if p.set["r"] == "ALL" {
				return errors.New("sar: -r ALL is not available: clifrd does not record AnonPages, KernelStack and VmallocUsed yet")
			}
			add(query.SarAct{Key: "mem"})
		}
		if p.has("H") {
			if v12 {
				return errors.New("sar: -H is not available for sysstat 12: clifrd does not record the reserved and surplus huge pages yet")
			}
			add(query.SarAct{Key: "huge"})
		}
		if p.has("q") {
			switch p.set["q"] {
			case "", "LOAD":
				add(query.SarAct{Key: "queue"})
			case "CPU":
				if !v12 {
					return errors.New("sar: -q CPU needs sysstat 12 (the recorded host has 11.7.3)")
				}
				add(query.SarAct{Key: "psicpu"})
			case "ALL", "PSI":
				if !v12 {
					return errors.New("sar: -q " + p.set["q"] + " needs sysstat 12 (the recorded host has 11.7.3)")
				}
				if p.set["q"] == "ALL" {
					add(query.SarAct{Key: "queue"})
				}
				add(query.SarAct{Key: "psicpu"})
				skipped = append(skipped, "-q IO", "-q MEM")
			default:
				return fmt.Errorf("sar: -q %s is not available: clifrd does not record the full pressure averages yet", p.set["q"])
			}
		}
		if p.has("I") {
			switch {
			case p.set["I"] != "SUM":
				return errors.New("sar: -I " + p.set["I"] + " is not available: clifrd does not record /proc/interrupts yet")
			case v != "11.7" && v != "12.5":
				return errors.New("sar: -I SUM of sysstat 12.6 and later sums /proc/interrupts, which clifrd does not record yet")
			}
			add(query.SarAct{Key: "irq"})
		}
		for _, n := range p.all["n"] {
			for _, k := range strings.Split(n, ",") {
				if err := netKey(strings.ToUpper(k)); err != nil {
					return err
				}
			}
		}
		if p.has("F") {
			add(query.SarAct{Key: "fs", Mount: p.set["F"] == "MOUNT"})
		}
		if len(acts) == 0 {
			add(query.SarAct{Key: "cpu"})
		}
		o := query.SarOpts{Acts: acts, StepMS: step, Version: v}
		d, err := query.Sar(c.db, c.w.From, c.w.To, o)
		if err != nil {
			return err
		}
		c.header("sar: sysstat %s's sar -f, one record per %s (the system sample at or after each multiple, local clock)",
			query.SarVersion(st), fmtStep(step))
		if !d.HasPSI() {
			kept := o.Acts[:0]
			for _, a := range o.Acts {
				if a.Key != "psicpu" {
					kept = append(kept, a)
				}
			}
			if len(kept) == 0 {
				return errors.New("sar: requested activities not available: the host had no /proc/pressure (PSI off)")
			}
			if len(kept) < len(o.Acts) {
				c.header("sar: no CPU pressure: the host had no /proc/pressure (PSI off)")
			}
			o.Acts = kept
		}
		for _, n := range d.Notes {
			c.header("sar: %s", n)
		}
		if len(skipped) > 0 {
			c.header("sar: -A without %s (not recorded)", strings.Join(skipped, ", "))
		}
		return c.emit([]*query.SarData{d}, func(int) rowMeta { return rowMeta{TS: c.w.From} },
			func(w io.Writer) { query.PrintSar(w, d, o) })
	}, nil
}

func fmtStep(ms int64) string {
	if ms%60000 == 0 {
		return fmt.Sprintf("%d min", ms/60000)
	}
	return fmt.Sprintf("%d s", ms/1000)
}
