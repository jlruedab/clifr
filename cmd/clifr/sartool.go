package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/query"
)

func sarTool() *tool {
	return &tool{
		name: "sar", synopsis: "[-A] [-u [ALL]] [-P ALL|CPUS] [-B] [-b] [-d [-p]] [-w] [-W] [-r [ALL]] [-S] [-H] [-v] [-q [KEYWORD]] [-I SUM|ALL] [-m CPU] [-n KEYWORD[,...]] [-F [MOUNT]] [-i SEC] [INTERVAL]",
		opts: []opt{
			{short: 'A', help: "every report clifr can make"},
			{short: 'u', arg: "ALL", optional: true, words: []string{"ALL"}, help: "CPU use (ALL: every column)"},
			{short: 'P', arg: "CPUS", help: "per CPU (CPU use, softnet, frequency, interrupts): ALL, or CPU numbers separated by commas"},
			{short: 'B', help: "paging"},
			{short: 'b', help: "I/O transfers of the physical devices"},
			{short: 'd', help: "each block device (whole devices, as sa1's default collects them)"},
			{short: 'p', help: "with -d: the device name last, device-mapper devices by name"},
			{short: 'w', help: "processes created and context switches"},
			{short: 'W', help: "swapping"},
			{short: 'r', arg: "ALL", optional: true, words: []string{"ALL"}, help: "memory (ALL: anonymous, slab, kernel stack, page table, vmalloc)"},
			{short: 'S', help: "swap space"},
			{short: 'H', help: "huge pages"},
			{short: 'v', help: "dentries, files, inodes, ptys (from a read every minute)"},
			{short: 'q', arg: "KEYWORD", optional: true, words: []string{"CPU", "IO", "MEM", "LOAD", "PSI", "ALL"},
				help: "run queue and load; CPU, IO, MEM: pressure; PSI: the three; ALL: everything"},
			{short: 'I', arg: "SUM", words: []string{"SUM", "ALL"}, help: "interrupts: SUM, or ALL (sysstat 12.6 and later: from a read every minute)"},
			{short: 'm', arg: "KEYWORD", help: "power: CPU (the CPU frequency; ALL: CPU only)"},
			{short: 'n', arg: "KEYWORD", help: "network: DEV EDEV NFS NFSD SOCK IP EIP ICMP EICMP TCP ETCP UDP SOCK6 IP6 EIP6 ICMP6 EICMP6 UDP6 SOFT ALL"},
			{short: 'F', arg: "MOUNT", optional: true, words: []string{"MOUNT"}, help: "file systems (MOUNT: by mount point)"},
			{short: 'i', arg: "SEC", help: "seconds between records (default 600, as sa1's)"},
			{short: 'y', help: "TTYs (not recorded)"},
		},
		about:  "sar's reports over a period, as sar -f prints them from a daily file",
		window: true,
		notes: []string{
			"sar -f FILE -s A -e B, as the recorded host's sysstat prints it (C locale): 12.7.7; 12.6.1",
			"(Ubuntu 24.04), 12.5.x (RHEL 9, Ubuntu 22.04), 11.7.3 (RHEL 8). The records are the system",
			"samples at each multiple of -i SEC (default 600 s, the clock's, as sa1 runs; INTERVAL is the",
			"same), each report in turn with its Average, LINUX RESTART at a reboot. -v, -n NFS/NFSD and",
			"-I (sysstat 12.6+) come from reads every minute; -b, -d, -r ALL, -H (sysstat 12), -I, -m CPU,",
			"-n SOFT and -q IO/MEM from data recorded since schema 14 (2026-11-22). -d lists whole devices",
			"(sa1's default -S DISK: no partitions). Not recorded: -I ALL of sysstat 11 and 12.5 (every IRQ",
			"number of /proc/stat), -m FAN/TEMP/IN/BAT/USB, -y, -n FC.",
		},
		examples: []string{`clifr --since "02:00" --until "04:00" sar`, `clifr --since "02:00" --until "04:00" "sar -r -S"`,
			`clifr --since "02:00" --until "02:10" "sar -n DEV -i 60"`, `clifr --since "02:00" --until "04:00" "sar -dp"`},
		prepare: prepareSar,
	}
}

func prepareSar(p parsed, c *runCtx) (func() error, error) {
	if !c.w.IsRange() {
		return nil, errors.New("sar: reports a period, as sar -f does: use --since and --until")
	}
	if p.has("y") {
		return nil, errors.New("sar: -y (serial lines) is not recorded")
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
	var cpus []int // -P
	if v, ok := p.set["P"]; ok {
		if v == "ALL" {
			cpus = []int{query.SarAllCPU}
		} else {
			for _, f := range strings.Split(v, ",") {
				n, err := strconv.Atoi(f)
				if err != nil || n < 0 {
					return nil, fmt.Errorf("sar: bad CPU %q", f)
				}
				cpus = append(cpus, n)
			}
		}
	}
	return func() error {
		st := query.StyleAt(c.db, c.w.From)
		v := st.Sar
		v12 := v != "11.7"
		irqFile := v != "11.7" && v != "12.5" // -I from /proc/interrupts (12.6+)
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
					acts[i].Pretty = acts[i].Pretty || a.Pretty
					return
				}
			}
			acts = append(acts, a)
		}
		allNet := []string{"DEV", "EDEV", "NFS", "NFSD", "SOCK", "IP", "EIP", "ICMP", "EICMP", "TCP", "ETCP", "UDP", "SOCK6", "IP6", "EIP6", "ICMP6", "EICMP6", "UDP6", "SOFT"}
		actKey := func(n string) string {
			switch n {
			case "DEV":
				return "netdev"
			case "EDEV":
				return "netedev"
			case "SOFT":
				return "softnet"
			}
			return strings.ToLower(n)
		}
		netKey := func(k string) error {
			switch k {
			case "ALL":
				for _, n := range allNet {
					add(query.SarAct{Key: actKey(n), CPUs: cpus})
				}
				skipped = append(skipped, "-n FC")
			case "FC":
				return errors.New("sar: -n FC (Fibre Channel) is not recorded")
			default:
				for _, n := range allNet {
					if n == k {
						add(query.SarAct{Key: actKey(n), CPUs: cpus})
						return nil
					}
				}
				return fmt.Errorf("sar: unknown -n keyword %q", k)
			}
			return nil
		}
		if p.has("A") {
			all := []int{query.SarAllCPU}
			add(query.SarAct{Key: "cpu", All: true, CPUs: all})
			for _, k := range []string{"pcsw", "swap", "paging", "io", "swapmem", "huge", "ktables", "queue", "fs"} {
				add(query.SarAct{Key: k})
			}
			add(query.SarAct{Key: "mem", All: true})
			add(query.SarAct{Key: "disk"})
			add(query.SarAct{Key: "cpufreq", CPUs: all})
			if irqFile {
				add(query.SarAct{Key: "irq", All: true, CPUs: all})
			} else {
				add(query.SarAct{Key: "irq"})
				skipped = append(skipped, "-I ALL")
			}
			if v12 {
				for _, k := range []string{"psicpu", "psiio", "psimem"} {
					add(query.SarAct{Key: k})
				}
			}
			netKey("ALL")
			for i := range acts {
				if acts[i].Key == "softnet" {
					acts[i].CPUs = all
				}
			}
			skipped = append(skipped, "-m FAN/TEMP/IN/BAT/USB", "-y")
		}
		if p.has("u") {
			add(query.SarAct{Key: "cpu", All: p.set["u"] == "ALL"})
		}
		if cpus != nil && (p.has("u") || !p.has("I") && !p.has("m") && len(p.all["n"]) == 0) {
			add(query.SarAct{Key: "cpu", All: p.has("u") && p.set["u"] == "ALL", CPUs: cpus})
		}
		for flag, key := range map[string]string{"w": "pcsw", "W": "swap", "S": "swapmem", "v": "ktables", "B": "paging", "b": "io", "H": "huge"} {
			if p.has(flag) {
				add(query.SarAct{Key: key})
			}
		}
		if p.has("d") {
			add(query.SarAct{Key: "disk", Pretty: p.has("p")})
		}
		if p.has("r") {
			add(query.SarAct{Key: "mem", All: p.set["r"] == "ALL"})
		}
		if p.has("q") {
			kw := p.set["q"]
			if kw != "" && kw != "LOAD" && !v12 {
				return errors.New("sar: -q " + kw + " needs sysstat 12 (the recorded host has 11.7.3)")
			}
			switch kw {
			case "", "LOAD":
				add(query.SarAct{Key: "queue"})
			case "CPU":
				add(query.SarAct{Key: "psicpu"})
			case "IO":
				add(query.SarAct{Key: "psiio"})
			case "MEM":
				add(query.SarAct{Key: "psimem"})
			case "PSI", "ALL":
				if kw == "ALL" {
					add(query.SarAct{Key: "queue"})
				}
				for _, k := range []string{"psicpu", "psiio", "psimem"} {
					add(query.SarAct{Key: k})
				}
			}
		}
		if p.has("I") {
			if p.set["I"] == "ALL" && !irqFile {
				return errors.New("sar: -I ALL of sysstat 11 and 12.5 lists every IRQ number of /proc/stat, which clifrd does not record")
			}
			add(query.SarAct{Key: "irq", All: p.set["I"] == "ALL", CPUs: cpus})
		}
		if p.has("m") {
			switch p.set["m"] {
			case "CPU", "ALL":
				add(query.SarAct{Key: "cpufreq", CPUs: cpus})
				if p.set["m"] == "ALL" {
					skipped = append(skipped, "-m FAN/TEMP/IN/BAT/USB")
				}
			default:
				return fmt.Errorf("sar: -m %s (sensors, batteries, USB devices) is not recorded", p.set["m"])
			}
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
		// Reports whose data this recording lacks (schema 14): -A leaves them
		// out with a note, an option asking for one is refused.
		if miss := d.SarMissing(o); len(miss) > 0 {
			kept := o.Acts[:0]
			var names []string
			for _, a := range o.Acts {
				if !miss[a.Key] {
					kept = append(kept, a)
					continue
				}
				if a.Key == "mem" && p.has("A") { // -r without ALL's columns
					a.All = false
					kept = append(kept, a)
					names = append(names, "mem ALL")
					continue
				}
				names = append(names, a.Key)
			}
			if !p.has("A") || len(kept) == 0 {
				return fmt.Errorf("sar: not in this recording (recorded since schema 14, 2026-11-22): %s", strings.Join(names, ", "))
			}
			c.header("sar: -A without %s: not in this recording (recorded since schema 14, 2026-11-22)", strings.Join(names, ", "))
			o.Acts = kept
		}
		if !d.HasPSI() {
			kept := o.Acts[:0]
			for _, a := range o.Acts {
				if !strings.HasPrefix(a.Key, "psi") {
					kept = append(kept, a)
				}
			}
			if len(kept) == 0 {
				return errors.New("sar: requested activities not available: the host had no /proc/pressure (PSI off)")
			}
			if len(kept) < len(o.Acts) {
				c.header("sar: no pressure reports: the host had no /proc/pressure (PSI off)")
			}
			o.Acts = kept
		}
		for _, n := range d.Notes {
			c.header("sar: %s", n)
		}
		if len(skipped) > 0 {
			c.header("sar: without %s (not recorded)", strings.Join(skipped, ", "))
		}
		var rows []query.SarRow
		if c.g.json {
			rows = query.SarRows(d, o)
		}
		return c.emit(rows, func(i int) rowMeta { return rowMeta{TS: rows[i].TS} },
			func(w io.Writer) { query.PrintSar(w, d, o) })
	}, nil
}

func fmtStep(ms int64) string {
	if ms%60000 == 0 {
		return fmt.Sprintf("%d min", ms/60000)
	}
	return fmt.Sprintf("%d s", ms/1000)
}
