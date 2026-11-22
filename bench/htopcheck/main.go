// htopcheck compares a real htop screen (tmux capture-pane text) with
// clifr's htop at the same moment.
//
//	htopcheck REAL.txt CLIFR.txt
//
// The header: each line's shape (numbers and bar characters masked) must be
// the same; Mem and Swp within 2%, Load average within 0.10, Uptime within
// 3 s, the Tasks counts within 2%. The tabs and column titles exactly. Each
// process by PID: USER, PRI, NI, Command (and the tree drawing) exactly;
// VIRT, RES, SHR within 5% (sampled up to an interval apart), S, CPU%,
// MEM% within 0.3 and TIME+ within 2 s are reported apart. The function key
// bar and processes on one side only (started or ended between the sample
// and the capture, or htop's own) are counted, not compared.
package main

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type row struct {
	pid                   int
	user, pri, ni, s, cmd string
	virt, res, shr        float64
	cpu, mem, time        float64
	tree                  string
	line                  string
}

type screen struct {
	header  []string
	tabs    string
	titles  string
	rows    map[int]row
	order   []int
	hasTabs bool
}

var (
	pidRe   = regexp.MustCompile(`^\s*(\d+) `)
	maskNum = regexp.MustCompile(`\d+(\.\d+)?[KMGTP%]?`)
	maskBar = regexp.MustCompile(`\[[|#*@$%&. ]*`)
)

func parse(path string) screen {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	sc := screen{rows: map[int]row{}}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	i := 0
	for ; i < len(lines); i++ {
		l := lines[i]
		if strings.Contains(l, "PID") && strings.Contains(l, "Command") {
			sc.titles = strings.TrimRight(l, " ")
			break
		}
		if strings.HasPrefix(strings.TrimSpace(l), "[Main]") {
			sc.tabs, sc.hasTabs = strings.TrimRight(l, " "), true
			continue
		}
		sc.header = append(sc.header, strings.TrimRight(l, " "))
	}
	cmdCol := strings.Index(sc.titles, "Command")
	if cmdCol >= 0 {
		cmdCol = len([]rune(sc.titles[:cmdCol]))
	}
	for i++; i < len(lines); i++ {
		l := strings.TrimRight(lines[i], " ")
		if strings.HasPrefix(l, "F1Help") || strings.HasPrefix(l, "F1") {
			continue
		}
		m := pidRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		pid, _ := strconv.Atoi(m[1])
		r := row{pid: pid, line: l}
		rs := []rune(l)
		if cmdCol > 0 && len(rs) >= cmdCol {
			rest := string(rs[cmdCol:])
			t := strings.IndexFunc(rest, func(c rune) bool { return !strings.ContainsRune("│├└─ ", c) })
			if t < 0 {
				t = len(rest)
			}
			r.tree, r.cmd = rest[:t], rest[t:]
		}
		f := strings.Fields(string(rs[:min(len(rs), max(cmdCol, 0))]))
		if len(f) >= 11 {
			r.user, r.pri, r.ni = f[1], f[2], f[3]
			r.virt, r.res, r.shr = kb(f[4]), kb(f[5]), kb(f[6])
			r.s = f[7]
			r.cpu, _ = strconv.ParseFloat(f[8], 64)
			r.mem, _ = strconv.ParseFloat(f[9], 64)
			r.time = hms(f[10])
		}
		if _, dup := sc.rows[pid]; !dup {
			sc.order = append(sc.order, pid)
		}
		sc.rows[pid] = r
	}
	return sc
}

func kb(s string) float64 {
	mult := 1.0
	switch s[len(s)-1] {
	case 'M':
		mult = 1024
	case 'G':
		mult = 1024 * 1024
	case 'T':
		mult = 1024 * 1024 * 1024
	}
	v, _ := strconv.ParseFloat(strings.TrimRight(s, "KMGT"), 64)
	return v * mult
}

// hms reads TIME+ (M:SS.cc, HhMM:SS, ...) as seconds; -1 when not readable.
func hms(s string) float64 {
	if h, rest, ok := strings.Cut(s, "h"); ok && strings.Contains(rest, ":") {
		hh, _ := strconv.ParseFloat(h, 64)
		m, sec, _ := strings.Cut(rest, ":")
		mm, _ := strconv.ParseFloat(m, 64)
		ss, _ := strconv.ParseFloat(sec, 64)
		return hh*3600 + mm*60 + ss
	}
	if m, sec, ok := strings.Cut(s, ":"); ok {
		mm, _ := strconv.ParseFloat(m, 64)
		ss, _ := strconv.ParseFloat(sec, 64)
		return mm*60 + ss
	}
	return -1
}

func near(a, b, rel float64) bool {
	return math.Abs(a-b) <= rel*max(math.Abs(a), math.Abs(b)) || math.Abs(a-b) <= 4
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: htopcheck REAL.txt CLIFR.txt")
		os.Exit(2)
	}
	real, rec := parse(os.Args[1]), parse(os.Args[2])
	var bad []string
	// Header.
	shape := func(l string) string { return maskNum.ReplaceAllString(maskBar.ReplaceAllString(l, "["), "N") }
	if len(real.header) != len(rec.header) {
		bad = append(bad, fmt.Sprintf("header: %d lines, clifr %d", len(real.header), len(rec.header)))
	}
	for i := 0; i < min(len(real.header), len(rec.header)); i++ {
		if shape(real.header[i]) != shape(rec.header[i]) {
			bad = append(bad, fmt.Sprintf("header line %d shape:\n  real  %q\n  clifr %q", i+1, real.header[i], rec.header[i]))
		}
	}
	vals := func(sc screen) map[string][]float64 {
		out := map[string][]float64{}
		num := regexp.MustCompile(`\d+(\.\d+)?[KMGT]?`)
		for _, l := range sc.header {
			for _, k := range []string{"Mem[", "Swp[", "Tasks: ", "Load average: ", "Uptime: "} {
				j := strings.Index(l, k)
				if j < 0 {
					continue
				}
				seg := l[j+len(k):]
				if k == "Mem[" || k == "Swp[" {
					seg = seg[:strings.IndexByte(seg+"]", ']')]
					seg = seg[strings.LastIndexAny(seg, "|#*@$%&. ")+1:]
				} else if e := strings.Index(seg, "  "); e > 0 {
					seg = seg[:e]
				}
				if k == "Uptime: " {
					p := strings.Split(strings.Fields(seg)[len(strings.Fields(seg))-1], ":")
					if len(p) == 3 {
						h, _ := strconv.Atoi(p[0])
						m, _ := strconv.Atoi(p[1])
						s, _ := strconv.Atoi(p[2])
						out[k] = []float64{float64(h*3600 + m*60 + s)}
					}
					continue
				}
				for _, n := range num.FindAllString(seg, -1) {
					out[k] = append(out[k], kb(n))
				}
			}
		}
		return out
	}
	rv, cv := vals(real), vals(rec)
	for k, tol := range map[string]float64{"Mem[": 0.02, "Swp[": 0.02, "Tasks: ": 0.02} {
		a, b := rv[k], cv[k]
		if len(a) != len(b) {
			bad = append(bad, fmt.Sprintf("%s %v, clifr %v", k, a, b))
			continue
		}
		for i := range a {
			if k == "Tasks: " && i == 3 {
				continue // running: a moment's count
			}
			if !near(a[i], b[i], tol) {
				bad = append(bad, fmt.Sprintf("%s %v, clifr %v", k, a, b))
				break
			}
		}
	}
	if a, b := rv["Load average: "], cv["Load average: "]; len(a) != 3 || len(b) != 3 || math.Abs(a[0]-b[0]) > 0.10 {
		bad = append(bad, fmt.Sprintf("Load average %v, clifr %v", a, b))
	}
	if a, b := rv["Uptime: "], cv["Uptime: "]; len(a) != 1 || len(b) != 1 || math.Abs(a[0]-b[0]) > 3 {
		bad = append(bad, fmt.Sprintf("Uptime %v, clifr %v", a, b))
	}
	if real.tabs != rec.tabs {
		bad = append(bad, fmt.Sprintf("tabs %q, clifr %q", real.tabs, rec.tabs))
	}
	if real.titles != rec.titles {
		bad = append(bad, fmt.Sprintf("titles:\n  real  %q\n  clifr %q", real.titles, rec.titles))
	}
	// Processes.
	exact := map[string]int{}
	near5 := map[string]int{}
	diffs := map[string]int{}
	var both, onlyReal, onlyRec int
	var examples []string
	for _, pid := range real.order {
		r := real.rows[pid]
		x, ok := rec.rows[pid]
		if !ok {
			onlyReal++
			continue
		}
		both++
		check := func(name string, eq, ok bool) {
			switch {
			case eq:
				exact[name]++
			case ok:
				near5[name]++
			default:
				diffs[name]++
				if len(examples) < 25 {
					examples = append(examples, fmt.Sprintf("pid %d %s:\n  real  %s\n  clifr %s", pid, name, r.line, x.line))
				}
			}
		}
		check("USER", r.user == x.user, false)
		check("PRI", r.pri == x.pri, false)
		check("NI", r.ni == x.ni, false)
		check("VIRT", r.virt == x.virt, near(r.virt, x.virt, 0.05))
		check("RES", r.res == x.res, near(r.res, x.res, 0.05))
		check("SHR", r.shr == x.shr, near(r.shr, x.shr, 0.05))
		check("S", r.s == x.s, true)
		check("CPU%", r.cpu == x.cpu, true)
		check("MEM%", r.mem == x.mem, math.Abs(r.mem-x.mem) <= 0.3)
		check("TIME+", r.time == x.time, math.Abs(r.time-x.time) <= 2)
		check("tree", r.tree == x.tree, false)
		check("Command", r.cmd == x.cmd, false)
	}
	for pid := range rec.rows {
		if _, ok := real.rows[pid]; !ok {
			onlyRec++
		}
	}
	fmt.Printf("processes: real %d, clifr %d, both %d, real only %d, clifr only %d\n", len(real.rows), len(rec.rows), both, onlyReal, onlyRec)
	names := []string{"USER", "PRI", "NI", "VIRT", "RES", "SHR", "S", "CPU%", "MEM%", "TIME+", "tree", "Command"}
	for _, n := range names {
		fmt.Printf("  %-8s exact %4d  near %4d  differ %4d\n", n, exact[n], near5[n], diffs[n])
	}
	sort.Strings(bad)
	for _, b := range bad {
		fmt.Println("HEADER " + b)
	}
	for _, e := range examples {
		fmt.Println("e.g. " + e)
	}
	strict := 0
	for _, n := range []string{"USER", "PRI", "NI", "tree", "Command"} {
		strict += diffs[n]
	}
	if len(bad) > 0 || strict > 0 {
		os.Exit(1)
	}
}
