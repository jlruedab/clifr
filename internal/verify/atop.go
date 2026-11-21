package verify

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"clifr/internal/query"
	"clifr/internal/store"
)

// compareAtop compares atop's screen since boot (atop [-m|-d|-s|-v|-c] 1 1)
// with clifr's at the moment atop ran, in the same process view: system lines by label (and CPU, disk or interface),
// processes by PID. Words must be equal; numbers in atop's forms (53.3G,
// 134423e3, 4m59s, 12%) may differ by 5% or 3 units, as the system moved
// between clifrd's sample and atop's own reading. A process on one side
// only started or ended in between: churn.
func compareAtop(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	a, err := query.AtopSysAt(db, snap.ts)
	if err != nil {
		res.example("%s: %v", snap.cmd, err)
		return res, nil
	}
	a.SetStyle(query.StyleAt(db, snap.ts))
	if f := strings.Fields(snap.cmd); len(f) == 4 {
		a.View = strings.TrimPrefix(f[1], "-")
	}
	text := render(func(sb *strings.Builder) {
		query.PrintAtopSys(sb, a)
		query.PrintAtopProcs(sb, a)
	})
	real, rk := atopIndex(snap.output)
	rec, xk := atopIndex(text)
	res.Real, res.Recon = len(rk), len(xk)
	for _, k := range rk {
		x, ok := rec[k]
		if !ok {
			if strings.HasPrefix(k, "pid ") {
				res.ChurnMissing++
				continue
			}
			res.Missing++
			res.example("%s missing %s", snap.cmd, strings.Join(real[k], " "))
			continue
		}
		res.Matched++
		r := real[k]
		var fields []fieldPair
		for i := range max(len(r), len(x)) {
			var rv, xv string
			if i < len(r) {
				rv = r[i]
			}
			if i < len(x) {
				xv = x[i]
			}
			if k == "ATOP" && (strings.Contains(rv, "/") || strings.Contains(rv, ":")) {
				continue // the date and time atop ran
			}
			if !atopSame(rv, xv) {
				fields = append(fields, fieldPair{atopFieldName(k, i), rv, xv})
			}
		}
		res.compare(snap.cmd+" "+k, fields, func() bool {
			// A process younger than clifrd's sample: clifr has no values
			// of it yet (its exec only).
			pid, err := strconv.Atoi(strings.TrimPrefix(k, "pid "))
			return err == nil && strings.HasPrefix(k, "pid ") && a.StartedAfter(pid, snap.sampleTS)
		})
	}
	for _, k := range xk {
		if _, ok := real[k]; !ok {
			if strings.HasPrefix(k, "pid ") {
				res.ChurnExtra++
				continue
			}
			res.Extra++
			res.example("%s extra %s", snap.cmd, strings.Join(rec[k], " "))
		}
	}
	return res, nil
}

// atopIndex keys atop's lines: a system line by its label, the CPU, disk or
// interface it shows (the second MEM line by its place), a process by PID.
func atopIndex(out string) (map[string][]string, []string) {
	m := map[string][]string{}
	var keys []string
	seen := map[string]int{}
	add := func(k string, f []string) {
		if _, dup := m[k]; !dup {
			keys = append(keys, k)
		}
		m[k] = f
	}
	procs := false
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		f := strings.Fields(strings.ReplaceAll(t, "|", " "))
		switch {
		case len(f) == 0:
			continue
		case strings.HasPrefix(t, "ATOP - "):
			add("ATOP", f)
		case strings.HasPrefix(t, "*** System and Process Activity"):
			procs = true
			add("banner", f)
		case procs && f[0] == "PID":
			add("columns", f)
		case procs:
			if _, err := strconv.Atoi(f[0]); err == nil {
				add("pid "+f[0], f)
			}
		case len(f) > 1 && len(t) > 4 && t[3:5] == " |":
			k := f[0]
			switch f[0] {
			case "cpu":
				k = "cpu " + f[len(f)-3] // cpuNNN w
			case "LVM", "MDD", "DSK", "NET":
				k = f[0] + " " + f[1]
			default:
				seen[f[0]]++
				if n := seen[f[0]]; n > 1 {
					k = fmt.Sprint(f[0], " ", n)
				}
			}
			add(k, f)
		}
	}
	return m, keys
}

func atopFieldName(key string, i int) string {
	if strings.HasPrefix(key, "pid ") {
		return "process column " + strconv.Itoa(i)
	}
	return strings.SplitN(key, " ", 2)[0] + " field " + strconv.Itoa(i)
}

// atopSame: equal words, or numbers within 5% or 3 units. A kernel
// worker's name ends with the work queue it runs at that moment
// (kworker/8:1H-kblockd): compared up to its last dash.
func atopSame(a, b string) bool {
	if a == b {
		return true
	}
	if strings.HasPrefix(a, "kworker/") && strings.HasPrefix(b, "kworker/") {
		if i, j := strings.LastIndexByte(a, '-'), strings.LastIndexByte(b, '-'); i > 0 && j > 0 {
			return a[:i] == b[:j]
		}
	}
	x, okA := atopNumber(a)
	y, okB := atopNumber(b)
	if !okA || !okB {
		return false
	}
	d := math.Abs(x - y)
	return d <= 3 || d <= 0.05*math.Max(math.Abs(x), math.Abs(y))
}

// atopNumber reads a number as atop prints it: plain, with a size unit (B K
// M G T P E), as NNNeE, a percentage, or a time (SS.HHs, MMmSSs, HHhMMm,
// DDdHHh, NdNhNmNs).
func atopNumber(s string) (float64, bool) {
	s = strings.TrimSuffix(s, "%")
	if s == "" {
		return 0, false
	}
	if v, err := strconv.ParseFloat(s, 64); err == nil {
		return v, true
	}
	if i := strings.IndexByte(s, 'e'); i > 0 {
		m, err1 := strconv.ParseFloat(s[:i], 64)
		e, err2 := strconv.Atoi(s[i+1:])
		if err1 == nil && err2 == nil {
			return m * math.Pow(10, float64(e)), true
		}
	}
	if u := strings.IndexByte("BKMGTPE", s[len(s)-1]); u >= 0 {
		if v, err := strconv.ParseFloat(s[:len(s)-1], 64); err == nil {
			return v * math.Pow(1024, float64(u)), true
		}
	}
	// Times: units in d, h, m, s.
	var total, cur float64
	unit := map[byte]float64{'d': 86400, 'h': 3600, 'm': 60, 's': 1}
	num := ""
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c == '.' {
			num += string(c)
			continue
		}
		f, ok := unit[c]
		if !ok || num == "" {
			return 0, false
		}
		v, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return 0, false
		}
		cur = v * f
		total += cur
		num = ""
	}
	if num != "" {
		return 0, false
	}
	return total, true
}
