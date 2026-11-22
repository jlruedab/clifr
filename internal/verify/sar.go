package verify

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/query"
	"clifr/internal/store"
)

// SarRow is one line of a sar report: its kind ("t" an interval, "Average",
// "Summary"), its item (a CPU, interface, file system; "" none) and values.
type SarRow struct {
	Kind, Item string
	Vals       []string
}

// SarReport is every row of one report (by its column titles), in order.
type SarReport struct {
	Titles string
	Rows   []SarRow
}

// SarOutput is sar's output split up: the first line, the reports (each
// once: live sar prints the intervals and the averages apart, sar -f may
// repeat a header) and the number of LINUX RESTART lines.
type SarOutput struct {
	First    string
	Reports  []*SarReport
	Restarts int
}

var sarStamp = regexp.MustCompile(`^(\d\d:\d\d:\d\d( [AP]M)?|Average:|Summary:)\s`)

// ParseSar splits sar's output (live or sar -f, C locale).
func ParseSar(out string) SarOutput {
	var o SarOutput
	by := map[string]*SarReport{}
	var cur *SarReport
	isNum := func(s string) bool { _, err := strconv.ParseFloat(s, 64); return err == nil }
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(l, "#"):
			continue
		case strings.HasPrefix(l, "Linux "):
			o.First = l
			continue
		case strings.Contains(l, "LINUX RESTART"):
			o.Restarts++
			continue
		}
		m := sarStamp.FindString(l)
		if m == "" {
			continue
		}
		f := strings.Fields(l[len(m):])
		if len(f) == 0 {
			continue
		}
		if !isNum(f[0]) && !isNum(f[len(f)-1]) && (len(f) < 2 || !isNum(f[1])) {
			t := strings.Join(f, " ")
			if by[t] == nil {
				by[t] = &SarReport{Titles: t}
				o.Reports = append(o.Reports, by[t])
			}
			cur = by[t]
			continue
		}
		if cur == nil {
			continue
		}
		r := SarRow{Kind: "t"}
		if s := strings.TrimSpace(m); s == "Average:" || s == "Summary:" {
			r.Kind = strings.TrimSuffix(s, ":")
		}
		var item []string
		for _, x := range f {
			if isNum(x) {
				r.Vals = append(r.Vals, x)
			} else {
				item = append(item, x)
			}
		}
		r.Item = strings.Join(item, " ")
		cur.Rows = append(cur.Rows, r)
	}
	return o
}

// SarNear: a value of sar's (rates and percentages with decimals, sizes and
// counts without) within 5%, or 0.5 for one with decimals.
func SarNear(a, b string) bool {
	if a == b {
		return true
	}
	x, err1 := strconv.ParseFloat(a, 64)
	y, err2 := strconv.ParseFloat(b, 64)
	if err1 != nil || err2 != nil {
		return false
	}
	d := math.Abs(x - y)
	return d <= 0.05*max(math.Abs(x), math.Abs(y)) || strings.Contains(a, ".") && d <= 0.5
}

// SarRowKey groups rows for matching: kind and item, the n-th of them.
func SarRowKey(r SarRow) string { return r.Kind + "|" + r.Item }

// SarRows indexes a report's rows by SarRowKey, in order.
func SarRows(r *SarReport) (map[string][]SarRow, []string) {
	m := map[string][]SarRow{}
	var keys []string
	for _, x := range r.Rows {
		k := SarRowKey(x)
		if _, ok := m[k]; !ok {
			keys = append(keys, k)
		}
		m[k] = append(m[k], x)
	}
	sort.Strings(keys)
	return m, keys
}

// sarVerifyActs: the reports of clifrd's sar capture (recorder.sarReports)
// that clifr makes.
func sarVerifyActs() []query.SarAct {
	acts := []query.SarAct{{Key: "cpu", All: true, CPUs: []int{query.SarAllCPU}}, {Key: "mem", All: true}, {Key: "softnet", CPUs: []int{query.SarAllCPU}}}
	for _, k := range []string{"pcsw", "swap", "paging", "io", "disk", "huge", "swapmem", "ktables", "queue", "netdev", "netedev", "nfs", "nfsd",
		"sock", "ip", "eip", "icmp", "eicmp", "tcp", "etcp", "udp", "sock6", "ip6", "eip6", "icmp6", "eicmp6", "udp6", "fs"} {
		acts = append(acts, query.SarAct{Key: k})
	}
	return acts
}

// compareSar compares sar's reports over one interval (clifrd runs sar
// REPORTS INTERVAL 1 in the background at a checkpoint) with clifr's sar
// from the checkpoint sample to the system sample nearest sar's end: each
// report's rows by item (CPU, interface, file system), the values within 5%
// (or 0.5 for decimals): sar reads a moment after the checkpoint sample.
func compareSar(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	ignoredFields[snap.cmd] = "the times (sar reads a moment after the checkpoint); values within 5% or 0.5; " +
		"run-queue size, blocked tasks, socket and dentry counts and memory sizes are instantaneous (compared within 5%)"
	var to int64
	if err := db.QueryRow(`SELECT ts FROM sys_samples WHERE ts > ? ORDER BY ABS(ts - ?) LIMIT 1`, snap.sampleTS, snap.endTS).Scan(&to); err != nil {
		res.example("%s: no system sample after the checkpoint", snap.cmd)
		return res, nil
	}
	st := query.StyleAt(db, to)
	o := query.SarOpts{Acts: sarVerifyActs(), Times: []int64{snap.sampleTS, to}, Version: st.Sar}
	d, err := query.Sar(db, snap.sampleTS, to, o)
	if err != nil {
		return res, err
	}
	text := render(func(sb *strings.Builder) { query.PrintSar(sb, d, o) })
	real, rec := ParseSar(snap.output), ParseSar(text)
	recBy := map[string]*SarReport{}
	for _, r := range rec.Reports {
		recBy[r.Titles] = r
	}
	for _, rr := range real.Reports {
		cr := recBy[rr.Titles]
		if cr == nil {
			continue // a report clifr does not make (or a release's other columns)
		}
		titles := strings.Fields(rr.Titles)
		rm, keys := SarRows(rr)
		cm, _ := SarRows(cr)
		for _, k := range keys {
			for n, x := range rm[k] {
				res.Real++
				if n >= len(cm[k]) {
					res.Missing++
					res.example("%s: %s: missing %s", snap.cmd, titles[0], k)
					continue
				}
				res.Recon++
				res.Matched++
				y := cm[k][n]
				var fields []fieldPair
				for i := range x.Vals {
					name := fmt.Sprint(i)
					if j := len(titles) - len(x.Vals) + i; j >= 0 && j < len(titles) {
						name = titles[j]
					}
					c := ""
					if i < len(y.Vals) {
						c = y.Vals[i]
					}
					f := fieldPair{name, x.Vals[i], c}
					if SarNear(x.Vals[i], c) {
						f.clifr = f.real
					}
					fields = append(fields, f)
				}
				res.compare(fmt.Sprintf("%s %s %s", snap.cmd[:3], titles[0], k), fields, func() bool { return false })
			}
		}
		for k, ys := range cm {
			if n := len(rm[k]); len(ys) > n {
				res.Recon += len(ys) - n
				res.Extra += len(ys) - n
				res.example("%s: %s: extra %s", snap.cmd, titles[0], k)
			}
		}
	}
	return res, nil
}
