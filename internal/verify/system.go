package verify

import (
	"database/sql"
	"math"
	"regexp"
	"strconv"
	"strings"

	"clifr/internal/query"
	"clifr/internal/store"
)

// The system-wide tools. Without an interval they print averages since boot,
// which `clifr <tool> --at` computes from the counters of the checkpoint
// sample. The real tool reads its counters a little later (GapMS), so numbers
// are compared with a tolerance instead of as text.

// systemCommands are compared by compareSystem.
var systemCommands = []string{"uptime", "vmstat", "mpstat -P ALL", "iostat -dx"}

func init() {
	ignoredFields["uptime"] = "the number of users before 2026-11-20 (not recorded); loads may differ by 0.05, the uptime by one minute"
	ignoredFields["vmstat"] = "r and b (the moment the tool ran); numbers match within 1% or 0.02 (free, buff, cache: 2%)"
	ignoredFields["mpstat -P ALL"] = "none; numbers match within 1% or 0.02"
	ignoredFields["iostat -dx"] = "none; numbers match within 1% or 0.02"
}

// sysTable is a tool's output as rows of named columns, keyed by the row's
// label (CPU, device; "" for a single row).
type sysTable map[string]map[string]string

// parseColumns reads the table that starts at the header line containing
// marker. keyCol names the label column ("" for none); the first skip fields
// of every row are dropped (mpstat's time).
func parseColumns(out, marker, keyCol string, skip int) sysTable {
	t := sysTable{}
	var head []string
	for _, line := range strings.Split(out, "\n") {
		fs := strings.Fields(line)
		if head == nil {
			if strings.Contains(line, marker) && len(fs) > skip {
				head = fs[skip:]
			}
			continue
		}
		if len(fs) != len(head)+skip {
			if len(t) > 0 {
				break
			}
			continue
		}
		fs = fs[skip:]
		row, key := map[string]string{}, ""
		for i, h := range head {
			if h == keyCol {
				key = fs[i]
			} else {
				row[h] = fs[i]
			}
		}
		t[key] = row
	}
	return t
}

// near reports whether two printed numbers agree within the tolerance.
func near(real, clifr string, rel, abs float64) bool {
	if real == clifr {
		return true
	}
	a, err1 := strconv.ParseFloat(real, 64)
	b, err2 := strconv.ParseFloat(clifr, 64)
	if err1 != nil || err2 != nil {
		return false
	}
	d := math.Abs(a - b)
	return d <= abs+1e-9 || d <= rel*math.Max(math.Abs(a), math.Abs(b))
}

var uptimeRe = regexp.MustCompile(`up\s+(?:(\d+) days?,\s+)?(?:(\d+):(\d+)|(\d+) min),.*load average: ([\d.]+), ([\d.]+), ([\d.]+)`)

var uptimeUsersRe = regexp.MustCompile(`,\s+(\d+) users?,`)

// parseUptime turns an uptime line into one row: minutes up and the loads.
func parseUptime(out string) sysTable {
	m := uptimeRe.FindStringSubmatch(out)
	if m == nil {
		return sysTable{}
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	min := n(m[1])*1440 + n(m[2])*60 + n(m[3]) + n(m[4])
	row := map[string]string{"up_min": strconv.Itoa(min), "load1": m[5], "load5": m[6], "load15": m[7]}
	if u := uptimeUsersRe.FindStringSubmatch(out); u != nil {
		row["users"] = u[1]
	}
	return sysTable{"": row}
}

// between: v lies between a and b (either order), or near one of them.
func between(v, a, b string, rel, abs float64) bool {
	if near(v, a, rel, abs) || near(v, b, rel, abs) {
		return true
	}
	x, err1 := strconv.ParseFloat(v, 64)
	y, err2 := strconv.ParseFloat(a, 64)
	z, err3 := strconv.ParseFloat(b, 64)
	return err1 == nil && err2 == nil && err3 == nil && min(y, z) <= x && x <= max(y, z)
}

func render(print func(*strings.Builder)) string {
	var sb strings.Builder
	print(&sb)
	return sb.String()
}

func compareSystem(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	rel, abs := map[string]float64{}, map[string]float64{}
	skip := map[string]bool{}
	// reconAt is clifr's output at the system sample ts, parsed.
	reconAt := func(ts int64) (sysTable, error) {
		spans, err := query.SysSpans(db, query.Window{At: ts}, 0)
		if err != nil || spans[0].To != ts {
			return nil, err
		}
		switch snap.cmd {
		case "uptime":
			rows, err := query.Uptime(db, spans)
			if err != nil {
				return nil, err
			}
			rows[0].Users = query.UsersAt(db, ts, query.Procps3(db, ts))
			return parseUptime(render(func(sb *strings.Builder) { query.PrintUptime(sb, rows) })), nil
		case "vmstat":
			rows, err := query.VMStat(db, spans)
			if err != nil {
				return nil, err
			}
			return parseColumns(render(func(sb *strings.Builder) { query.PrintVMStat(sb, rows) }), " r  b", "", 0), nil
		case "mpstat -P ALL":
			rows, err := query.MPStat(db, spans, "ALL")
			if err != nil {
				return nil, err
			}
			return parseColumns(render(func(sb *strings.Builder) { query.PrintMPStat(sb, rows) }), "%usr", "CPU", 1), nil
		case "iostat -dx":
			reps, err := query.IOStat(db, spans, false)
			if err != nil {
				return nil, err
			}
			return parseColumns(render(func(sb *strings.Builder) { query.PrintIOStat(sb, reps, true, true) }), "Device", "Device", 0), nil
		}
		return nil, nil
	}
	recon, err := reconAt(snap.sampleTS)
	if err != nil {
		return res, err
	}
	if recon == nil {
		res.example("no system counters at the checkpoint sample")
		return res, nil
	}
	// The same at the next system sample: the real tool read the counters
	// between the two, so a value between them changed during the gap (a
	// since-boot average moves fast on a young system: a VM writing 1 MB in
	// the 100 ms gap, minutes after boot, moved vmstat's bo by 1.6%).
	var next sysTable
	var nextTS sql.NullInt64
	db.QueryRow(`SELECT MIN(ts) FROM sys_samples WHERE ts > ?`, snap.sampleTS).Scan(&nextTS)
	if nextTS.Valid {
		if next, err = reconAt(nextTS.Int64); err != nil {
			return res, err
		}
	}
	var real sysTable
	switch snap.cmd {
	case "uptime":
		real = parseUptime(snap.output)
		abs["up_min"], abs["load1"], abs["load5"], abs["load15"] = 1, 0.05, 0.05, 0.05
		if recon[""]["users"] == "" { // logins not recorded
			skip["users"] = true
		}
	case "vmstat":
		real = parseColumns(snap.output, " r  b", "", 0)
		skip["r"], skip["b"] = true, true
		rel["free"], rel["buff"], rel["cache"] = 0.02, 0.02, 0.02
		for _, c := range []string{"us", "sy", "id", "wa", "st", "gu", "si", "so", "bi", "bo", "in", "cs"} {
			abs[c] = 1 // whole numbers: a rounding step
		}
	case "mpstat -P ALL":
		real = parseColumns(snap.output, "%usr", "CPU", 1)
	case "iostat -dx":
		real = parseColumns(snap.output, "Device", "Device", 0)
	}
	res.Real, res.Recon = len(real), len(recon)
	for key, rr := range real {
		sr, ok := recon[key]
		if !ok {
			res.Missing++
			res.example("%s %s: not reconstructed", snap.cmd, key)
			continue
		}
		res.Matched++
		exact, changed := true, false
		for col, rv := range rr {
			if skip[col] {
				continue
			}
			r, a := rel[col], abs[col]
			if r == 0 {
				r = 0.01
			}
			if a == 0 {
				a = 0.02
			}
			if !near(rv, sr[col], r, a) {
				if nr, ok := next[key]; ok && between(rv, sr[col], nr[col], r, a) {
					changed = true
					continue
				}
				exact = false
				res.FieldDiffs[col]++
				if res.FieldDiffs[col] <= 3 {
					res.example("%s %s: real %q, clifr %q", strings.TrimSpace(snap.cmd+" "+key), col, rv, sr[col])
				}
			}
		}
		switch {
		case exact && changed:
			res.ChurnChanged++
		case exact:
			res.Exact++
		}
	}
	for key := range recon {
		if _, ok := real[key]; !ok {
			res.Extra++
			res.example("%s %s: only in the reconstruction", snap.cmd, key)
		}
	}
	return res, nil
}
