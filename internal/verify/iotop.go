package verify

import (
	"database/sql"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"clifr/internal/query"
	"clifr/internal/store"
)

// iotopIgnored: what compareIotop does not compare.
const iotopIgnored = "SWAPIN (not recorded); the work-item suffix of kernel worker names; DISK READ/WRITE match within 10% or 1 KiB/s and IO % within 2 points " +
	"(iotop measures from a moment after the checkpoint sample); iotop-c's output is not compared"

// compareIotop compares the second screen of iotop -b -P -n 2 -d INTERVAL,
// started right after a checkpoint sample (clifrd runs it in the
// background), with clifr's iotop for the interval from that sample to the
// process sample nearest iotop's end: the header's totals and each process
// by PID (PRIO, USER and COMMAND exactly). A process on one side only
// started or ended in the interval: churn.
func compareIotop(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	ignoredFields[snap.cmd] = iotopIgnored
	if strings.Contains(snap.output, "Warning: task_delayacct") || strings.Contains(snap.output, "\n  Total DISK READ:") ||
		strings.HasPrefix(snap.output, "  Total DISK READ:") {
		res.example("%s: iotop-c, not compared (clifr prints the Python iotop's output)", snap.cmd)
		return res, nil
	}
	var to sql.NullInt64
	if err := db.QueryRow(`SELECT ts FROM samples WHERE skipped = 0 AND ts > ? ORDER BY ABS(ts - ?) LIMIT 1`,
		snap.sampleTS, snap.endTS).Scan(&to); err != nil && err != sql.ErrNoRows {
		return res, err
	}
	if !to.Valid {
		res.example("%s: no process sample after the checkpoint", snap.cmd)
		return res, nil
	}
	o := query.IotopOpts{Processes: true}
	screens, err := query.Iotop(db, []int64{snap.sampleTS, to.Int64}, o)
	if err != nil {
		return res, err
	}
	st := query.StyleAt(db, to.Int64)
	text := render(func(sb *strings.Builder) {
		query.PrintIotop(sb, screens, o, st, query.IotopDelayAcct(db, to.Int64), query.IotopPIDWidth(db, to.Int64),
			func(ts int64) string { return time.UnixMilli(ts).Format("15:04:05") })
	})
	realTot, realRows := parseIotop(snap.output, 1)
	recTot, recRows := parseIotop(text, 1)
	if realRows == nil {
		res.example("%s: no second screen in iotop's output", snap.cmd)
		return res, nil
	}
	near := func(a, b float64) bool { return math.Abs(a-b) <= max(0.10*max(a, b), 1024) }
	num := func(name string, a, b float64) fieldPair {
		f := fieldPair{name: name, real: iotopRate(a), clifr: iotopRate(b)}
		if near(a, b) {
			f.clifr = f.real
		}
		return f
	}
	never := func() bool { return false }
	// Churn: started or ended between the checkpoint sample and the later
	// of clifr's end sample and iotop's last refresh (iotop lists the
	// processes there at its last refresh, a new one with zeros).
	churnTo := max(to.Int64, snap.endTS)
	for _, k := range []string{"Total", "Actual"} {
		r, x := realTot[k], recTot[k]
		res.Real++
		res.Recon++
		res.Matched++
		res.compare(k, []fieldPair{num(k+" DISK READ", r[0], x[0]), num(k+" DISK WRITE", r[1], x[1])}, never)
	}
	for pid, r := range realRows {
		if snap.ignore[pid] {
			continue
		}
		res.Real++
		x, ok := recRows[pid]
		if !ok {
			if procChurn(db, pid, snap.sampleTS, churnTo) {
				res.ChurnMissing++
				continue
			}
			res.Missing++
			res.example("%s missing pid %d %s", snap.cmd, pid, r.cmd)
			continue
		}
		res.Matched++
		// A kernel worker's name ends in its current work item.
		fields := []fieldPair{{"PRIO", r.prio, x.prio}, {"USER", r.user, x.user}, {"COMMAND", kworkerBase(r.cmd), kworkerBase(x.cmd)},
			num("DISK READ", r.read, x.read), num("DISK WRITE", r.write, x.write)}
		if r.io >= 0 && x.io >= 0 {
			f := fieldPair{"IO", fmt.Sprintf("%.2f %%", r.io), fmt.Sprintf("%.2f %%", x.io)}
			if math.Abs(r.io-x.io) <= 2 {
				f.clifr = f.real
			}
			fields = append(fields, f)
		}
		res.compare(fmt.Sprintf("%s pid %d", snap.cmd, pid), fields, never)
	}
	for pid, x := range recRows {
		if snap.ignore[pid] {
			continue
		}
		res.Recon++
		if _, ok := realRows[pid]; ok {
			continue
		}
		if procChurn(db, pid, snap.sampleTS, churnTo) {
			res.ChurnExtra++
			continue
		}
		res.Extra++
		res.example("%s extra pid %d %s", snap.cmd, pid, x.cmd)
	}
	return res, nil
}

type iotopRow struct {
	prio, user, cmd string
	read, write, io float64 // bytes/s; io: % (-1: not shown)
}

// parseIotop reads screen n (0: the first) of iotop -b output, the Python
// iotop's in any build: the header's totals ("Total", and "Actual" for
// Current or Actual) and the lines by PID (RHEL's printed as b'...').
func parseIotop(out string, n int) (map[string][2]float64, map[int]iotopRow) {
	tot := map[string][2]float64{}
	var rows map[int]iotopRow
	screen := -1
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "Total DISK READ") {
			screen++
			if screen == n {
				rows = map[int]iotopRow{}
			}
		}
		if screen != n {
			continue
		}
		if k, ok := iotopTotal(l); ok {
			_, after, _ := strings.Cut(l, ":")
			a, b, _ := strings.Cut(after, "|")
			_, b, _ = strings.Cut(b, ":")
			tot[k] = [2]float64{iotopParseRate(a), iotopParseRate(b)}
			continue
		}
		l = pyUnrepr(l)
		f := strings.Fields(l)
		if len(f) < 8 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		r := iotopRow{prio: f[1], user: f[2], read: iotopParseRate(f[3] + " " + f[4]), write: iotopParseRate(f[5] + " " + f[6]), io: -1}
		rest := f[7:]
		switch {
		case rest[0] == "?unavailable?":
			rest = rest[1:]
		case len(rest) >= 4 && rest[1] == "%" && rest[3] == "%": // SWAPIN, IO
			r.io, _ = strconv.ParseFloat(rest[2], 64)
			rest = rest[4:]
		case len(rest) >= 3 && rest[0] == "?" && rest[2] == "%": // clifr's: SWAPIN not recorded
			r.io, _ = strconv.ParseFloat(rest[1], 64)
			rest = rest[3:]
		}
		r.cmd = strings.Join(rest, " ")
		rows[pid] = r
	}
	return tot, rows
}

func iotopTotal(l string) (string, bool) {
	switch {
	case strings.HasPrefix(l, "Total DISK READ"):
		return "Total", true
	case strings.HasPrefix(l, "Current DISK READ"), strings.HasPrefix(l, "Actual DISK READ"):
		return "Actual", true
	}
	return "", false
}

// iotopParseRate reads "1499.57 B/s" or "2.00 K/s" as bytes per second.
func iotopParseRate(s string) float64 {
	f := strings.Fields(s)
	if len(f) < 2 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	if i := strings.IndexByte("BKMGTPE", f[1][0]); i > 0 {
		v *= math.Pow(1024, float64(i))
	}
	return v
}

func iotopRate(v float64) string { return strconv.FormatFloat(v, 'f', 0, 64) + " B/s" }

// pyUnrepr undoes Python's repr of bytes (b'...' or b"..."), as RHEL's
// iotop prints its lines; other lines are returned as they are.
func pyUnrepr(l string) string {
	if len(l) < 3 || l[0] != 'b' || (l[1] != '\'' && l[1] != '"') || l[len(l)-1] != l[1] {
		return l
	}
	s := l[2 : len(l)-1]
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b = append(b, s[i])
			continue
		}
		i++
		switch s[i] {
		case 't':
			b = append(b, '\t')
		case 'n':
			b = append(b, '\n')
		case 'r':
			b = append(b, '\r')
		case 'x':
			if i+2 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					b = append(b, byte(v))
					i += 2
					continue
				}
			}
			b = append(b, '\\', 'x')
		default:
			b = append(b, s[i])
		}
	}
	return string(b)
}
