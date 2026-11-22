// clifr iotop: the batch output (iotop -b) of iotop 0.6, the Python iotop
// every distribution installs as iotop (Ubuntu 0.6-24 and 0.6-42; RHEL's
// 0.6-18 and 0.6-30, a branch of its own). The computations, formats and
// sort follow iotop's code (iotop/ui.py and iotop/data.py, Copyright (c) 2007
// Guillaume Chazarain, GPL-2.0-or-later; packaging/notices/iotop.txt).

package query

import (
	"database/sql"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// IotopOpts are iotop's options that change what it prints.
type IotopOpts struct {
	Only, Processes, Accumulated, Kilobytes, Time bool
	Quiet                                         int   // -q given 0-3 times
	PIDs, UIDs                                    []int // -p, -u (empty: all)
}

// IotopScreen is one refresh of iotop: the first (zeros: iotop has nothing
// to compare yet) or the interval between two process samples.
type IotopScreen struct {
	TS          int64       `json:"ts_ms"`
	From        int64       `json:"from_ms,omitempty"` // 0: iotop's first screen
	Seconds     float64     `json:"seconds"`
	TotalRead   float64     `json:"total_read_bytes_s"` // all threads of the processes watched
	TotalWrite  float64     `json:"total_write_bytes_s"`
	ActualRead  float64     `json:"actual_read_bytes_s"` // /proc/vmstat pgpgin, pgpgout
	ActualWrite float64     `json:"actual_write_bytes_s"`
	Procs       []IotopProc `json:"processes"`
	// WholeIO: recorded before schema 13, the counters of /proc/PID/io,
	// which add a reaped child's I/O to its parent.
	WholeIO bool `json:"whole_process_io,omitempty"`
	first   bool
}

// IotopProc is one line: bytes read and written (in the screen's interval,
// or since iotop first saw the process with -a), the written bytes less the
// cancelled ones as iotop shows them, and the block I/O delay averaged over
// the threads (ns).
type IotopProc struct {
	PID      int     `json:"pid"`
	Prio     string  `json:"prio"`
	User     string  `json:"user"`
	Read     int64   `json:"read_bytes"`
	Write    int64   `json:"write_bytes"` // less cancelled writes
	BlkioNS  float64 `json:"blkio_delay_ns"`
	Seconds  float64 `json:"seconds"` // what Read and Write are over
	Command  string  `json:"command"`
	rawWrite int64   // with cancelled writes: the sort key and -o
	cancel   int64
	order    int
}

type iotopVals struct {
	id                     int64
	pid, uid               int
	comm, cmdline          string
	argv0                  int
	rb, wb, cw, blkio, thr int64
	ioprio, dif            sql.NullInt64
	nice, policy           int
	upMS                   int64
	whole                  bool // /proc/PID/io's counters (before schema 13)
}

// iotopAt returns the processes with a sample at or before s, alive at s,
// with their values at s (event-only processes have none: iotop could not
// see them either).
func iotopAt(db *store.DB, s int64) (map[int64]iotopVals, error) {
	var up sql.NullInt64
	db.QueryRow(`SELECT uptime_ms FROM sys_samples WHERE ts = ?`, s).Scan(&up)
	rows, err := db.Query(`
		SELECT p.id, p.pid, p.uid, p.comm, COALESCE(p.cmdline, ''), COALESCE(p.argv0_len, 0),
		       COALESCE(x.read_bytes, 0), COALESCE(x.write_bytes, 0), COALESCE(x.cancelled_write_bytes, 0),
		       COALESCE(x.blkio_all_ticks, x.blkio_ticks, 0), COALESCE(x.threads, 1), x.ioprio, x.ioprio_dif,
		       COALESCE(x.nice, 0), COALESCE(x.policy, 0),
		       x.thr_read_bytes, x.thr_write_bytes, x.thr_cancelled_write_bytes
		FROM processes p
		JOIN proc_samples x ON x.proc_id = p.id
		     AND x.ts = (SELECT MAX(ts) FROM proc_samples WHERE proc_id = p.id AND ts <= ?1)
		WHERE p.first_seen <= ?1 AND COALESCE(p.last_seen, ?2) >= ?1
		  AND (p.ended IS NULL OR p.ended > ?1)`, s, openEnd)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]iotopVals{}
	for rows.Next() {
		var v iotopVals
		var trb, twb, tcw sql.NullInt64
		if err := rows.Scan(&v.id, &v.pid, &v.uid, &v.comm, &v.cmdline, &v.argv0, &v.rb, &v.wb, &v.cw, &v.blkio, &v.thr,
			&v.ioprio, &v.dif, &v.nice, &v.policy, &trb, &twb, &tcw); err != nil {
			return nil, err
		}
		// The threads' own counters (schema 13), as iotop adds them up;
		// before, /proc/PID/io's, which also hold reaped children's I/O.
		if trb.Valid {
			v.rb, v.wb, v.cw = trb.Int64, twb.Int64, tcw.Int64
		} else {
			v.whole = true
		}
		v.upMS = up.Int64
		out[v.id] = v
	}
	return out, rows.Err()
}

// IotopTimes are the process sample times iotop's screens end at. At a
// moment: the two process samples at or before it (one interval). Over a
// range: the first process sample in it, then each one at least stepMS
// (less 10%) after the previous one (0: every one), at most count in all (0: no
// limit). A reboot in between is an error.
func IotopTimes(db *store.DB, w Window, stepMS int64, count int) ([]int64, error) {
	if !w.IsRange() {
		rows, err := db.Query(`SELECT ts, uptime_ms FROM sys_samples WHERE ts <= ?
			AND ts IN (SELECT ts FROM samples WHERE skipped = 0) ORDER BY ts DESC LIMIT 2`, w.At)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var ts, up []int64
		for rows.Next() {
			var t, u int64
			if err := rows.Scan(&t, &u); err != nil {
				return nil, err
			}
			ts, up = append([]int64{t}, ts...), append([]int64{u}, up...)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if len(ts) < 2 {
			return nil, fmt.Errorf("iotop: needs two process samples at or before %s", FormatMS(w.At))
		}
		if up[1] < up[0] {
			return nil, fmt.Errorf("iotop: the system rebooted between the process samples of %s and %s", FormatMS(ts[0]), FormatMS(ts[1]))
		}
		return ts, nil
	}
	// Samples come a few ms early or late: -d 30 over 30 s samples takes
	// every one.
	spans, err := ProcSpans(db, w, stepMS-stepMS/10)
	if err != nil {
		return nil, err
	}
	ts := []int64{spans[0].From}
	for _, sp := range spans {
		if sp.From != ts[len(ts)-1] {
			return nil, fmt.Errorf("iotop: the system rebooted at about %s, within the range", FormatMS(sp.From))
		}
		if count > 0 && len(ts) == count {
			break
		}
		ts = append(ts, sp.To)
	}
	return ts, nil
}

// IotopDelayAcct reports whether iotop 0.6 shows SWAPIN and IO % for the
// recording at t: kernel.task_delayacct is 1, or the kernel has no such
// sysctl (before 5.14: delay accounting is on unless booted with
// nodelayacct, which clifr cannot see). Without a recorded sysctl list, the
// kernel release decides.
func IotopDelayAcct(db *store.DB, t int64) bool {
	if lines, _, ok, err := FileAt(db, "sysctl", t); err == nil && ok {
		for _, l := range lines {
			if v, ok := strings.CutPrefix(l, "kernel.task_delayacct = "); ok {
				return strings.TrimSpace(v) == "1"
			}
		}
		return true
	}
	rel := MetaAt(db, "uname_release", t)
	maj, rest, _ := strings.Cut(rel, ".")
	mi, _, _ := strings.Cut(rest, ".")
	a, err1 := strconv.Atoi(maj)
	b, err2 := strconv.Atoi(mi)
	return err1 == nil && err2 == nil && (a < 5 || a == 5 && b < 14)
}

// IotopPIDWidth is iotop's PID column: the digits of kernel.pid_max.
func IotopPIDWidth(db *store.DB, t int64) int {
	if lines, _, ok, err := FileAt(db, "sysctl", t); err == nil && ok {
		for _, l := range lines {
			if v, ok := strings.CutPrefix(l, "kernel.pid_max = "); ok {
				return len(strings.TrimSpace(v))
			}
		}
	}
	return 7 // 4194304, systemd's setting on 64-bit hosts
}

// Iotop computes iotop's screens at the sample times ts (process samples,
// in order): the first as iotop's first refresh, then one per interval.
// delayAcct: iotop shows IO % (and sorts by it).
func Iotop(db *store.DB, ts []int64, o IotopOpts) ([]IotopScreen, error) {
	watched := func(v iotopVals) bool {
		if len(o.PIDs) > 0 && !containsInt(o.PIDs, v.pid) {
			return false
		}
		return len(o.UIDs) == 0 || containsInt(o.UIDs, v.uid)
	}
	type accum struct {
		rb, wb, cw int64
		blkio      float64
		sinceMS    int64 // uptime when iotop first saw it
	}
	acc := map[int64]*accum{}
	order := map[int64]int{} // iotop keeps processes in the order it first saw them
	var prev map[int64]iotopVals
	var out []IotopScreen
	for i, t := range ts {
		cur, err := iotopAt(db, t)
		if err != nil {
			return nil, err
		}
		ids := make([]int64, 0, len(cur))
		for id, v := range cur {
			if watched(v) {
				ids = append(ids, id)
			}
		}
		// New processes in /proc's order (by PID), after the ones seen before.
		sort.Slice(ids, func(a, b int) bool { return cur[ids[a]].pid < cur[ids[b]].pid })
		for _, id := range ids {
			if _, ok := order[id]; !ok {
				order[id] = len(order)
			}
		}
		sc := IotopScreen{TS: t, first: i == 0}
		var secs float64
		if i > 0 {
			sc.From = ts[i-1]
			var up0, up1 int64
			for _, v := range cur {
				up1 = v.upMS
				break
			}
			for _, v := range prev {
				up0 = v.upMS
				break
			}
			secs = float64(up1-up0) / 1000
			if secs <= 0 {
				secs = float64(t-ts[i-1]) / 1000
			}
			sc.Seconds = secs
			var s0, s1 store.SysSample
			if s0, err = loadSys(db, ts[i-1]); err != nil {
				return nil, fmt.Errorf("iotop: no system sample at %s: %w", FormatMS(ts[i-1]), err)
			}
			if s1, err = loadSys(db, t); err != nil {
				return nil, fmt.Errorf("iotop: no system sample at %s: %w", FormatMS(t), err)
			}
			sc.ActualRead = float64(max(s1.PgpgIn-s0.PgpgIn, 0)*1024) / secs
			sc.ActualWrite = float64(max(s1.PgpgOut-s0.PgpgOut, 0)*1024) / secs
		}
		var totR, totW int64
		for _, id := range ids {
			c := cur[id]
			sc.WholeIO = sc.WholeIO || c.whole
			p, seen := prev[id]
			a := acc[id]
			if a == nil {
				a = &accum{sinceMS: c.upMS}
				acc[id] = a
			}
			var rb, wb, cw int64
			var blkio float64
			if seen && i > 0 {
				rb, wb, cw = max(c.rb-p.rb, 0), max(c.wb-p.wb, 0), max(c.cw-p.cw, 0)
				// iotop -P: each thread's delay over the interval, summed and
				// divided by the number of threads.
				blkio = float64(max(c.blkio-p.blkio, 0)) * 1e9 / float64(procfs.ClockTicks) / float64(max(c.thr, 1))
			}
			a.rb, a.wb, a.cw, a.blkio = a.rb+rb, a.wb+wb, a.cw+cw, a.blkio+blkio
			totR, totW = totR+rb, totW+wb
			pr := IotopProc{PID: c.pid, Prio: iotopPrio(c), User: iotopUser(c.uid), Command: iotopCmdline(c), order: order[id]}
			if o.Accumulated {
				pr.Read, pr.rawWrite, pr.cancel, pr.BlkioNS = a.rb, a.wb, a.cw, a.blkio
				pr.Seconds = float64(c.upMS-a.sinceMS) / 1000
			} else {
				pr.Read, pr.rawWrite, pr.cancel, pr.BlkioNS, pr.Seconds = rb, wb, cw, blkio, secs
			}
			pr.Write = max(pr.rawWrite-pr.cancel, 0)
			sc.Procs = append(sc.Procs, pr)
		}
		if secs > 0 {
			sc.TotalRead, sc.TotalWrite = float64(totR)/secs, float64(totW)/secs
		}
		out = append(out, sc)
		prev = cur
	}
	return out, nil
}

func containsInt(l []int, v int) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// iotopPrio is the PRIO column: "?dif" when the threads differ, else the
// recorded priority as iotop names it; recordings before schema 13 derive
// it from the policy and nice value as iotop does for a task without one.
func iotopPrio(v iotopVals) string {
	if v.dif.Valid && v.dif.Int64 == 1 {
		return "?dif"
	}
	p := int(v.ioprio.Int64)
	if !v.ioprio.Valid || p < 0 {
		switch v.policy {
		case 1, 2:
			p = 1<<13 | (v.nice+20)/5
		case 5:
			p = 3 << 13
		default:
			p = 2<<13 | (v.nice+20)/5
		}
	}
	switch p >> 13 {
	case 1:
		return fmt.Sprintf("rt/%d", p&8191)
	case 3:
		return "idle"
	}
	return fmt.Sprintf("be/%d", p&8191)
}

// iotopUser is the owner of /proc/PID by name, else the number.
func iotopUser(uid int) string {
	n := UserName(uid, false)
	if n == "" {
		return strconv.Itoa(uid)
	}
	return n
}

// iotopCmdline is iotop's COMMAND: the first 4096 characters of the command
// line, argv[0] without its directory when it is a path, the arguments
// joined by spaces, stripped; a kernel thread as [name].
func iotopCmdline(v iotopVals) string {
	if v.cmdline == "" {
		return "[" + v.comm + "]"
	}
	s := v.cmdline
	if r := []rune(s); len(r) > 4096 {
		s = string(r[:4096])
	}
	a0 := min(v.argv0, len(s))
	if a0 <= 0 { // not recorded (older recordings): up to the first space
		if a0 = strings.IndexByte(s, ' '); a0 < 0 {
			a0 = len(s)
		}
	}
	if strings.HasPrefix(s, "/") {
		s = s[strings.LastIndexByte(s[:a0], '/')+1:]
	}
	return strings.TrimFunc(s, unicode.IsSpace)
}

// iotopStyle is the Python iotop build: "" 0.6-42 (Ubuntu 24.04 and later,
// most others), "0.6-24" (Ubuntu 22.04: sorts by IO % even without delay
// accounting; ?unavailable? one space further), "rhel" (RHEL 8 and 9:
// "Total DISK READ :", "Actual DISK READ:", each line printed as Python
// bytes, b'...').
func iotopStyle(st ToolStyle) string { return st.Iotop }

// PrintIotop writes the screens as iotop -b does.
func PrintIotop(w io.Writer, screens []IotopScreen, o IotopOpts, st ToolStyle, delayAcct bool, pidWidth int, clockOf func(int64) string) {
	style := iotopStyle(st)
	bw := func(v float64) string { return iotopSize(o.Kilobytes, v) + "/s" }
	for _, sc := range screens {
		sum1, sum2 := "Total DISK READ:   %s | Total DISK WRITE:   %s", "Current DISK READ: %s | Current DISK WRITE: %s"
		if style == "rhel" {
			sum1, sum2 = "Total DISK READ : %s | Total DISK WRITE : %s", "Actual DISK READ: %s | Actual DISK WRITE: %s"
		}
		summary := []string{
			fmt.Sprintf(sum1, rjust(bw(sc.TotalRead), 14), rjust(bw(sc.TotalWrite), 14)),
			fmt.Sprintf(sum2, rjust(bw(sc.ActualRead), 14), rjust(bw(sc.ActualWrite), 14)),
		}
		id := strings.Repeat(" ", max(0, pidWidth-3)) + "PID"
		if !o.Processes {
			id = strings.Repeat(" ", max(0, pidWidth-3)) + "TID"
		}
		titles := id + "  PRIO" + "  USER" + "     DISK READ" + "  DISK WRITE" + "  SWAPIN" + "      IO" + "    COMMAND"
		procs := iotopSorted(sc, o, style, delayAcct)
		var lines []string
		for _, p := range procs {
			lines = append(lines, iotopLine(p, o, style, delayAcct, pidWidth))
		}
		if o.Time {
			now := clockOf(sc.TS) + " "
			titles = "    TIME" + titles
			for i := range lines {
				lines[i] = now + lines[i]
			}
			for i := range summary {
				summary[i] = now + summary[i]
			}
		}
		if o.Quiet <= 2 {
			for _, s := range summary {
				fmt.Fprintln(w, s)
			}
			first := 0
			if sc.first {
				first = 1
			}
			if o.Quiet <= first {
				fmt.Fprintln(w, titles)
			}
		}
		for _, l := range lines {
			if style == "rhel" {
				l = pyBytesRepr(l)
			}
			fmt.Fprintln(w, l)
		}
	}
}

// iotopSorted: the processes shown (-o: those with I/O), by iotop's sort
// key, highest first, ties in the order iotop first saw them (Python's sort
// is stable, also reversed). The default key is the IO % one; without delay
// accounting 0.6-42 and RHEL's switch to DISK WRITE (0.6-24 does not).
func iotopSorted(sc IotopScreen, o IotopOpts, style string, delayAcct bool) []IotopProc {
	var ps []IotopProc
	for _, p := range sc.Procs {
		if o.Only && p.Read == 0 && p.rawWrite == 0 && p.cancel == 0 && p.BlkioNS == 0 {
			continue
		}
		ps = append(ps, p)
	}
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].order < ps[j].order })
	byIO := delayAcct || style == "0.6-24"
	key := func(p IotopProc) float64 {
		if !byIO {
			return float64(p.rawWrite - p.cancel)
		}
		if p.BlkioNS != 0 {
			return p.BlkioNS
		}
		if p.Read != 0 || p.rawWrite != 0 {
			return 1
		}
		return 0
	}
	sort.SliceStable(ps, func(i, j int) bool { return key(ps[i]) > key(ps[j]) })
	return ps
}

func iotopLine(p IotopProc, o IotopOpts, style string, delayAcct bool, pidWidth int) string {
	size := func(v int64) string {
		if o.Accumulated {
			return iotopSize(o.Kilobytes, float64(v))
		}
		if v == 0 || p.Seconds <= 0 {
			return iotopSize(o.Kilobytes, 0) + "/s"
		}
		return iotopSize(o.Kilobytes, float64(v)/p.Seconds) + "/s"
	}
	user := p.User
	if r := []rune(user); len(r) > 8 {
		user = string(r[:8])
	}
	line := fmt.Sprintf("%*d %4s %-8s %11s %11s", pidWidth, p.PID, p.Prio, user, size(p.Read), size(p.Write))
	switch {
	case delayAcct:
		// SWAPIN is not recorded (taskstats only): "?".
		pct := 0.0
		if p.Seconds > 0 {
			pct = math.Min(99.99, p.BlkioNS/(p.Seconds*10000000.0))
		}
		line += fmt.Sprintf(" %7s %7s", "?", fmt.Sprintf("%.2f %%", pct))
	case style == "0.6-24":
		line += "  ?unavailable? "
	default:
		line += " ?unavailable? "
	}
	return line + " " + p.Command
}

// iotopSize is iotop's human_size (-k: kilobytes).
func iotopSize(kb bool, size float64) string {
	if kb {
		return fmt.Sprintf("%.2f K", size/1024.0)
	}
	if size == 0 {
		return "0.00 B"
	}
	sign := ""
	if size < 0 {
		sign, size = "-", -size
	}
	expo := int(math.Log(size/2) / math.Log(2) / 10)
	units := "BKMGTPE"
	if expo < 0 || expo >= len(units) {
		expo = 0
	}
	return fmt.Sprintf("%s%.2f %c", sign, size/float64(int64(1)<<(10*expo)), units[expo])
}

func rjust(s string, n int) string {
	if l := len([]rune(s)); l < n {
		return strings.Repeat(" ", n-l) + s
	}
	return s
}

// pyBytesRepr is Python 3's repr of a str encoded as UTF-8 (RHEL's iotop
// prints each line with print(l.encode('utf-8'))): b'...', or b"..." when
// the line has a single quote and no double one.
func pyBytesRepr(s string) string {
	q := byte('\'')
	if strings.IndexByte(s, '\'') >= 0 && strings.IndexByte(s, '"') < 0 {
		q = '"'
	}
	var b strings.Builder
	b.WriteString("b")
	b.WriteByte(q)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == q || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(&b, `\x%02x`, c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte(q)
	return b.String()
}
