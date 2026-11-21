// Parts of this file follow util-linux's login-utils/last.c (GPL-2.0-or-later), used under the
// GPL-3.0: see LICENSING.md and packaging/notices/util-linux.txt.

package query

import (
	"database/sql"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"clifr/internal/store"
)

// last (util-linux 2.32-2.37, the same code): the logins and boots within
// the recording, newest first. util-linux reads wtmp; clifr has no wtmp but
// the history of utmp (or logind's sessions where there is no utmp), from
// which it writes the records wtmp would hold: a login when a user record
// appears, a logout when its slot turns into a dead process (at that
// record's time) or the record goes away (at the time clifrd saw it gone),
// none when the machine rebooted in between; a boot record per boot and a
// shutdown record at the last sample of each boot that ended cleanly. Then
// util-linux's own pass over them (process_wtmp_file, list), with one
// difference: a boot clifr knows crashed ends in "crash" at its last sample
// on disk, where util-linux runs it on to the next shutdown record.

// wtmp record kinds (utmp.h) and the shutdown pseudo-record.
const (
	wtShutdown = -1
)

// WtmpRec is one record clifr derives for last.
type WtmpRec struct {
	Type   int    `json:"type"` // UtBootTime, UtUserProcess, UtDeadProcess, -1 shutdown
	PID    int    `json:"pid,omitempty"`
	Line   string `json:"line"`
	User   string `json:"user,omitempty"`
	Host   string `json:"host,omitempty"`
	Addr   string `json:"-"`
	TimeMS int64  `json:"time_ms"`
	seq    int
	// a boot whose last clifrd run did not stop cleanly (the machine went
	// down without a shutdown) and its last sample on disk
	crashed bool
	lastMS  int64
}

// LastRow is one line of last.
type LastRow struct {
	User     string `json:"user"`
	Line     string `json:"line"`
	Host     string `json:"host"`
	LoginMS  int64  `json:"login_ms"`
	LogoutMS int64  `json:"logout_ms,omitempty"`
	// End: "logout", "still logged in", "gone - no logout", "crash", "down",
	// "still running", "reboot" (a boot that ended).
	End  string `json:"end"`
	addr string
	what int
}

// LastOptions are last's options.
type LastOptions struct {
	Full, NoHost, HostLast, Wide, IP bool
	Max                              int      // -n: at most this many lines (0: all)
	Names                            []string // users, terminals or "reboot"
	Since                            int64    // range: records from this time (0: all)
}

// snapHistory is a snapshot source's states up to t: each time it changed,
// its lines by key.
type snapState2 struct {
	ts    int64
	lines map[string]string
}

func snapHistory(db *store.DB, source string, t int64) ([]snapState2, error) {
	rows, err := db.Query(`SELECT ts, key, pos, whole, line FROM snapshots WHERE source = ? AND ts <= ? ORDER BY ts, pos`, source, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []snapState2
	cur := map[string]string{}
	var curTS int64 = -1
	var wholeAt int64 = -1
	flush := func() {
		if curTS >= 0 {
			out = append(out, snapState2{curTS, cur})
		}
	}
	for rows.Next() {
		var ts int64
		var key, line sql.NullString
		var pos, whole int
		if err := rows.Scan(&ts, &key, &pos, &whole, &line); err != nil {
			return nil, err
		}
		if ts != curTS {
			flush()
			next := make(map[string]string, len(cur))
			for k, v := range cur {
				next[k] = v
			}
			cur, curTS = next, ts
		}
		if whole == 1 && wholeAt != ts { // a whole copy replaces the source
			cur, wholeAt = map[string]string{}, ts
		}
		if pos >= 0 {
			cur[key.String] = line.String
		}
	}
	flush()
	return out, rows.Err()
}

// LoginRecords derives wtmp's records up to t from the recorded utmp (or
// logind's sessions), and the boots. ok: logins were recorded.
func LoginRecords(db *store.DB, t int64, boots []Boot) (recs []WtmpRec, ok bool, err error) {
	seq := 0
	add := func(r WtmpRec) {
		seq++
		r.seq = seq
		recs = append(recs, r)
	}
	for _, r := range BootRecords(boots) {
		add(r)
	}
	rebootBetween := func(a, b int64) bool {
		for _, bt := range boots {
			if bt.BootMS > a && bt.BootMS <= b {
				return true
			}
		}
		return false
	}
	hist, err := snapHistory(db, "utmp", t)
	if err != nil {
		return nil, false, err
	}
	if len(hist) > 0 {
		prev, prevTS := map[string]UtmpEntry{}, int64(0)
		for _, st := range hist {
			cur := map[string]UtmpEntry{}
			for k, l := range st.lines {
				if e, ok := parseUtmpLine(l); ok && e.Type == UtUserProcess && e.User != "" {
					cur[k] = e
				}
			}
			same := func(a, b UtmpEntry) bool {
				return a.PID == b.PID && a.Line == b.Line && a.TimeMS == b.TimeMS && a.User == b.User
			}
			for k, p := range prev {
				if n, ok := cur[k]; ok && same(p, n) {
					continue
				}
				// gone: its slot's dead record, else when clifrd saw it gone
				if l, ok := st.lines[k]; ok {
					if d, ok := parseUtmpLine(l); ok && d.Type == UtDeadProcess && d.Line == p.Line {
						add(WtmpRec{Type: UtDeadProcess, PID: d.PID, Line: d.Line, TimeMS: d.TimeMS})
						continue
					}
				}
				if !rebootBetween(prevTS, st.ts) {
					add(WtmpRec{Type: UtDeadProcess, PID: p.PID, Line: p.Line, TimeMS: st.ts})
				}
			}
			for k, n := range cur {
				if p, ok := prev[k]; ok && same(p, n) {
					continue
				}
				add(WtmpRec{Type: UtUserProcess, PID: n.PID, Line: n.Line, User: n.User, Host: n.Host, Addr: n.Addr, TimeMS: n.TimeMS})
			}
			prev, prevTS = cur, st.ts
		}
		ok = true
	} else {
		hist, err = snapHistory(db, "logind", t)
		if err != nil {
			return nil, false, err
		}
		prev, prevTS := map[string]UtmpEntry{}, int64(0)
		for _, st := range hist {
			cur := map[string]UtmpEntry{}
			for k, l := range st.lines {
				if e := parseLogindLine(l); strings.HasPrefix(e.Class, "user") {
					cur[k] = e
				}
			}
			for k, p := range prev {
				if n, ok := cur[k]; ok && n.TimeMS == p.TimeMS {
					continue
				}
				if !rebootBetween(prevTS, st.ts) {
					add(WtmpRec{Type: UtDeadProcess, PID: p.Leader, Line: logindLine(p), TimeMS: st.ts})
				}
			}
			for k, n := range cur {
				if p, ok := prev[k]; ok && n.TimeMS == p.TimeMS {
					continue
				}
				add(WtmpRec{Type: UtUserProcess, PID: n.Leader, Line: logindLine(n), User: n.User, Host: n.Host, TimeMS: n.TimeMS})
			}
			prev, prevTS = cur, st.ts
		}
		ok = len(hist) > 0
	}
	slices.SortStableFunc(recs, func(a, b WtmpRec) int {
		if a.TimeMS/1000 != b.TimeMS/1000 { // wtmp's order: seconds, then as written
			return int(a.TimeMS/1000 - b.TimeMS/1000)
		}
		if a.Type == UtBootTime && b.Type != UtBootTime {
			return -1
		}
		if b.Type == UtBootTime && a.Type != UtBootTime {
			return 1
		}
		if a.TimeMS != b.TimeMS {
			return int(a.TimeMS - b.TimeMS)
		}
		return a.seq - b.seq
	})
	return recs, ok, nil
}

// BootRecords are wtmp's records of the boots: a boot record each, and a
// shutdown record at the last sample of each earlier boot whose last clifrd
// run stopped cleanly (systemd writes one at a shutdown; none after a crash).
func BootRecords(boots []Boot) []WtmpRec {
	var out []WtmpRec
	for i, b := range boots {
		kernel := b.Kernel
		if kernel == "" {
			kernel = "-"
		}
		out = append(out, WtmpRec{Type: UtBootTime, Line: "~", User: "reboot", Host: kernel, TimeMS: b.BootMS, seq: len(out) + 1,
			crashed: b.Crashed && i < len(boots)-1, lastMS: b.LastMS})
		if i < len(boots)-1 && !b.Crashed && b.LastMS > 0 {
			out = append(out, WtmpRec{Type: wtShutdown, Line: "~", User: "shutdown", Host: kernel, TimeMS: b.LastMS, seq: len(out) + 1})
		}
	}
	return out
}

// logindLine is a logind session's terminal for last: its TTY, else its
// seat, else its X display.
func logindLine(e UtmpEntry) string {
	switch {
	case e.TTY != "":
		return e.TTY
	case e.Seat != "":
		return e.Seat
	case e.Display != "":
		return e.Display
	}
	return "?"
}

// LastAt runs util-linux's pass over the records up to t (currentdate = t):
// alive reports whether a login's process ran at t (else "gone - no
// logout"); bootMS is the boot covering t (a login before it is gone).
func LastAt(recs []WtmpRec, t, bootMS int64, o LastOptions, alive func(pid int) bool) []LastRow {
	const (
		rCrash = iota + 1
		rDown
		rNormal
		rNow
		rReboot
		rPhantom
	)
	var ulist []WtmpRec
	var lastboot int64
	lastdown := t
	whydown := 0
	var out []LastRow
	list := func(r WtmpRec, logout int64, what int) {
		row := LastRow{User: r.User, Line: r.Line, Host: r.Host, LoginMS: r.TimeMS, LogoutMS: logout, addr: r.Addr, what: what}
		switch what {
		case rCrash:
			row.End = "crash"
		case rDown:
			row.End = "down"
		case rNow:
			row.End = "still logged in"
		case rPhantom:
			row.End = "gone - no logout"
		case rReboot:
			row.End = "reboot"
			if logout == t {
				row.End = "still running"
			}
		default:
			row.End = "logout"
		}
		out = append(out, row)
	}
	for i := len(recs) - 1; i >= 0; i-- {
		r := recs[i]
		if r.TimeMS/1000 > t/1000 || o.Since > 0 && r.TimeMS/1000 < o.Since/1000 {
			continue
		}
		down := false
		switch r.Type {
		case wtShutdown:
			lastdown = r.TimeMS
			down = true
		case UtBootTime:
			// util-linux: up to the next shutdown record, else "still
			// running" (a boot that crashed too: util-linux has no "crash"
			// for boots). clifr knows a crash (the run that did not stop
			// cleanly): "crash", the length up to its last sample on disk
			// (the user's choice, 2026-11-20).
			r.Line = "system boot"
			if r.crashed {
				list(r, r.lastMS, rCrash)
			} else {
				list(r, lastdown, rReboot)
			}
			lastboot = r.TimeMS
			down = true
		case UtUserProcess:
			found := false
			keep := ulist[:0]
			for _, p := range ulist {
				if p.Line == r.Line {
					if !found {
						list(r, p.TimeMS, rNormal)
						found = true
					}
					continue
				}
				keep = append(keep, p)
			}
			ulist = keep
			if !found {
				what := whydown
				if lastboot == 0 {
					what = rNow
					if r.TimeMS/1000 < bootMS/1000 || alive == nil || !alive(r.PID) {
						what = rPhantom
					}
				}
				list(r, lastboot, what)
			}
			if r.Line != "" {
				ulist = append([]WtmpRec{r}, ulist...)
			}
		case UtDeadProcess:
			if r.Line != "" {
				ulist = append([]WtmpRec{r}, ulist...)
			}
		}
		if down {
			lastboot = r.TimeMS
			whydown = rCrash
			if r.Type == wtShutdown {
				whydown = rDown
			}
			ulist = nil
		}
	}
	return out
}

// PrintLast prints the rows as util-linux last does (short or -F times,
// host after the line, -a: last, -R: none), the names filter and -n
// applied, then "wtmp begins".
func PrintLast(w io.Writer, rows []LastRow, begins, t int64, o LastOptions) {
	nameLen, domainLen := 8, 16
	if o.Wide {
		nameLen, domainLen = 32, 256
	}
	inLen, outLen := 16, 7
	if o.Full {
		inLen, outLen = 24, 26
	}
	ctime := func(ms int64) string { return time.Unix(ms/1000, 0).Format("Mon Jan _2 15:04:05 2006") }
	n := 0
	for _, r := range rows {
		if len(o.Names) > 0 && !slices.ContainsFunc(o.Names, func(s string) bool {
			return s == r.User || s == r.Line || strings.HasPrefix(r.Line, "tty") && r.Line[3:] == s
		}) {
			continue
		}
		login := ctime(r.LoginMS)
		var logout, length string
		if o.Full {
			logout = "- " + ctime(r.LogoutMS)
		} else {
			logout = "- " + time.Unix(r.LogoutMS/1000, 0).Format("15:04")
		}
		secs := r.LogoutMS/1000 - r.LoginMS/1000
		mins, hours, days := secs/60%60, secs/3600%24, secs/86400
		abs := func(v int64) int64 { return max(v, -v) }
		switch {
		case r.End == "still running":
			if o.Full {
				logout, length = "  still running", ""
			} else {
				logout, length = "  still", "running"
			}
		case days != 0:
			length = fmt.Sprintf("(%d+%02d:%02d)", days, abs(hours), abs(mins))
		case hours != 0:
			length = fmt.Sprintf(" (%02d:%02d)", hours, abs(mins))
		case secs >= 0:
			length = fmt.Sprintf(" (%02d:%02d)", hours, mins)
		default:
			length = fmt.Sprintf(" (-00:%02d)", abs(mins))
		}
		switch r.End {
		case "crash":
			logout = "- crash"
		case "down":
			logout = "- down "
		case "still logged in":
			if o.Full {
				logout, length = "  still logged in", ""
			} else {
				logout, length = "  still", "logged in"
			}
		case "gone - no logout":
			if o.Full {
				logout, length = "  gone - no logout", ""
			} else {
				logout, length = "   gone", "- no logout"
			}
		}
		domain := r.Host
		if o.IP { // the recorded address; none: 0.0.0.0, as last -i prints it
			domain = "0.0.0.0"
			if a, err := netip.ParseAddr(r.addr); err == nil {
				domain = a.Unmap().String()
			}
		}
		cut := func(s string, n int) string {
			if len(s) > n {
				return s[:n]
			}
			return s
		}
		user, line := cut(r.User, nameLen), cut(r.Line, 12)
		var s string
		switch {
		case o.NoHost:
			s = fmt.Sprintf("%-8s %-12s %-*s %-*s %s", user, line, inLen, cut(login, inLen), outLen, cut(logout, outLen), length)
		case o.HostLast:
			s = fmt.Sprintf("%-8s %-12s %-*s %-*s %-12s %s", user, line, inLen, cut(login, inLen), outLen, cut(logout, outLen),
				cut(length, 12), domain)
		default:
			s = fmt.Sprintf("%-8s %-12s %-16s %-*s %-*s %s", user, line, cut(domain, domainLen), inLen, cut(login, inLen),
				outLen, cut(logout, outLen), length)
		}
		fmt.Fprintln(w, careful(strings.TrimRight(s, " \t\n")))
		n++
		if o.Max > 0 && n >= o.Max {
			break
		}
	}
	fmt.Fprintf(w, "\nwtmp begins %s\n", ctime(begins))
}

// careful is fputc_careful: unprintable characters as '*'.
func careful(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c == 0x7f {
			b[i] = '*'
		}
	}
	return string(b)
}

// LastBegins is wtmp's first record: the start of the recording, or a boot
// or login before it.
func LastBegins(db *store.DB, recs []WtmpRec) int64 {
	var begins sql.NullInt64
	db.QueryRow(`SELECT MIN(ts) FROM samples`).Scan(&begins)
	b := begins.Int64
	for _, r := range recs {
		if r.TimeMS > 0 && (b == 0 || r.TimeMS < b) {
			b = r.TimeMS
		}
	}
	return b
}
