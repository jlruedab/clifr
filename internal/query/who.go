// Parts of this file follow GNU coreutils' src/who.c (GPL-3.0-or-later), used under the
// GPL-3.0: see LICENSING.md and packaging/notices/coreutils.txt.

package query

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"clifr/internal/store"
)

// Login sessions (2026-11-20): the snapshots sources "utmp" (each record of
// /run/utmp), "logind" (systemd-logind's sessions, where there is no utmp)
// and "ttyatime" (each session terminal's last access and mode); see
// recorder/sessions.go. who and w read utmp where the recording has it (GNU
// coreutils, procps 3.3), logind otherwise (uutils, procps 4).

// utmp record types (utmp.h).
const (
	UtRunLvl       = 1
	UtBootTime     = 2
	UtNewTime      = 3
	UtOldTime      = 4
	UtInitProcess  = 5
	UtLoginProcess = 6
	UtUserProcess  = 7
	UtDeadProcess  = 8
)

// UtmpEntry is one login record: a utmp record, or one that who builds from
// a logind session (uutils: one per seat and per terminal, and a boot
// record).
type UtmpEntry struct {
	Type    int    `json:"type"`
	PID     int    `json:"pid"`
	Line    string `json:"line"`
	ID      string `json:"id"`
	User    string `json:"user"`
	UID     int    `json:"uid"` // logind; -1 in utmp
	Host    string `json:"host"`
	Term    int    `json:"termination"`
	Exit    int    `json:"exit"`
	Session int    `json:"session"`
	TimeMS  int64  `json:"time_ms"`
	Addr    string `json:"addr,omitempty"`
	// The terminal's last access (IDLE) and mode (mesg) at T: from
	// ttyatime, 0 / -1 when not a device or not recorded.
	TTYAtimeMS int64 `json:"tty_atime_ms"`
	TTYMode    int   `json:"tty_mode"`
	// Logind: the session's class, type, state, leader, seat and display.
	Class   string `json:"class,omitempty"`
	SType   string `json:"session_type,omitempty"`
	State   string `json:"state,omitempty"`
	Leader  int    `json:"leader,omitempty"`
	Seat    string `json:"seat,omitempty"`
	Display string `json:"display,omitempty"`
	TTY     string `json:"tty,omitempty"`
	Remote  bool   `json:"remote,omitempty"`
}

// Sessions is the login records at T.
type Sessions struct {
	Source  string      // who's: "utmp" where the recording has it, else "logind"
	TS      int64       // when they were read last at or before T
	Entries []UtmpEntry // who's records: utmp's in file order, or built from logind as uutils does
	// Both sources as recorded (w and uptime of procps 4 read logind first).
	Utmp, Logind         []UtmpEntry // Logind in directory order (sd_get_sessions)
	HaveUtmp, HaveLogind bool
	// TTY: each session terminal's last access, mode and tty_nr (0: not
	// recorded, before 2026-11-20 19:00), by name without /dev/.
	TTY map[string]TTYInfo
}

// TTYInfo is a terminal device as clifrd last stat'ed it.
type TTYInfo struct {
	AtimeMS int64
	Mode    int
	TTYNr   int
}

// unescField undoes the recorder's \xNN escapes.
func unescField(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				sb.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// parseUtmpLine parses a "utmp" source line:
// type pid line id user host termination exit session sec usec addr.
func parseUtmpLine(l string) (UtmpEntry, bool) {
	f := strings.Split(l, "\t")
	if len(f) < 12 {
		return UtmpEntry{}, false
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	e := UtmpEntry{Type: n(f[0]), PID: n(f[1]), Line: unescField(f[2]), ID: unescField(f[3]), User: unescField(f[4]),
		Host: unescField(f[5]), Term: n(f[6]), Exit: n(f[7]), Session: n(f[8]), Addr: f[11], UID: -1, TTYMode: -1}
	e.TimeMS = int64(n(f[9]))*1000 + int64(n(f[10]))/1000
	return e, true
}

// parseLogindLine parses a "logind" source line: KEY=value fields.
func parseLogindLine(l string) UtmpEntry {
	e := UtmpEntry{UID: -1, TTYMode: -1, Type: UtUserProcess}
	for _, kv := range strings.Split(l, "\t") {
		k, v, _ := strings.Cut(kv, "=")
		v = unescField(v)
		switch k {
		case "ID":
			e.ID = v
		case "UID":
			if u, err := strconv.Atoi(v); err == nil {
				e.UID = u
			}
		case "USER":
			e.User = v
		case "TTY":
			e.TTY = v
		case "SEAT":
			e.Seat = v
		case "DISPLAY":
			e.Display = v
		case "REMOTE_HOST":
			e.Host = v
		case "REMOTE":
			e.Remote = v == "1"
		case "CLASS":
			e.Class = v
		case "TYPE":
			e.SType = v
		case "STATE":
			e.State = v
		case "LEADER":
			e.Leader, _ = strconv.Atoi(v)
		case "REALTIME":
			if us, err := strconv.ParseInt(v, 10, 64); err == nil {
				e.TimeMS = us / 1000
			}
		}
	}
	return e
}

// SessionsAt reads the login records at t: utmp and logind's sessions as
// recorded at t; who's records from utmp where the recording has it, else
// from logind. bootMS is the boot covering t (the boot record uutils builds).
func SessionsAt(db *store.DB, t, bootMS int64) (*Sessions, error) {
	s := &Sessions{TTY: map[string]TTYInfo{}}
	lines, uts, ok, err := FileAt(db, "utmp", t)
	if err != nil {
		return nil, err
	}
	s.HaveUtmp = ok && len(lines) > 0
	for _, l := range lines {
		if e, ok := parseUtmpLine(l); ok {
			s.Utmp = append(s.Utmp, e)
		}
	}
	lines, lts, ok, err := FileAt(db, "logind", t)
	if err != nil {
		return nil, err
	}
	s.HaveLogind = ok
	for _, l := range lines {
		if l != "" {
			s.Logind = append(s.Logind, parseLogindLine(l))
		}
	}
	switch {
	case s.HaveUtmp:
		s.Source, s.TS, s.Entries = "utmp", uts, slices.Clone(s.Utmp)
	case s.HaveLogind:
		s.Source, s.TS, s.Entries = "logind", lts, uutilsRecords(s.Logind, bootMS)
	default:
		return nil, fmt.Errorf("logins not recorded at %s (recorded since 2026-11-20)", FormatMS(t))
	}
	atimes, _, _, err := FileAt(db, "ttyatime", t)
	if err != nil {
		return nil, err
	}
	for _, l := range atimes {
		f := strings.Split(l, "\t")
		if len(f) < 3 {
			continue
		}
		var ti TTYInfo
		ti.AtimeMS, _ = strconv.ParseInt(f[1], 10, 64)
		mode, _ := strconv.ParseInt(f[2], 8, 64)
		ti.Mode = int(mode)
		if len(f) > 3 {
			ti.TTYNr, _ = strconv.Atoi(f[3])
		}
		s.TTY[f[0]] = ti
	}
	set := func(e *UtmpEntry, line string) {
		if v, ok := s.TTY[strings.TrimPrefix(line, "/dev/")]; ok {
			e.TTYAtimeMS, e.TTYMode = v.AtimeMS, v.Mode
		}
	}
	for _, l := range [][]UtmpEntry{s.Entries, s.Utmp} {
		for i := range l {
			set(&l[i], l[i].Line)
		}
	}
	for i := range s.Logind {
		set(&s.Logind[i], s.Logind[i].TTY)
	}
	return s, nil
}

// uutilsRecords builds the login records uutils' who reads from logind
// (uucore systemd_logind.rs, 0.10.0): a boot record (the boot time: uutils
// takes /var/lib/systemd/random-seed's mtime, written a few seconds after
// boot), then the sessions by id in reverse string order, each with a seat
// and a terminal as two records, else one; sessions with neither (nor a
// display) left out. The pid is 0.
func uutilsRecords(sessions []UtmpEntry, bootMS int64) []UtmpEntry {
	var out []UtmpEntry
	if bootMS > 0 {
		out = append(out, UtmpEntry{Type: UtBootTime, User: "reboot", Line: "~", ID: "boot", TimeMS: bootMS, UID: -1, TTYMode: -1})
	}
	ss := slices.Clone(sessions)
	slices.SortStableFunc(ss, func(a, b UtmpEntry) int { return strings.Compare(b.ID, a.ID) })
	for _, s := range ss {
		if s.UID < 0 {
			continue
		}
		tty, seat := strings.TrimPrefix(s.TTY, "?"), strings.TrimPrefix(s.Seat, "?")
		host := s.Host
		if host == "" {
			host = s.Display
		}
		rec := func(line string) UtmpEntry {
			return UtmpEntry{Type: UtUserProcess, Line: line, ID: s.ID, User: s.User, UID: s.UID, Host: host,
				TimeMS: s.TimeMS, TTYMode: -1, Class: s.Class, SType: s.SType, State: s.State, Leader: s.Leader,
				Seat: s.Seat, Display: s.Display, TTY: s.TTY, Remote: s.Remote}
		}
		switch {
		case seat != "" && tty != "":
			out = append(out, rec(seat), rec(tty))
		case seat != "":
			out = append(out, rec(seat))
		case tty != "":
			out = append(out, rec(tty))
		case s.Display != "":
			out = append(out, rec(s.Display))
		}
	}
	return out
}

// WhoOptions are who's options.
type WhoOptions struct {
	All, Boot, Dead, Heading, Login, Process, Count, RunLevel, Short, Time, Mesg, Users bool
	// ISO: "%Y-%m-%d %H:%M" (a locale other than C/POSIX), else "%b %e %H:%M".
	ISO bool
	// UID: user names as uids (Ubuntu 26.04's who: its AppArmor profile
	// denies it /etc/passwd).
	UID bool
}

// WhoISO reports whether who prints ISO times in this environment: GNU
// who (gnulib's hard_locale) for any LC_TIME locale but C and POSIX; uutils
// for any but "C" in the first of LC_ALL, LC_TIME and LANG set.
func WhoISO(uutils bool) bool {
	for _, k := range []string{"LC_ALL", "LC_TIME", "LANG"} {
		if v, ok := os.LookupEnv(k); ok && (v != "" || uutils) {
			if uutils {
				return v != "C"
			}
			return v != "C" && v != "POSIX"
		}
	}
	return uutils
}

// whoFlags are who's derived settings (GNU who.c 8.32; uutils who 0.10.0
// computes them from the same options).
type whoFlags struct {
	users, runlevel, boot, clock, initspawn, login, dead bool
	mesg, idle, exit, short, heading                     bool
}

func whoSettings(o WhoOptions, uutils bool) whoFlags {
	var f whoFlags
	f.heading = o.Heading
	f.mesg = o.Mesg || o.All
	if o.All {
		f.boot, f.dead, f.login, f.initspawn, f.runlevel, f.clock, f.users = true, true, true, true, true, true, true
		f.idle, f.exit = true, true
	}
	f.boot = f.boot || o.Boot
	f.dead = f.dead || o.Dead
	f.login = f.login || o.Login
	f.initspawn = f.initspawn || o.Process
	f.runlevel = f.runlevel || o.RunLevel
	f.clock = f.clock || o.Time
	f.users = f.users || o.Users
	assumptions := !(o.All || o.Boot || o.Dead || o.Login || o.Process || o.RunLevel || o.Time || o.Users)
	if uutils {
		if assumptions {
			f.users = true
		}
		f.idle = f.dead || f.login || f.runlevel || f.users
		f.exit = f.dead
		f.short = !f.exit && assumptions
		return f
	}
	if o.Dead {
		f.idle, f.exit = true, true
	}
	if o.Login || o.RunLevel || o.Users {
		f.idle = true
	}
	f.short = o.Short
	if assumptions {
		f.users, f.short = true, true
	}
	if f.exit {
		f.short = false
	}
	return f
}

// whoPrinter prints who's lines.
type whoPrinter struct {
	w      io.Writer
	f      whoFlags
	uutils bool
	iso    bool
}

func (p *whoPrinter) timeStr(ms int64) string {
	t := time.UnixMilli(ms)
	if p.iso {
		return t.Format("2006-01-02 15:04")
	}
	return t.Format("Jan _2 15:04")
}

// line is who.c's print_line (uutils: the time padded to 10 only).
func (p *whoPrinter) line(user string, state byte, line, tm, idle, pid, comment, exit string) {
	var b strings.Builder
	fmt.Fprintf(&b, "%-8s", user)
	if p.f.mesg {
		b.WriteByte(' ')
		b.WriteByte(state)
	}
	fmt.Fprintf(&b, " %-12s", line)
	tw := 10
	if !p.uutils {
		tw = 12
		if p.iso {
			tw = 16
		}
	}
	fmt.Fprintf(&b, " %-*s", tw, tm)
	if !p.short() {
		if p.f.idle {
			fmt.Fprintf(&b, " %-6s", idle)
		}
		fmt.Fprintf(&b, " %10s", pid)
	}
	fmt.Fprintf(&b, " %-8s", comment)
	if p.f.exit {
		fmt.Fprintf(&b, " %-12s", exit)
	}
	fmt.Fprintln(p.w, strings.TrimRight(b.String(), " "))
}

func (p *whoPrinter) short() bool { return p.f.short }

// idleStr is who.c's idle_string at now.
func (p *whoPrinter) idleStr(when, boot, now int64) string {
	if boot < when && now-24*3600 < when && when <= now {
		idle := now - when
		if idle < 60 {
			return "  .  "
		}
		return fmt.Sprintf("%02d:%02d", idle/3600, idle%3600/60)
	}
	if p.uutils {
		return "old"
	}
	return " old "
}

// PrintWho prints the records as who does at t. alive reports whether a
// user process's pid was running at t (GNU who leaves out a user record
// whose process is gone: read_utmp's READ_UTMP_CHECK_PIDS); uutils and
// logind records have pid 0. uutils: logind's records, uutils' layout.
func PrintWho(w io.Writer, s *Sessions, o WhoOptions, t int64, alive func(pid int) bool) {
	uutils := s.Source == "logind"
	p := &whoPrinter{w: w, f: whoSettings(o, uutils), uutils: uutils, iso: o.ISO}
	user := func(e UtmpEntry) string {
		if uutils && (o.UID || e.User == "") {
			return strconv.Itoa(e.UID)
		}
		return e.User
	}
	isUser := func(e UtmpEntry) bool {
		if e.Type != UtUserProcess || user(e) == "" {
			return false
		}
		return uutils || e.PID <= 0 || alive == nil || alive(e.PID)
	}
	if o.Count {
		var names []string
		for _, e := range s.Entries {
			if isUser(e) {
				names = append(names, user(e))
			}
		}
		fmt.Fprintln(w, strings.Join(names, " "))
		fmt.Fprintf(w, "# users=%d\n", len(names))
		return
	}
	if p.f.heading {
		p.line("NAME", ' ', "LINE", "TIME", "IDLE", "PID", "COMMENT", "EXIT")
	}
	now := t / 1000
	var boot int64 // GNU: the last boot record before; uutils: 0
	for _, e := range s.Entries {
		pid := strconv.Itoa(e.PID)
		tm := p.timeStr(e.TimeMS)
		idEq := "id=" + e.ID
		switch {
		case p.f.users && isUser(e):
			mesg, idle := byte('?'), "  ?"
			if e.TTYMode >= 0 {
				mesg = '-'
				if e.TTYMode&0o020 != 0 {
					mesg = '+'
				}
				if e.TTYAtimeMS/1000 != 0 {
					b := boot
					if uutils {
						b = 0
					}
					idle = p.idleStr(e.TTYAtimeMS/1000, b, now)
				}
			}
			host := e.Host
			if host != "" {
				host = "(" + host + ")"
			}
			p.line(user(e), mesg, e.Line, tm, idle, pid, host, "")
		case p.f.runlevel && e.Type == UtRunLvl:
			last, curr := byte(e.PID/256), byte(e.PID%256)
			comment := ""
			if uutils {
				l := byte('N')
				if last == 'N' {
					l = 'S'
				}
				if last >= 0x20 && last != 0x7f {
					comment = "last=" + string(l)
				}
			} else if last >= 0x20 && last < 0x7f {
				if last == 'N' {
					last = 'S'
				}
				comment = "last=" + string(last)
			}
			p.line("", ' ', "run-level "+string(curr), tm, "", "", comment, "")
		case p.f.boot && e.Type == UtBootTime:
			p.line("", ' ', "system boot", tm, "", "", "", "")
		case p.f.clock && e.Type == UtNewTime:
			p.line("", ' ', "clock change", tm, "", "", "", "")
		case p.f.initspawn && e.Type == UtInitProcess:
			p.line("", ' ', e.Line, tm, "", pid, idEq, "")
		case p.f.login && e.Type == UtLoginProcess:
			p.line("LOGIN", ' ', e.Line, tm, "", pid, idEq, "")
		case p.f.dead && e.Type == UtDeadProcess:
			p.line("", ' ', e.Line, tm, "", pid, idEq, fmt.Sprintf("term=%d exit=%d", e.Term, e.Exit))
		}
		if e.Type == UtBootTime {
			boot = e.TimeMS / 1000
		}
	}
}

// PIDsAliveAt is the pids among pids that a recorded process had at t.
func PIDsAliveAt(db *store.DB, t int64, pids []int) (map[int]bool, error) {
	out := map[int]bool{}
	if len(pids) == 0 {
		return out, nil
	}
	list := make([]string, len(pids))
	for i, p := range pids {
		list[i] = strconv.Itoa(p)
	}
	rows, err := db.Query(`SELECT DISTINCT pid FROM processes WHERE pid IN (`+strings.Join(list, ",")+`)
		  AND first_seen <= ?1 AND COALESCE(ended, last_seen, ?2) >= ?1`, t, openEnd)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out[p] = true
	}
	return out, rows.Err()
}

// BootClockAt is the boot time on the clock at the system sample at or
// before t (sys_samples.boot_ms: now - CLOCK_BOOTTIME, schema 12) and the
// run's boot time, by which clifrd recorded process start times (measured
// once, when it started). They differ when the clock was stepped after
// clifrd started (the first NTP sync at boot). ok: the recording has it.
func BootClockAt(db *store.DB, t int64) (clock, run int64, ok bool) {
	var c sql.NullInt64
	db.QueryRow(`SELECT arg_max(boot_ms, ts) FROM sys_samples WHERE ts <= ?`, t).Scan(&c)
	run = BootAt(db, t)
	if !c.Valid || c.Int64 <= 0 || run <= 0 {
		return 0, run, false
	}
	return c.Int64, run, true
}

// StartShiftAt is what to add to a recorded start time to have it on the
// clock of t, as a tool run at t computes it (its boot time then plus the
// process's ticks): 0 without a clock step, or in older recordings.
func StartShiftAt(db *store.DB, t int64) int64 {
	if clock, run, ok := BootClockAt(db, t); ok {
		return clock - run
	}
	return 0
}

// clockStep is a step of the clock while clifrd ran: the boot time on the
// clock moved by d ms between two system samples, the later at ts.
type clockStep struct{ ts, d int64 }

// clockSteps are the recording's clock steps (moves of sys_samples.boot_ms
// above 100 ms between consecutive samples of one boot; schema 12).
func clockSteps(db *store.DB) []clockStep {
	rows, err := db.Query(`SELECT ts, d FROM (
		SELECT ts, boot_ms - lag(boot_ms) OVER (ORDER BY ts) AS d FROM sys_samples WHERE boot_ms > 0)
		WHERE abs(d) > 100 AND abs(d) < 86400000 ORDER BY ts`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []clockStep
	for rows.Next() {
		var s clockStep
		if rows.Scan(&s.ts, &s.d) == nil {
			out = append(out, s)
		}
	}
	return out
}

// startShift is what to add to a recorded start time to have it on the
// clock in force when the process started: the steps after its run began
// (process ids carry the run's start, in seconds, times 1e9) and before it
// started. A history view (life) puts starts beside event times, which were
// recorded on the clock of their moment.
func startShift(steps []clockStep, id, start int64) int64 {
	runStart := id / 1_000_000_000 * 1000
	var shift int64
	for _, s := range steps {
		if s.ts > runStart && s.ts <= start+shift+s.d {
			shift += s.d
		}
	}
	return shift
}

// BootAt is the boot time of the boot covering t (0: unknown).
func BootAt(db *store.DB, t int64) int64 {
	boots, err := Boots(db, t)
	if err != nil || len(boots) == 0 {
		return 0
	}
	return boots[len(boots)-1].BootMS
}
