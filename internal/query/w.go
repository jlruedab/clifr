// Parts of this file follow procps-ng's w.c (LGPL-2.1-or-later), used under the
// GPL-3.0: see LICENSING.md and packaging/notices/procps.txt.

package query

import (
	"fmt"
	"io"
	"net/netip"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"time"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// w (procps): the login sessions at T with what each is doing. procps 3.3
// (RHEL 8/9's 3.3.15/3.3.17, Ubuntu 22.04's 3.3.17) reads utmp and scans the
// processes in pid order; Debian/Ubuntu's 4.0.4 (with their patches: user
// sessions only, the session's terminal found through its processes,
// processes in start-time order) reads logind's sessions where there are
// any, else utmp. The processes are those alive at T with their values at
// the last sample (CPU, foreground group), as ps shows them.

// WOptions are w's options.
type WOptions struct {
	NoHeader, NoCurrent, Short, ToggleFrom, OldStyle, IPAddr, PIDs bool
	User                                                           string
	Columns                                                        int  // $COLUMNS, 0: unset (w into a pipe: 512)
	NoFromDefault                                                  bool // built without W_SHOWFROM (RHEL 9)
}

// WLine is one line of w.
type WLine struct {
	User    string `json:"user"`
	TTY     string `json:"tty"`
	From    string `json:"from,omitempty"`
	LoginMS int64  `json:"login_ms"`
	// IdleS: seconds since the terminal's last access; -1: no terminal,
	// -2: an X display (?xdm?).
	IdleS     int64  `json:"idle_s"`
	JCPUTicks int64  `json:"jcpu_ticks"`
	PCPUTicks int64  `json:"pcpu_ticks"` // -1: no process (procps 3.3) / 0 (4.0): "?"
	What      string `json:"what"`
	LoginPID  int    `json:"login_pid"` // utmp's pid or the session leader
	WhatPID   int    `json:"what_pid"`
	// for printing
	host, addr string
	session    bool
}

// WReport is w at T: the uptime line's values and the sessions.
type WReport struct {
	Uptime  UptimeRow `json:"uptime"`
	Lines   []WLine   `json:"sessions"`
	Procps3 bool      `json:"-"`
	Now     int64     `json:"-"`
}

// wProc is a process as w reads it.
type wProc struct {
	pid, ppid, tty, euid, ruid, pgrp, tpgid int
	start, ticks                            int64
	cmd3, cmd4                              string // what procps 3.3 / 4.0 print
}

// ttyNrOf is a terminal's tty_nr from its name, for terminals clifrd did
// not stat (recordings before tty_nr was recorded): pts/N, ttyN, ttySN.
func ttyNrOf(name string) int {
	enc := func(maj, min int) int { return min&0xff | maj<<8 | (min&^0xff)<<12 }
	if n, ok := strings.CutPrefix(name, "pts/"); ok {
		if v, err := strconv.Atoi(n); err == nil {
			return enc(136+v/256, v%256)
		}
	}
	if n, ok := strings.CutPrefix(name, "ttyS"); ok {
		if v, err := strconv.Atoi(n); err == nil {
			return enc(4, 64+v)
		}
	}
	if n, ok := strings.CutPrefix(name, "tty"); ok {
		if v, err := strconv.Atoi(n); err == nil && v < 64 {
			return enc(4, v)
		}
	}
	return -1
}

// cleanTTY is w's clean-up of a terminal name: up to the first character
// that is neither alphanumeric nor '/'.
func cleanTTY(s string) string {
	for i := 0; i < len(s) && i < 32; i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '/') {
			return s[:i]
		}
	}
	if len(s) > 32 {
		return s[:32]
	}
	return s
}

// uidOfName is getpwnam's uid for a user name: the recorded passwd, else
// this machine's; -1 when unknown.
func uidOfName(name string) int {
	if recordedUsers != nil {
		best := -1
		for uid, n := range recordedUsers {
			if n == name && (best < 0 || uid < best) {
				best = uid
			}
		}
		return best
	}
	if u, err := user.Lookup(name); err == nil {
		if v, err := strconv.Atoi(u.Uid); err == nil {
			return v
		}
	}
	return -1
}

// WAt reconstructs w at t. procps3: the RHEL 8/9 and Ubuntu 22.04 version.
func WAt(db *store.DB, t int64, procps3 bool, o WOptions) (*WReport, error) {
	s, err := SessionsAt(db, t, 0)
	if err != nil {
		return nil, err
	}
	if _, err := LoadUsers(db, t); err != nil {
		return nil, err
	}
	spans, err := SysSpans(db, Window{At: t}, 0)
	if err != nil {
		return nil, err
	}
	up, err := Uptime(db, spans)
	if err != nil {
		return nil, err
	}
	rep := &WReport{Uptime: up[0], Procps3: procps3, Now: t}
	rep.Uptime.At(t)
	n := s.UserCount(procps3)
	rep.Uptime.Users = &n
	snap, err := SnapshotAt(db, t, false)
	if err != nil {
		return nil, err
	}
	pa, err := processesAt(db, snap, t)
	if err != nil {
		return nil, err
	}
	procs := make([]wProc, 0, len(pa))
	for _, p := range pa {
		wp := wProc{pid: p.pid, ppid: p.ppid, tty: p.tty, euid: p.uid, ruid: p.uid, pgrp: p.pgrp, tpgid: -2,
			start: p.startMS, ticks: p.cpuTicks.Int64}
		if p.ruid.Valid {
			wp.ruid = int(p.ruid.Int64)
		}
		if p.tpgid.Valid {
			wp.tpgid = int(p.tpgid.Int64)
		}
		wp.cmd4 = commandOf(p.cmdline, p.comm, p.state.String)
		wp.cmd3 = procpsSafe(p.comm)
		if p.cmdline != "" {
			wp.cmd3 = procpsSafe(p.cmdline)
		}
		procs = append(procs, wp)
	}
	rep.Lines = wLines(s, procs, t, procps3, o)
	return rep, nil
}

// wLines builds w's lines from the sessions and the processes at t (in pid
// order).
func wLines(s *Sessions, procs []wProc, t int64, procps3 bool, o WOptions) []WLine {
	var out []WLine
	if !procps3 { // the patched 4.0.4 sorts them by start time
		slices.SortStableFunc(procs, func(a, b wProc) int {
			if a.start != b.start {
				return int(a.start - b.start)
			}
			return a.pid - b.pid
		})
	}
	nowS := t / 1000
	idle := func(tty string) int64 {
		if ti, ok := s.TTY[tty]; ok && ti.AtimeMS > 0 {
			return nowS - ti.AtimeMS/1000
		}
		return 0 // w: stat failed
	}
	lineOf := func(tty string) int {
		if ti, ok := s.TTY[tty]; ok && ti.TTYNr > 0 {
			return ti.TTYNr
		}
		return ttyNrOf(tty)
	}
	// 4.0.4: logind's sessions when logind keeps any (none listed: nothing),
	// utmp only without logind
	if procps3 || !s.HaveLogind {
		for _, u := range s.Utmp {
			if u.Type != UtUserProcess || u.User == "" || o.User != "" && u.User != o.User {
				continue
			}
			l, ok := wUtmpLine(u, procs, procps3, o, lineOf, idle)
			if ok {
				out = append(out, l)
			}
		}
		return out
	}
	for _, se := range s.Logind {
		if !strings.HasPrefix(se.Class, "user") || o.User != "" && se.User != o.User {
			continue
		}
		// the terminal: logind's, else one of the leader's children's or
		// grandchildren's
		tty, line := cleanTTY(se.TTY), -1
		if se.TTY != "" {
			line = lineOf(tty)
		} else {
			tty, line = ttyOfLeader(se.Leader, procs)
		}
		l := WLine{User: se.User, TTY: tty, LoginMS: se.TimeMS, LoginPID: se.Leader, WhatPID: -1, IdleS: -1,
			host: se.Host, session: true}
		uid := se.UID
		if o.NoCurrent {
			uid = -1
		}
		found := best4(&l, se.Leader, line, uid, o.NoCurrent, procs)
		if !found {
			continue
		}
		if tty != "" {
			l.IdleS = idle(tty)
		}
		l.From = se.Host
		out = append(out, l)
	}
	return out
}

// ttyOfLeader is the patched 4.0.4's third way to a session's terminal: a
// child of the leader with one, else a grandchild (procs in start order).
func ttyOfLeader(leader int, procs []wProc) (string, int) {
	if leader <= 0 {
		return "", -1
	}
	for i, p := range procs {
		if p.ppid != leader {
			continue
		}
		if p.tty != 0 {
			return procfs.TTYName(p.tty), p.tty
		}
		for _, q := range procs[i:] {
			if q.ppid == p.pid && q.tty != 0 {
				return procfs.TTYName(q.tty), q.tty
			}
		}
	}
	return "", -1
}

// best4 is the patched 4.0.4's find_best_proc: JCPU of the terminal's
// processes, WHAT the newest foreground process of the user on it, else the
// login process, else the terminal's oldest process.
func best4(l *WLine, utPID, line, uid int, ignoreUser bool, procs []wProc) bool {
	var bestTime, secondTime int64
	found := false
	l.What = "-"
	take := func(p wProc) { l.What, l.WhatPID, l.PCPUTicks = p.cmd4, p.pid, p.ticks }
	for _, p := range procs {
		if p.pid == utPID {
			found = true
			if bestTime == 0 {
				bestTime = p.start
				take(p)
			}
		}
		if p.tty != line || line < 0 {
			continue
		}
		l.JCPUTicks += p.ticks
		if !(secondTime != 0 && p.start <= secondTime) {
			secondTime = p.start
			if l.What == "-" {
				take(p)
			}
		}
		if !ignoreUser && uid != p.euid && uid != p.ruid || p.pgrp != p.tpgid || p.start <= bestTime {
			continue
		}
		bestTime = p.start
		take(p)
	}
	return found
}

// wUtmpLine is a utmp record's line: procps 3.3's getproc and showinfo, or
// 4.0.4's with a utmp record (no logind sessions).
func wUtmpLine(u UtmpEntry, procs []wProc, procps3 bool, o WOptions, lineOf func(string) int, idle func(string) int64) (WLine, bool) {
	l := WLine{User: u.User, From: u.Host, LoginMS: u.TimeMS, LoginPID: u.PID, WhatPID: -1, IdleS: -1, host: u.Host, addr: u.Addr}
	// getpwnam failing makes w skip the record; clifr shows it with no
	// foreground process (the recorded passwd has only /etc/passwd's users,
	// w would find others through NSS)
	uid := -1
	if !o.NoCurrent {
		uid = uidOfName(u.User)
	}
	if !procps3 {
		// the patched 4.0.4 never takes utmp's line (its loop stops at the
		// empty buffer): the terminal of the login process's children
		tty, line := ttyOfLeader(u.PID, procs)
		l.TTY = tty
		if !best4(&l, u.PID, line, uid, o.NoCurrent, procs) {
			return l, false
		}
		switch {
		case strings.HasPrefix(u.Line, ":"):
			l.IdleS = -2
		case tty != "":
			l.IdleS = idle(tty)
		}
		return l, true
	}
	l.TTY = u.Line
	tty := cleanTTY(u.Line)
	line := lineOf(tty)
	if tty == "" {
		line = 0 // "/dev/": rdev 0, the processes without a terminal
	}
	var best, second *wProc
	found := false
	for i := range procs {
		p := &procs[i]
		if p.pid == u.PID {
			found = true
			if best == nil {
				best = p
			}
		}
		if p.tty != line {
			continue
		}
		l.JCPUTicks += p.ticks
		second = p
		if !o.NoCurrent && uid != p.euid && uid != p.ruid || p.pgrp != p.tpgid || best != nil && p.start <= best.start {
			continue
		}
		best = p
	}
	if !found {
		return l, false
	}
	if best == nil {
		best = second
	}
	l.What, l.PCPUTicks = "-", -1
	if best != nil {
		l.What, l.WhatPID, l.PCPUTicks = best.cmd3, best.pid, best.ticks
	}
	if strings.HasPrefix(u.Line, ":") {
		l.IdleS = -2
	} else {
		l.IdleS = idle(tty)
	}
	return l, true
}

// UserCount is the number of users uptime, w and top print: procps 3.3
// counts utmp's user records; the patched 4.0.4 logind's sessions of class
// user*, else utmp's.
func (s *Sessions) UserCount(procps3 bool) int {
	n := 0
	if !procps3 && len(s.Logind) > 0 {
		for _, se := range s.Logind {
			if strings.HasPrefix(se.Class, "user") {
				n++
			}
		}
		return n
	}
	for _, u := range s.Utmp {
		if u.Type == UtUserProcess && u.User != "" {
			n++
		}
	}
	return n
}

// Procps3 reports whether the host recorded at t has procps 3.3 (RHEL 8/9,
// Ubuntu 22.04: w and uptime read utmp), not 4 (logind first).
func Procps3(db *store.DB, t int64) bool {
	return StyleAt(db, t).Procps3
}

// UsersAt is UserCount at t; nil when logins were not recorded.
func UsersAt(db *store.DB, t int64, procps3 bool) *int {
	s, err := SessionsAt(db, t, 0)
	if err != nil {
		return nil
	}
	n := s.UserCount(procps3)
	return &n
}

// ival7 is w's print_time_ival7.
func ival7(t int64, centi int64, old bool) string {
	if t < 0 {
		return "   ?   "
	}
	switch {
	case t >= 48*3600:
		return fmt.Sprintf(" %2ddays", t/86400)
	case old && t >= 3600:
		return fmt.Sprintf(" %2d:%02d ", t/3600, t/60%60)
	case old && t > 60:
		return fmt.Sprintf(" %2d:%02dm", t/60, t%60)
	case old:
		return "       "
	case t >= 3600:
		return fmt.Sprintf(" %2d:%02dm", t/3600, t/60%60)
	case t > 60:
		return fmt.Sprintf(" %2d:%02d ", t/60, t%60)
	}
	return fmt.Sprintf(" %2d.%02ds", t, centi)
}

// loginTime is w's print_logintime at now.
func loginTime(logMS, nowS int64) string {
	lt, nt := time.Unix(logMS/1000, 0), time.Unix(nowS, 0)
	d := nowS - logMS/1000
	if d > 12*3600 && lt.YearDay() != nt.YearDay() {
		if d > 6*86400 {
			return fmt.Sprintf(" %02d%3s%02d", lt.Day(), lt.Format("Jan"), lt.Year()%100)
		}
		return fmt.Sprintf(" %3s%02d  ", lt.Format("Mon"), lt.Hour())
	}
	return fmt.Sprintf(" %02d:%02d  ", lt.Hour(), lt.Minute())
}

// printHost is w's print_host: the host up to the first space or
// unprintable character ('-' then), at least "-", padded to fromlen.
func printHost(b *strings.Builder, host string, fromlen int) {
	if len(host) > fromlen {
		host = host[:fromlen]
	}
	width := 0
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c == 0 {
			break
		}
		if c > ' ' && c < 0x7f {
			b.WriteByte(c)
			width++
			continue
		}
		b.WriteByte('-')
		width++
		break
	}
	if width == 0 {
		b.WriteByte('-')
		width++
	}
	for ; width < fromlen; width++ {
		b.WriteByte(' ')
	}
}

// printDisplayOrInterface is w -i's display (host ":0") or IPv6 interface
// ("%eth0") after the address.
func printDisplayOrInterface(b *strings.Builder, host string, restlen int) {
	if restlen <= 0 {
		return
	}
	printable := func(c byte) bool { return c >= ' ' && c < 0x7f }
	disp := 0
	for disp < len(host) && host[disp] != ':' && printable(host[disp]) {
		disp++
	}
	if disp < len(host) && host[disp] == ':' {
		tmp := disp + 1
		for tmp < len(host) && host[tmp] != ':' && printable(host[tmp]) {
			tmp++
		}
		emit := func(from int) {
			n := 256 - from
			if n > restlen {
				n = restlen
			}
			i := from
			for n > 0 && i < len(host) && printable(host[i]) && host[i] != ' ' {
				b.WriteByte(host[i])
				n--
				restlen--
				i++
			}
			if n > 0 && i < len(host) {
				restlen--
				b.WriteByte('-')
			}
		}
		if tmp >= len(host) || host[tmp] != ':' {
			emit(disp)
		} else {
			for tmp < len(host) && host[tmp] != '%' && printable(host[tmp]) {
				tmp++
			}
			if tmp < len(host) && host[tmp] == '%' {
				emit(tmp)
			}
		}
	}
	for ; restlen > 0; restlen-- {
		b.WriteByte(' ')
	}
}

// PrintW prints the report as w does.
func PrintW(w io.Writer, r *WReport, o WOptions) {
	const userlen, fromlen = 8, 16
	from := !o.NoFromDefault != o.ToggleFrom // -f toggles the build's default
	if o.IPAddr {
		from = true
	}
	longform := !o.Short
	maxcmd := o.Columns
	if maxcmd == 0 {
		maxcmd = 512
	}
	clamp := func(v int) int { return min(max(v, 7), 512) }
	maxcmd = clamp(maxcmd)
	maxcmd -= 21 + userlen
	if from {
		maxcmd -= fromlen
	}
	if longform {
		maxcmd -= 20
	}
	maxcmd = clamp(maxcmd)
	if !o.NoHeader {
		PrintUptime(w, []UptimeRow{r.Uptime})
		fmt.Fprintf(w, "%-*s TTY      ", userlen, "USER")
		if r.Procps3 {
			if from {
				fmt.Fprintf(w, "%-*s", fromlen-1, "FROM")
			}
			if longform {
				fmt.Fprint(w, "  LOGIN@   IDLE   JCPU   PCPU WHAT\n")
			} else {
				fmt.Fprint(w, "   IDLE WHAT\n")
			}
		} else {
			if from {
				fmt.Fprintf(w, "%-*s", fromlen, "FROM")
			}
			if longform {
				fmt.Fprint(w, " LOGIN@   IDLE   JCPU   PCPU  WHAT\n")
			} else {
				fmt.Fprint(w, "   IDLE WHAT\n")
			}
		}
	}
	hz := int64(procfs.ClockTicks)
	cpu := func(t int64) string { return ival7(t/hz, (t%hz)*(100/hz), o.OldStyle) }
	for _, l := range r.Lines {
		var b strings.Builder
		user := l.User
		if len(user) > userlen {
			user = user[:userlen]
		}
		tty := l.TTY
		if len(tty) > 8 {
			tty = tty[:8]
		}
		fmt.Fprintf(&b, "%-*s%-9s", userlen+1, user, tty)
		if from {
			wFrom(&b, l, o.IPAddr, fromlen)
		}
		if longform {
			b.WriteString(loginTime(l.LoginMS, r.Now/1000))
		}
		switch {
		case l.IdleS == -2:
			b.WriteString(" ?xdm? ")
		case l.IdleS == -1:
			b.WriteString("       ")
		default:
			b.WriteString(ival7(l.IdleS, 0, o.OldStyle))
		}
		if longform {
			b.WriteString(cpu(l.JCPUTicks))
			if r.Procps3 && l.PCPUTicks >= 0 || !r.Procps3 && l.PCPUTicks > 0 {
				b.WriteString(cpu(l.PCPUTicks))
			} else {
				b.WriteString("   ?   ")
			}
		}
		mc := maxcmd
		if o.PIDs && !r.Procps3 {
			p := fmt.Sprintf(" %d/%d", l.LoginPID, l.WhatPID)
			b.WriteString(p)
			if len(p) > mc {
				mc = 0
			} else {
				mc -= len(p)
			}
		}
		what := l.What
		if len(what) > mc {
			what = what[:mc]
		}
		b.WriteString(" " + what)
		fmt.Fprintln(w, b.String())
	}
}

// wFrom is w's print_from: the host, or with -i the recorded address (and
// a display or interface from the host); logind sessions: the remote host.
func wFrom(b *strings.Builder, l WLine, ip bool, fromlen int) {
	if l.session || !ip {
		printHost(b, l.host, fromlen)
		return
	}
	addr := ""
	if a, err := netip.ParseAddr(l.addr); err == nil {
		addr = a.Unmap().String()
	}
	if len(addr) > fromlen {
		addr = addr[:fromlen]
	}
	if addr == "" {
		printHost(b, l.host, fromlen)
		return
	}
	b.WriteString(addr)
	printDisplayOrInterface(b, l.host, fromlen-len(addr))
}
