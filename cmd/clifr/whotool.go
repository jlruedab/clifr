package main

import (
	"errors"
	"fmt"
	"io"

	"clifr/internal/query"
)

func whoTool() *tool {
	return &tool{
		name: "who", synopsis: "[-abdHlpqrstTuw]",
		about: "who was logged in, as coreutils who prints it",
		opts: []opt{
			{short: 'a', long: "all", help: "same as -b -d -l -p -r -t -T -u"},
			{short: 'b', long: "boot", help: "time of the last system boot"},
			{short: 'd', long: "dead", help: "dead processes"},
			{short: 'H', long: "heading", help: "a line of column headings"},
			{short: 'l', long: "login", help: "system login processes"},
			{short: 'p', long: "process", help: "active processes spawned by init"},
			{short: 'q', long: "count", help: "all login names and the number of users logged on"},
			{short: 'r', long: "runlevel", help: "the current runlevel"},
			{short: 's', long: "short", help: "only name, line and time (default)"},
			{short: 't', long: "time", help: "last system clock change"},
			{short: 'T', long: "mesg", help: "the user's message status as +, - or ?"},
			{short: 'w', long: "writable", help: "same as -T"},
			{long: "message", help: "same as -T"},
			{short: 'u', long: "users", help: "users logged in, with IDLE and PID"},
		},
		window: true,
		notes: []string{
			"The login records at T (recorded since 2026-11-20): /run/utmp where the host has it (RHEL 8/9,",
			"Ubuntu 22.04: GNU coreutils' who), else systemd-logind's sessions (Ubuntu 25.10+: uutils' who,",
			"one line per seat and per terminal of a session, PID 0; user names as uids, as Ubuntu 26.04's",
			"who prints them: its AppArmor profile denies it /etc/passwd). clifrd reads both within a second",
			"of a change. A user record whose process was gone at T is left out, as who does. IDLE and -T",
			"come from the terminal's last access and mode, read at system samples (10 s). Times as clifr's",
			"locale makes who print them: \"2026-11-20 17:55\", or \"Nov 20 17:55\" with LC_ALL=C.",
			"Not supported: FILE, \"am i\" and -m (no terminal), --lookup (DNS).",
		},
		examples: []string{`clifr --at "09:30" who`, `clifr --at "09:30" "who -aH"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 0 {
				return nil, fmt.Errorf("who: unexpected argument %q (no FILE or \"am i\": the records are the recorded host's)", p.pos[0])
			}
			if c.w.IsRange() {
				return nil, errors.New("who: needs --at (last lists the logins over a range)")
			}
			return func() error {
				t := c.w.At
				s, err := query.SessionsAt(c.db, t, query.BootAt(c.db, t))
				if err != nil {
					return fmt.Errorf("who: %w", err)
				}
				uutils := s.Source == "logind"
				var pids []int
				for _, e := range s.Entries {
					if e.Type == query.UtUserProcess && e.PID > 0 {
						pids = append(pids, e.PID)
					}
				}
				alive, err := query.PIDsAliveAt(c.db, t, pids)
				if err != nil {
					return err
				}
				o := query.WhoOptions{
					All: p.has("all"), Boot: p.has("boot"), Dead: p.has("dead"), Heading: p.has("heading"),
					Login: p.has("login"), Process: p.has("process"), Count: p.has("count"), RunLevel: p.has("runlevel"),
					Short: p.has("short"), Time: p.has("time"), Users: p.has("users"),
					Mesg: p.has("mesg") || p.has("writable") || p.has("message"),
					ISO:  query.WhoISO(uutils), UID: uutils && query.StyleAt(c.db, t).UnameUnknown,
				}
				c.header("logins: the recorded %s as of %s", map[bool]string{true: "logind sessions", false: "utmp"}[uutils], query.FormatMS(s.TS))
				return c.emit(s.Entries, func(int) rowMeta { return rowMeta{TS: s.TS} },
					func(w io.Writer) { query.PrintWho(w, s, o, t, func(pid int) bool { return alive[pid] }) })
			}, nil
		},
	}
}
