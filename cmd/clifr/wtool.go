package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"clifr/internal/query"
)

func wTool() *tool {
	return &tool{
		name: "w", synopsis: "[-hsfoiup] [USER]",
		about: "who was logged in and what they were doing, as procps w prints it",
		opts: []opt{
			{short: 'h', long: "no-header", help: "no uptime line and no column headings"},
			{short: 'u', long: "no-current", help: "ignore the user when choosing the process shown (WHAT)"},
			{short: 's', long: "short", help: "short format: no LOGIN@, JCPU and PCPU"},
			{short: 'f', long: "from", help: "toggle the FROM column (shown by default, except RHEL 9's w)"},
			{short: 'o', long: "old-style", help: "old style output (blank for under a minute)"},
			{short: 'i', long: "ip-addr", help: "the recorded IP address instead of the host name"},
			{short: 'p', long: "pids", help: "the login and shown processes' PIDs (procps 4)"},
		},
		window: true,
		notes: []string{
			"The login sessions at T (recorded since 2026-11-20) as the recorded host's procps w lists them:",
			"3.3 (RHEL 8/9, Ubuntu 22.04) reads utmp; Debian/Ubuntu's 4.0.4 reads logind's user sessions,",
			"else utmp. The uptime line as clifr uptime prints it, with the users counted the same way.",
			"IDLE is the time since the terminal's last access (read at system samples, 10 s). JCPU (all",
			"processes on the terminal), PCPU and WHAT (the user's newest foreground process there, else the",
			"login process) come from the processes alive at T with their CPU time at the last process",
			"sample, at most --interval (30 s) old, as ps shows them; a session whose login process was gone",
			"at T is left out, as w does. WHAT fits $COLUMNS (512 when unset, as w into a pipe).",
			"Not supported: -t (terminal mode). A user missing from the recorded /etc/passwd (LDAP, sssd)",
			"is shown, without a foreground process (w would look it up through NSS).",
		},
		examples: []string{`clifr --at "09:30" w`, `clifr --at "09:30" "w -i alice"`},
		prepare: func(p parsed, c *runCtx) (func() error, error) {
			if len(p.pos) > 1 {
				return nil, fmt.Errorf("w: unexpected argument %q", p.pos[1])
			}
			if c.w.IsRange() {
				return nil, errors.New("w: needs --at (last lists the logins over a range)")
			}
			o := query.WOptions{NoHeader: p.has("no-header"), NoCurrent: p.has("no-current"), Short: p.has("short"),
				ToggleFrom: p.has("from"), OldStyle: p.has("old-style"), IPAddr: p.has("ip-addr"), PIDs: p.has("pids")}
			if len(p.pos) == 1 {
				o.User = p.pos[0]
			}
			if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
				o.Columns = n
			}
			return func() error {
				t := c.w.At
				procps3 := query.Procps3(c.db, t)
				o.NoFromDefault = query.StyleAt(c.db, t).WNoFrom
				if procps3 && o.PIDs {
					return errors.New("w: -p is procps 4's (the recorded host has procps 3.3)")
				}
				rep, err := query.WAt(c.db, t, procps3, o)
				if err != nil {
					return fmt.Errorf("w: %w", err)
				}
				c.header("w at %s: sessions as recorded, processes at the sample of %s", query.FormatMS(t), query.FormatMS(rep.Uptime.TS))
				return c.emit(rep.Lines, func(int) rowMeta { return rowMeta{TS: t, Sampled: []string{"jcpu_ticks", "pcpu_ticks", "idle_s"}} },
					func(w io.Writer) { query.PrintW(w, rep, o) })
			}, nil
		},
	}
}
