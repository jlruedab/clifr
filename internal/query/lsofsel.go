package query

import (
	"strconv"
	"strings"
)

// LsofSelect is lsof's selection: -p, -u, -c and -i are ORed, unless -a
// ANDs them. Users may be names or numbers; commands match by prefix.
type LsofSelect struct {
	PIDs     []int
	Users    []string
	Commands []string
	Inet     bool
	And      bool
}

func (s LsofSelect) empty() bool {
	return len(s.PIDs) == 0 && len(s.Users) == 0 && len(s.Commands) == 0 && !s.Inet
}

// Options returns what the database query can narrow by itself: one process,
// or inet sockets only, when that is the whole selection.
func (s LsofSelect) Options() LsofOptions {
	switch {
	case len(s.PIDs) == 1 && len(s.Users) == 0 && len(s.Commands) == 0 && (!s.Inet || s.And):
		return LsofOptions{PID: s.PIDs[0], InetOnly: s.Inet}
	case s.Inet && len(s.PIDs) == 0 && len(s.Users) == 0 && len(s.Commands) == 0:
		return LsofOptions{InetOnly: true}
	}
	return LsofOptions{}
}

// Filter keeps the rows the selection lists.
func (s LsofSelect) Filter(rows []LsofRow) []LsofRow {
	if s.empty() {
		return rows
	}
	users := map[string]bool{}
	for _, u := range s.Users {
		if n, err := strconv.Atoi(u); err == nil {
			u = UserName(n, false)
		}
		users[u] = true
	}
	out := rows[:0]
	for _, r := range rows {
		var hits, tests int
		test := func(on, hit bool) {
			if on {
				tests++
				if hit {
					hits++
				}
			}
		}
		pidHit := false
		for _, p := range s.PIDs {
			pidHit = pidHit || r.PID == p
		}
		test(len(s.PIDs) > 0, pidHit)
		test(len(s.Users) > 0, users[r.User])
		cmdHit := false
		for _, c := range s.Commands {
			cmdHit = cmdHit || strings.HasPrefix(r.Command, c)
		}
		test(len(s.Commands) > 0, cmdHit)
		test(s.Inet, strings.HasPrefix(r.Type, "IPv"))
		if s.And && hits == tests || !s.And && hits > 0 {
			out = append(out, r)
		}
	}
	return out
}
