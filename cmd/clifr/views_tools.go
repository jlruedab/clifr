package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/query"
)

// The range views (--samples, --changes, diff) of the commands that show a
// moment: their snapshot, row key and what counts as a change.

func psView(c *runCtx, sel func(*query.PSRow) bool, f query.PSFormat, forest bool) view[query.PSRow] {
	return view[query.PSRow]{
		name: "ps",
		at: func(t int64) ([]query.PSRow, func(*query.PSRow) rowMeta, error) {
			rows, s, err := query.PSAt(c.db, t)
			if err != nil {
				return nil, nil, err
			}
			if sel != nil {
				kept := rows[:0]
				for i := range rows {
					if sel(&rows[i]) {
						kept = append(kept, rows[i])
					}
				}
				rows = kept
			}
			return rows, func(*query.PSRow) rowMeta { return rowMeta{TS: t, SampleTS: s, Sampled: psSampled} }, nil
		},
		key: func(r *query.PSRow) string { return strconv.Itoa(r.PID) + "/" + strconv.FormatInt(r.StartMS, 10) },
		// Changes that matter: the command line, user, parent, terminal; not
		// the values that move at every sample.
		same: func(a, b *query.PSRow) bool {
			return a.Command == b.Command && a.User == b.User && a.PPID == b.PPID && a.TTY == b.TTY
		},
		print: func(w io.Writer, rows []query.PSRow) {
			if forest {
				rows = query.PSForest(rows)
			}
			if f == nil {
				query.PrintPS(w, rows)
			} else {
				query.PrintPSFormat(w, rows, f)
			}
		},
	}
}

func sockKey(r *query.SSRow) string {
	return fmt.Sprintf("%s %s:%d %s:%d", r.Proto, r.Local, r.LPort, r.Peer, r.RPort)
}

func ownersText(r *query.SSRow) string {
	var s []string
	for _, o := range r.Owners {
		s = append(s, fmt.Sprintf("%s/%d/%d", o.Comm, o.PID, o.FD))
	}
	return strings.Join(s, ",")
}

func ssView(c *runCtx, tcp, udp bool, filter query.SockFilter, v query.SSView) view[query.SSRow] {
	return view[query.SSRow]{
		name: "ss",
		at: func(t int64) ([]query.SSRow, func(*query.SSRow) rowMeta, error) {
			rows, meta, err := socketsAt(c, t, tcp, udp, filter)
			return v.Filter(rows), meta, err
		},
		key:   sockKey,
		same:  func(a, b *query.SSRow) bool { return a.State == b.State && ownersText(a) == ownersText(b) },
		print: func(w io.Writer, rows []query.SSRow) { query.PrintSSView(w, rows, v, tcp && udp) },
	}
}

func netstatView(c *runCtx, tcp, udp bool, v query.NetstatView) view[query.SSRow] {
	var progs map[int]string
	return view[query.SSRow]{
		name: "netstat",
		at: func(t int64) ([]query.SSRow, func(*query.SSRow) rowMeta, error) {
			rows, meta, err := socketsAt(c, t, tcp, udp, query.SockFilter{})
			if err != nil {
				return nil, nil, err
			}
			kept := rows[:0]
			for i := range rows {
				if v.Keep(&rows[i]) {
					kept = append(kept, rows[i])
				}
			}
			if v.Program {
				if progs, err = query.ProgramNames(c.db, t); err != nil {
					return nil, nil, err
				}
			}
			return kept, meta, nil
		},
		key:   sockKey,
		same:  func(a, b *query.SSRow) bool { return a.State == b.State && ownersText(a) == ownersText(b) },
		print: func(w io.Writer, rows []query.SSRow) { query.PrintNetstat(w, rows, v, progs) },
	}
}

func lsofView(c *runCtx, sel query.LsofSelect) view[query.LsofRow] {
	return view[query.LsofRow]{
		name: "lsof",
		at: func(t int64) ([]query.LsofRow, func(*query.LsofRow) rowMeta, error) {
			rows, _, sfd, err := query.LsofAt(c.db, t, sel.Options())
			if err != nil {
				return nil, nil, err
			}
			rows = sel.Filter(rows)
			events := query.TCPFromEvents(c.db)
			return rows, func(r *query.LsofRow) rowMeta {
				if events && r.Node == "TCP" {
					return rowMeta{TS: t}
				}
				return rowMeta{TS: t, SampleTS: sfd, Sampled: jsonKeys(*r)}
			}, nil
		},
		// A socket's NAME ends with its state, "(ESTABLISHED)": a state
		// change is a change of the row, not a new one.
		key: func(r *query.LsofRow) string {
			name, _, _ := strings.Cut(r.Name, " (")
			return strconv.Itoa(r.PID) + " " + r.FD + " " + name
		},
		same:  func(a, b *query.LsofRow) bool { return a.Type == b.Type && a.Node == b.Node && a.Name == b.Name },
		print: func(w io.Writer, rows []query.LsofRow) { query.PrintLsof(w, rows, false) },
	}
}

func dfView(c *runCtx, f query.DFFormat, sel query.DFSelect, paths []string) view[query.DFRow] {
	return view[query.DFRow]{
		name: "df",
		at: func(t int64) ([]query.DFRow, func(*query.DFRow) rowMeta, error) {
			rows, err := query.DF(c.db, t, sel)
			if err != nil {
				return nil, nil, err
			}
			if len(paths) > 0 {
				var sel []query.DFRow
				for _, p := range paths {
					if r, ok := query.DFFor(rows, p); ok {
						sel = append(sel, r)
					}
				}
				rows = sel
			}
			return rows, func(r *query.DFRow) rowMeta {
				return rowMeta{TS: t, SampleTS: r.SampleTS, Sampled: []string{"size_bytes", "used_bytes", "avail_bytes", "inodes", "iused", "ifree"}}
			}, nil
		},
		key: func(r *query.DFRow) string { return r.Point },
		// A change: another file system there, or Use% moved by a point.
		same:  func(a, b *query.DFRow) bool { return a.Source == b.Source && a.UsePct() == b.UsePct() },
		print: func(w io.Writer, rows []query.DFRow) { query.PrintDF(w, rows, f) },
	}
}

func mountView(c *runCtx, types query.MountTypes) view[query.MountRow] {
	return view[query.MountRow]{
		name: "mount",
		at: func(t int64) ([]query.MountRow, func(*query.MountRow) rowMeta, error) {
			rows, err := query.MountsAt(c.db, t)
			if err != nil {
				return nil, nil, err
			}
			kept := rows[:0]
			for _, m := range rows {
				if types.Keep(m.FSType) {
					kept = append(kept, m)
				}
			}
			return kept, func(*query.MountRow) rowMeta { return rowMeta{TS: t} }, nil
		},
		key: func(m *query.MountRow) string { return m.Source + " on " + m.Point + " #" + strconv.Itoa(m.MountID) },
		same: func(a, b *query.MountRow) bool {
			return a.FSType == b.FSType && a.Options == b.Options && a.SuperOptions == b.SuperOptions
		},
		print: func(w io.Writer, rows []query.MountRow) { query.PrintMount(w, rows) },
	}
}
