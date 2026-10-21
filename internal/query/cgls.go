package query

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// CglsProc is one process in a control group.
type CglsProc struct {
	PID     int    `json:"pid"`
	Cgroup  string `json:"cgroup"`
	Command string `json:"command"`
	Kernel  bool   `json:"kernel_thread"`
	pad     int    // NULs after the command line in /proc/<pid>/cmdline
}

// CglsOptions: -l (no line width), -k (kernel threads too), ASCII glyphs
// (systemd's choice for a non-UTF-8 locale), the line width otherwise.
type CglsOptions struct {
	Full, Kernel, ASCII bool
	Columns             int
}

// CglsAt returns the processes of the sample at or before t with their
// systemd cgroup (procfs.SystemdCgroup), and which cgroups were delegated.
// Processes only seen through events have no cgroup and are left out, as
// are those of recordings before 2026-10-22.
func CglsAt(db *store.DB, t int64) ([]CglsProc, map[string]bool, int64, error) {
	s, err := SnapshotAt(db, t, false)
	if err != nil {
		return nil, nil, 0, err
	}
	procs, err := processesAt(db, s, s)
	if err != nil {
		return nil, nil, 0, err
	}
	var out []CglsProc
	for _, p := range procs {
		cg, _, ok := procfs.SystemdCgroup(p.cgroup.String)
		if !ok || !p.state.Valid {
			continue
		}
		c := CglsProc{PID: p.pid, Cgroup: cg, Command: p.cmdline, pad: max(int(p.cmdlinePad.Int64), 1),
			// Kernel threads: no command line, and kthreadd or its children.
			Kernel: p.cmdline == "" && (p.pid == 2 || p.ppid == 2)}
		if c.Command == "" || p.state.String == "Z" {
			c.Command = "[" + p.comm + "]"
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, nil, 0, fmt.Errorf("systemd-cgls: no cgroups recorded at %s (recorded since 2026-10-22)", FormatMS(s))
	}
	delegated := map[string]bool{}
	rows, err := db.Query(`SELECT path, arg_max(delegate, ts) FROM cgroups WHERE ts <= ? GROUP BY path`, s)
	if err != nil {
		return nil, nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		var d int
		if err := rows.Scan(&p, &d); err != nil {
			return nil, nil, 0, err
		}
		delegated[p] = d == 1
	}
	return out, delegated, s, rows.Err()
}

// cglsCommand is systemd's get_process_cmdline for a room of columns (-1:
// no limit): it reads at most room bytes of /proc/<pid>/cmdline (NULs
// become spaces, trailing whitespace is dropped), escapes control
// characters and backslashes as \xNN, and ends in an ellipsis when the file
// was longer than that or the escaped text does not fit.
func cglsCommand(p CglsProc, room int, ascii bool) string {
	raw := p.Command + strings.Repeat(" ", p.pad-1) // the NUL padding, as spaces (the final NUL ends it)
	cut := false
	if room >= 0 && len(raw)+1 > room {
		raw, cut = raw[:room], true
	}
	raw = strings.TrimRight(raw, " \t\n\r")
	ell := "…"
	if ascii {
		ell = "..."
	}
	var units []string // one per input byte: itself or its escape
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c < 0x20 || c == 0x7f || c == '\\' || ascii && c >= 0x80 {
			units = append(units, fmt.Sprintf("\\x%02x", c))
		} else {
			units = append(units, string(c))
		}
	}
	n := 0
	for _, u := range units {
		n += len(u)
	}
	if room < 0 || !cut && n <= room {
		return strings.Join(units, "")
	}
	var b strings.Builder
	for _, u := range units {
		if b.Len()+len(u)+utf8.RuneCountInString(ell) > room {
			break
		}
		b.WriteString(u)
	}
	return b.String() + ell
}

// kernfsHash is the kernel's kernfs_name_hash for a name without namespace
// (64-bit kernels since 4.7): cgroupfs lists a directory's entries in this
// order, and systemd-cgls shows them as listed.
func kernfsHash(name string) uint32 {
	var h uint64
	for i := 0; i < len(name); i++ {
		c := uint64(name[i])
		h = (h + c<<4 + c>>4) * 11
	}
	x := uint32((h * 0x61C8864680B583EB) >> 32)
	x &= 0x7fffffff
	if x < 2 {
		x += 2
	}
	if x >= 0x7fffffff {
		x = 0x7fffffff - 1
	}
	return x
}

type cgNode struct {
	name     string
	procs    []CglsProc
	children map[string]*cgNode
}

// PrintCgls prints the tree as systemd-cgls without arguments: "CGroup /:",
// the root slice, then each cgroup with processes below it (empty ones
// left out), its processes first (sorted by PID), then its children in
// cgroupfs order. Delegated cgroups end in an ellipsis.
func PrintCgls(w io.Writer, procs []CglsProc, delegated map[string]bool, o CglsOptions) {
	root := &cgNode{name: "/", children: map[string]*cgNode{}}
	for _, p := range procs {
		if p.Kernel && !o.Kernel {
			continue
		}
		n := root
		for _, part := range strings.Split(strings.Trim(p.Cgroup, "/"), "/") {
			if part == "" {
				continue
			}
			c := n.children[part]
			if c == nil {
				c = &cgNode{name: part, children: map[string]*cgNode{}}
				n.children[part] = c
			}
			n = c
		}
		n.procs = append(n.procs, p)
	}
	g := map[string]string{"branch": "├─", "right": "└─", "vertical": "│ ", "space": "  ", "ellipsis": "…"}
	if o.ASCII {
		g = map[string]string{"branch": "|-", "right": "`-", "vertical": "| ", "space": "  ", "ellipsis": "..."}
	}
	fmt.Fprintln(w, "CGroup /:")
	fmt.Fprintln(w, "-.slice")
	var walk func(n *cgNode, cgPath, prefix string)
	walk = func(n *cgNode, cgPath, prefix string) {
		sort.Slice(n.procs, func(i, j int) bool { return n.procs[i].PID < n.procs[j].PID })
		kids := make([]*cgNode, 0, len(n.children))
		for _, c := range n.children {
			kids = append(kids, c)
		}
		sort.Slice(kids, func(i, j int) bool {
			hi, hj := kernfsHash(kids[i].name), kernfsHash(kids[j].name)
			if hi != hj {
				return hi < hj
			}
			return kids[i].name < kids[j].name
		})
		width := 0
		for _, p := range n.procs {
			width = max(width, len(strconv.Itoa(p.PID)))
		}
		for i, p := range n.procs {
			glyph := g["branch"]
			if i == len(n.procs)-1 && len(kids) == 0 {
				glyph = g["right"]
			}
			room := -1 // -l: no limit
			if !o.Full {
				// What is left of the line after the prefix, the glyph, the
				// PID and a space.
				room = o.Columns - utf8.RuneCountInString(prefix) - width - 3
				if room <= 0 {
					room = 20
				}
			}
			cmd := cglsCommand(p, room, o.ASCII)
			fmt.Fprintf(w, "%s%s%*d %s\n", prefix, glyph, width, p.PID, cmd)
		}
		for i, c := range kids {
			glyph, next := g["branch"], g["vertical"]
			if i == len(kids)-1 {
				glyph, next = g["right"], g["space"]
			}
			p := path.Join(cgPath, c.name)
			mark := ""
			if delegated[p] {
				mark = " " + g["ellipsis"]
			}
			fmt.Fprintf(w, "%s%s%s%s\n", prefix, glyph, c.name, mark)
			walk(c, p, prefix+next)
		}
	}
	walk(root, "/", "")
}
