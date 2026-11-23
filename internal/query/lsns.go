// lsns, following util-linux's sys-utils/lsns.c (2.32, 2.37, 2.39, 2.41;
// GPL-2.0-or-later; packaging/notices/util-linux.txt): the namespaces of the
// processes sampled at a moment (processes.netns and ns_*, schema 15), each
// with its number of processes and the lowest PID, the default process tree
// and -l, -t, -p, -o. Namespaces lsns finds only through open fds, sockets
// or bind mounts are not recorded.

package query

import (
	"database/sql"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// lsnsTypes are lsns' namespace types in its order (ns_names); 2.32 has no
// time.
var lsnsTypes = []string{"mnt", "net", "pid", "uts", "ipc", "user", "cgroup", "time"}

type lsnsProc struct {
	pid, ppid, uid int
	cmd            string
	parent         *lsnsProc
	ns             map[string]uint32
	outline        *lsnsLine
}

type lsnsNS struct {
	typ   string
	ino   uint32
	procs []*lsnsProc
	proc  *lsnsProc // the lowest PID
}

type lsnsLine struct {
	cells    []string
	children []*lsnsLine
}

// Lsns is the namespaces of the processes sampled at a moment.
type Lsns struct {
	TS    int64 `json:"ts_ms"`
	procs []*lsnsProc
	nss   []*lsnsNS // by inode
	nsfs  map[uint32][]string
	nsid  map[uint32]string
}

// LsnsAt reads the processes of the sample at or before t and their
// namespaces (recorded since schema 15).
func LsnsAt(db *store.DB, t int64) (*Lsns, error) {
	s, err := SnapshotAt(db, t, false)
	if err != nil {
		return nil, err
	}
	procs, err := processesAt(db, s, s)
	if err != nil {
		return nil, err
	}
	host, _ := strconv.ParseUint(MetaAt(db, "netns_host", s), 10, 32)
	ns := map[int64][7]sql.NullInt64{}
	rows, err := db.Query(`SELECT id, ns_cgroup, ns_ipc, ns_mnt, ns_pid, ns_time, ns_user, ns_uts FROM processes WHERE ns_mnt IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var v [7]sql.NullInt64
		if err := rows.Scan(&id, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6]); err != nil {
			rows.Close()
			return nil, err
		}
		ns[id] = v
	}
	rows.Close()
	if len(ns) == 0 || host == 0 {
		return nil, fmt.Errorf("lsns: the processes' namespaces are recorded since 2026-11-23 (schema 15)")
	}
	l := &Lsns{TS: s, nsfs: map[uint32][]string{}, nsid: map[uint32]string{}}
	byPID := map[int]*lsnsProc{}
	for _, p := range procs {
		v, ok := ns[p.id]
		if !ok || !p.state.Valid {
			continue
		}
		lp := &lsnsProc{pid: p.pid, ppid: p.ppid, uid: p.uid, cmd: p.cmdline, ns: map[string]uint32{}}
		if lp.cmd == "" {
			lp.cmd = p.comm
		}
		for i, typ := range store.NSTypes {
			if v[i].Valid && v[i].Int64 > 0 {
				lp.ns[typ] = uint32(v[i].Int64)
			}
		}
		net := uint32(host)
		if p.netns.Valid && p.netns.Int64 != 0 {
			net = uint32(p.netns.Int64)
		}
		lp.ns["net"] = net
		l.procs = append(l.procs, lp)
		byPID[lp.pid] = lp
	}
	sort.Slice(l.procs, func(i, j int) bool { return l.procs[i].pid < l.procs[j].pid })
	for _, p := range l.procs {
		p.parent = byPID[p.ppid]
	}
	// nsfs bind mounts (NSFS) and /run/netns ids (NETNSID).
	if ms, err := MountsAt(db, t); err == nil {
		for _, m := range ms {
			if m.FSType != "nsfs" {
				continue
			}
			if _, ino, ok := strings.Cut(strings.TrimSuffix(m.Root, "]"), ":["); ok {
				if n, err := strconv.ParseUint(ino, 10, 32); err == nil {
					l.nsfs[uint32(n)] = append(l.nsfs[uint32(n)], m.Point)
				}
			}
		}
	}
	return l, nil
}

// LsnsOpts are lsns' options.
type LsnsOpts struct {
	List     bool
	Types    map[string]bool // -t (nil: all)
	PID      int             // -p (0: all)
	Cols     []string
	ColsAdd  bool
	NoHead   bool
	Raw      bool
	ASCII    bool
	Version  string // "" 2.41, "2.39", "2.37", "2.32"
	Inode    uint32 // lsns NAMESPACE: its processes
	hasInode bool
}

var lsnsCols = []struct {
	name  string
	hint  int
	right bool
}{{"NS", 10, true}, {"TYPE", 5, false}, {"PATH", 0, false}, {"NPROCS", 5, true}, {"PID", 5, true}, {"PPID", 5, true},
	{"COMMAND", 0, false}, {"UID", 0, true}, {"USER", 0, false}, {"NETNSID", 0, true}, {"NSFS", 0, false}}

// LsnsColumn reports whether lsns has column name (PNS, ONS: not recorded).
func LsnsColumn(name string) bool {
	for _, c := range lsnsCols {
		if c.name == name {
			return true
		}
	}
	return false
}

// namespaces groups the processes by namespace, in inode order.
func (l *Lsns) namespaces(o LsnsOpts) []*lsnsNS {
	byKey := map[[2]string]*lsnsNS{}
	var out []*lsnsNS
	for _, p := range l.procs {
		for _, typ := range lsnsTypes {
			if typ == "time" && o.Version == "2.32" || o.Types != nil && !o.Types[typ] {
				continue
			}
			ino, ok := p.ns[typ]
			if !ok {
				continue
			}
			k := [2]string{typ, strconv.FormatUint(uint64(ino), 10)}
			n := byKey[k]
			if n == nil {
				n = &lsnsNS{typ: typ, ino: ino}
				byKey[k] = n
				out = append(out, n)
			}
			n.procs = append(n.procs, p)
			if n.proc == nil || p.pid < n.proc.pid {
				n.proc = p
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ino < out[j].ino })
	return out
}

func (o LsnsOpts) cols() []string {
	cols := []string{"NS", "TYPE", "NPROCS", "PID", "USER"}
	if o.Types != nil && len(o.Types) == 1 && o.Types["net"] {
		cols = append(cols, "NETNSID", "NSFS")
	}
	cols = append(cols, "COMMAND")
	if len(o.Cols) > 0 {
		if o.ColsAdd {
			return append(cols, o.Cols...)
		}
		return o.Cols
	}
	return cols
}

func (l *Lsns) cell(col string, n *lsnsNS, p *lsnsProc) string {
	switch col {
	case "NS":
		return strconv.FormatUint(uint64(n.ino), 10)
	case "TYPE":
		return n.typ
	case "NPROCS":
		return strconv.Itoa(len(n.procs))
	case "PID":
		return strconv.Itoa(p.pid)
	case "PPID":
		return strconv.Itoa(p.ppid)
	case "COMMAND":
		return scolsEncode(p.cmd)
	case "PATH":
		return fmt.Sprintf("/proc/%d/ns/%s", p.pid, n.typ)
	case "UID":
		return strconv.Itoa(p.uid)
	case "USER":
		return UserName(p.uid, false)
	case "NETNSID":
		if n.typ == "net" {
			if id, ok := l.nsid[n.ino]; ok {
				return id
			}
			return "unassigned"
		}
	case "NSFS":
		return strings.Join(l.nsfs[n.ino], "\n")
	}
	return ""
}

// Rows: the lines lsns prints, the tree's art already in COMMAND (when
// tree). JSON uses the cells without art.
func (l *Lsns) Rows(o LsnsOpts) ([]string, [][]string) {
	cols := o.cols()
	var roots []*lsnsLine
	var flat [][]string
	for _, n := range l.namespaces(o) {
		if o.PID != 0 {
			has := false
			for _, p := range n.procs {
				has = has || p.pid == o.PID
			}
			if !has {
				continue
			}
		}
		line := &lsnsLine{}
		for _, c := range cols {
			line.cells = append(line.cells, l.cell(c, n, n.proc))
		}
		flat = append(flat, line.cells)
		if p := n.proc.parent; !o.List && p != nil && p.outline != nil {
			p.outline.children = append(p.outline.children, line)
		} else {
			roots = append(roots, line)
		}
		n.proc.outline = line
	}
	tree := -1
	for i, c := range cols {
		if c == "COMMAND" {
			tree = i
		}
	}
	// The tree is COMMAND's: without it libsmartcols prints the lines in
	// the order they were added (by inode). Before 2.39 the namespaces are
	// never a tree (lsns.c sets tree only with a NAMESPACE argument).
	if o.List || tree < 0 || o.Version == "2.32" || o.Version == "2.37" {
		return cols, flat
	}
	branch, last, vert := "├─", "└─", "│ "
	if o.ASCII {
		branch, last, vert = "|-", "`-", "| "
	}
	var out [][]string
	var walk func(ln *lsnsLine, art, mine string)
	walk = func(ln *lsnsLine, art, mine string) {
		cells := append([]string(nil), ln.cells...)
		if tree >= 0 {
			cells[tree] = art + mine + cells[tree]
		}
		out = append(out, cells)
		for i, c := range ln.children {
			a, m := art, branch
			if mine == branch {
				a += vert
			} else if mine == last {
				a += "  "
			}
			if i == len(ln.children)-1 {
				m = last
			}
			walk(c, a, m)
		}
	}
	for _, r := range roots {
		walk(r, "", "")
	}
	return cols, out
}

// PrintLsns prints the table as lsns does into a pipe.
func PrintLsns(w io.Writer, l *Lsns, o LsnsOpts) {
	cols, rows := l.Rows(o)
	if len(rows) == 0 {
		return
	}
	right := func(i int) bool {
		for _, c := range lsnsCols {
			if c.name == cols[i] {
				return c.right
			}
		}
		return false
	}
	hint := func(i int) int {
		for _, c := range lsnsCols {
			if c.name == cols[i] {
				return c.hint
			}
		}
		return 0
	}
	if o.Raw {
		all := append([][]string{cols}, rows...)
		if o.NoHead {
			all = rows
		}
		printScols(w, all, right, true)
		return
	}
	width := make([]int, len(cols))
	for i := range cols {
		head := runeLen(cols[i])
		if o.NoHead && o.Version == "" {
			head = 1
		}
		data := 0
		for _, r := range rows {
			for _, part := range strings.Split(r[i], "\n") {
				data = max(data, runeLen(part))
			}
		}
		width[i] = scolsWidth(head, data, hint(i))
	}
	line := func(cells []string) {
		var b strings.Builder
		for i, v := range cells {
			v, _, _ = strings.Cut(v, "\n")
			pad := max(width[i]-runeLen(v), 0)
			switch {
			case right(i):
				b.WriteString(strings.Repeat(" ", pad) + v)
			case i == len(cells)-1:
				b.WriteString(v)
			default:
				b.WriteString(v + strings.Repeat(" ", pad))
			}
			if i < len(cells)-1 {
				b.WriteByte(' ')
			}
		}
		fmt.Fprintln(w, b.String())
	}
	if !o.NoHead {
		line(cols)
	}
	for _, r := range rows {
		line(r)
	}
}

func runeLen(s string) int { return len([]rune(s)) }
