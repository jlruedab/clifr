package query

import (
	"slices"
	"strconv"
	"strings"
)

// children maps each process to its children (by index into rows), in pid
// order; a process whose parent is not in rows is a root.
func children(rows []PSRow) (kids map[int][]int, roots []int) {
	at := map[int]int{}
	for i, r := range rows {
		at[r.PID] = i
	}
	kids = map[int][]int{}
	for i, r := range rows {
		if p, ok := at[r.PPID]; ok && r.PPID != r.PID {
			kids[p] = append(kids[p], i)
		} else {
			roots = append(roots, i)
		}
	}
	byPID := func(a, b int) int { return rows[a].PID - rows[b].PID }
	for _, k := range kids {
		slices.SortFunc(k, byPID)
	}
	slices.SortFunc(roots, byPID)
	return kids, roots
}

// PSForest orders rows as ps's f (forest) option does and gives each its
// prefix: init's children are not indented (the kernel reparents orphans to
// it), so the top level is pid 1, its children and the kernel threads' tree,
// kthreadd first; below them " \_ " marks a child, " |  " a level that has
// more siblings below.
func PSForest(rows []PSRow) []PSRow {
	kids, roots := children(rows)
	for _, i := range kids[pidIndex(rows, 1)] {
		roots = append(roots, i)
	}
	delete(kids, pidIndex(rows, 1))
	slices.SortFunc(roots, func(a, b int) int {
		ka, kb := rows[a].PID, rows[b].PID
		if ka == 2 && rows[a].PPID == 0 { // kthreadd's tree first, as procps prints it
			ka = -1
		}
		if kb == 2 && rows[b].PPID == 0 {
			kb = -1
		}
		return ka - kb
	})
	out := make([]PSRow, 0, len(rows))
	var walk func(i int, prefix string, depth int, last bool)
	walk = func(i int, prefix string, depth int, last bool) {
		r := rows[i]
		r.forest = ""
		next := ""
		if depth > 0 {
			r.forest = prefix + ` \_ `
			if last {
				next = prefix + "    "
			} else {
				next = prefix + " |  "
			}
		}
		out = append(out, r)
		for n, k := range kids[i] {
			walk(k, next, depth+1, n == len(kids[i])-1)
		}
	}
	for _, i := range roots {
		walk(i, "", 0, true)
	}
	return out
}

func pidIndex(rows []PSRow, pid int) int {
	for i, r := range rows {
		if r.PID == pid {
			return i
		}
	}
	return -1
}

// PstreeFormat holds pstree's options.
type PstreeFormat struct {
	Root    int  // the tree's top process (pstree's PID argument; 1 by default)
	SortPID bool // -n: children by pid, not by name
	Unicode bool // -U: line drawing characters
	Long    bool // -l: no line is cut (otherwise at 132 columns, ending in "+")
}

// Pstree renders the processes below f.Root as psmisc pstree -p does, without
// threads (they are not recorded: as with -T). ok is false when Root is not
// among the rows.
func Pstree(rows []PSRow, f PstreeFormat) (lines []string, ok bool) {
	kids, _ := children(rows)
	root := pidIndex(rows, f.Root)
	if root < 0 {
		return nil, false
	}
	for _, k := range kids {
		slices.SortStableFunc(k, func(a, b int) int {
			if f.SortPID {
				return rows[a].PID - rows[b].PID
			}
			if c := strings.Compare(rows[a].CommName, rows[b].CommName); c != 0 {
				return c
			}
			return rows[a].PID - rows[b].PID
		})
	}
	one, first, mid, last, bar := "---", "-+-", " |-", " `-", " | "
	if f.Unicode {
		one, first, mid, last, bar = "───", "─┬─", " ├─", " └─", " │ "
	}
	var render func(i int) []string
	render = func(i int) []string {
		label := psmiscSafe(rows[i].CommName) + "(" + strconv.Itoa(rows[i].PID) + ")"
		pad := strings.Repeat(" ", len(label))
		k := kids[i]
		if len(k) == 0 {
			return []string{label}
		}
		var out []string
		for n, c := range k {
			sub := render(c)
			cont := bar // the column continues below this child
			switch {
			case len(k) == 1:
				out = append(out, label+one+sub[0])
				cont = "   "
			case n == 0:
				out = append(out, label+first+sub[0])
			case n == len(k)-1:
				out = append(out, pad+last+sub[0])
				cont = "   "
			default:
				out = append(out, pad+mid+sub[0])
			}
			for _, s := range sub[1:] {
				out = append(out, pad+cont+s)
			}
		}
		return out
	}
	lines = render(root)
	if !f.Long {
		for i, l := range lines {
			if r := []rune(l); len(r) > 132 {
				lines[i] = string(r[:131]) + "+"
			}
		}
	}
	return lines, true
}
