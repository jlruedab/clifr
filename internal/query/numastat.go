package query

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"clifr/internal/store"
)

// NUMANode is what clifrd read of a NUMA node: its numastat and meminfo
// lines and its huge pages (size in kB -> total, free, surplus).
type NUMANode struct {
	Node     int                `json:"node"`
	Numastat []string           `json:"numastat"`
	Meminfo  []string           `json:"meminfo"`
	Huge     map[int64][3]int64 `json:"hugepages,omitempty"`
}

// NUMAAt returns the NUMA nodes as clifrd last read them at or before t
// (every minute), in node order.
func NUMAAt(db *store.DB, t int64) ([]NUMANode, error) {
	lines, _, ok, err := FileAt(db, "numa", t)
	if err != nil {
		return nil, err
	}
	if !ok || len(lines) == 0 {
		return nil, fmt.Errorf("numastat: NUMA nodes not recorded at %s (recorded since schema 9)", FormatMS(t))
	}
	byNode := map[int]*NUMANode{}
	var order []int
	for _, l := range lines {
		f := strings.SplitN(l, " ", 3)
		if len(f) < 3 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(f[0], "node"))
		if err != nil {
			continue
		}
		node := byNode[n]
		if node == nil {
			node = &NUMANode{Node: n, Huge: map[int64][3]int64{}}
			byNode[n] = node
			order = append(order, n)
		}
		switch f[1] {
		case "numastat":
			node.Numastat = append(node.Numastat, f[2])
		case "meminfo":
			node.Meminfo = append(node.Meminfo, f[2])
		case "hugepages":
			v := strings.Fields(f[2])
			if len(v) == 4 {
				var h [3]int64
				size, _ := strconv.ParseInt(v[0], 10, 64)
				for i := range h {
					h[i], _ = strconv.ParseInt(v[i+1], 10, 64)
				}
				node.Huge[size] = h
			}
		}
	}
	sort.Ints(order)
	out := make([]NUMANode, 0, len(order))
	for _, n := range order {
		out = append(out, *byNode[n])
	}
	return out, nil
}

// NumastatOptions: -m (meminfo), -n (numastat in MB), -c (compress), -z
// (leave out zero rows and columns); none of them: the compatibility
// output (numastat counters, one column per node).
type NumastatOptions struct {
	Meminfo, Numastat, Compress, NoZero bool
	// Old: numastat before 2.0.15 (version "20130723"): fixed rows in its
	// own order, "Token X not in hash table." for any other meminfo line,
	// huge pages counted in the default size.
	Old bool
}

// numastatOldRows are the old numastat's meminfo rows, in its order.
var numastatOldRows = []string{"MemTotal", "MemFree", "MemUsed", "HighTotal", "HighFree", "LowTotal", "LowFree", "Active",
	"Inactive", "Active(anon)", "Inactive(anon)", "Active(file)", "Inactive(file)", "Unevictable", "Mlocked", "Dirty",
	"Writeback", "FilePages", "Mapped", "AnonPages", "Shmem", "KernelStack", "PageTables", "NFS_Unstable", "Bounce",
	"WritebackTmp", "Slab", "SReclaimable", "SUnreclaim", "AnonHugePages", "ShmemHugePages", "ShmemPmdMapped",
	"HugePages_Total", "HugePages_Free", "HugePages_Surp", "KReclaimable"}

// numastatOldCounters are its numastat rows.
var numastatOldCounters = []string{"numa_hit", "numa_miss", "numa_foreign", "interleave_hit", "local_node", "other_node"}

// hugeField: the NUMANode.Huge counts behind a HugePages_* row.
var hugeField = map[string]int{"HugePages_Total": 0, "HugePages_Free": 1, "HugePages_Surp": 2}

// numaTable is numastat's vtab for one file: rows of a label and one value
// per node and the total.
type numaTable struct {
	labels []string
	vals   [][]float64 // per row: nodes..., total
}

// PrintNumastat prints numastat (2.0.19's table code) without a terminal:
// no line folding.
func PrintNumastat(w io.Writer, nodes []NUMANode, o NumastatOptions, pageBytes int64) {
	compat := !o.Meminfo && !o.Numastat
	if compat {
		printNumaTable(w, nodes, "numastat", true, o, pageBytes)
		return
	}
	if o.Meminfo {
		fmt.Fprint(w, "\nPer-node system memory usage (in MBs):\n")
		printNumaTable(w, nodes, "meminfo", false, o, pageBytes)
	}
	if o.Numastat {
		fmt.Fprint(w, "\nPer-node numastat info (in MBs):\n")
		printNumaTable(w, nodes, "numastat", false, o, pageBytes)
	}
}

func printNumaTable(w io.Writer, nodes []NUMANode, file string, compat bool, o NumastatOptions, pageBytes int64) {
	const mb = 1024 * 1024
	lines := func(n NUMANode) []string {
		if file == "meminfo" {
			return n.Meminfo
		}
		return n.Numastat
	}
	tokOffset := 0
	if file == "meminfo" {
		tokOffset = 2
	}
	split := func(l string) []string {
		return strings.FieldsFunc(l, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == ':' })
	}
	var t numaTable
	index := map[string]int{}
	if o.Old {
		// The rows are fixed; one that no node has is not shown.
		rows := numastatOldCounters
		if file == "meminfo" {
			rows = numastatOldRows
		}
		for _, r := range rows {
			label := r
			if !compat && file != "meminfo" {
				label = capitalizeWords(r)
			}
			index[r] = len(t.labels)
			t.labels = append(t.labels, label)
			t.vals = append(t.vals, make([]float64, len(nodes)+1))
		}
	}
	seen := make([]bool, len(t.labels))
	for ni, n := range nodes {
		for _, l := range lines(n) {
			tok := split(l)
			if len(tok) <= tokOffset+1 {
				continue
			}
			name := tok[tokOffset]
			if ni == 0 && !o.Old {
				label := name
				if !compat && file != "meminfo" { // Numa_Hit
					label = capitalizeWords(label)
				}
				index[name] = len(t.labels)
				t.labels = append(t.labels, label)
				t.vals = append(t.vals, make([]float64, len(nodes)+1))
				seen = append(seen, false)
			}
			row, ok := index[name]
			if !ok {
				if o.Old {
					fmt.Fprintf(w, "Token %s not in hash table.\n", name)
				}
				continue
			}
			seen[row] = true
			v, _ := strconv.ParseInt(tok[tokOffset+1], 10, 64)
			value := float64(v)
			if !compat {
				mult := 1.0
				switch {
				case len(tok) < 4:
					mult = float64(pageBytes)
				case strings.HasPrefix(tok[2], "HugePages") && o.Old:
					mult = float64(defaultHugeKB(n.Huge) * 1024)
				case strings.HasPrefix(tok[2], "HugePages"):
					// 2.0.19: the pages of every size, from sysfs
					if i, ok := hugeField[tok[2]]; ok {
						var total int64
						for size, h := range n.Huge {
							total += h[i] * size * 1024
						}
						if total > 0 {
							value = float64(total)
						}
					}
				case len(tok) > 4 && strings.HasPrefix(tok[4], "kB"):
					mult = 1024
				}
				value = value * mult / mb
			}
			t.vals[row][ni] = value
			t.vals[row][len(nodes)] += value
		}
	}
	// Columns: the labels (16, left), each node and the total (16, right;
	// the compatibility output sets no width for the total: not shown).
	ncols := len(nodes) + 2
	width := make([]int, ncols)
	width[0] = 16
	for c := 1; c < ncols; c++ {
		width[c] = 16
	}
	decimals := 2
	if compat {
		width[ncols-1], decimals = 0, 0
	}
	if o.Compress {
		decimals = 0
	}
	header := make([]string, ncols)
	for i, n := range nodes {
		if compat {
			header[i+1] = "node" + strconv.Itoa(n.Node)
		} else {
			header[i+1] = "Node " + strconv.Itoa(n.Node)
		}
	}
	if !compat {
		header[ncols-1] = "Total"
	}
	cell := func(row, col int) string { // data cells
		return strconv.FormatFloat(t.vals[row][col-1], 'f', decimals, 64)
	}
	if o.Compress {
		for c := 0; c < ncols; c++ {
			if width[c] == 0 {
				continue
			}
			wd := 4
			if c == 0 {
				for _, l := range t.labels {
					wd = max(wd, len(l))
				}
			} else {
				wd = max(wd, len(header[c]))
				for r := range t.labels {
					wd = max(wd, len(cell(r, c)))
				}
			}
			width[c] = min(wd+1, 16)
		}
	}
	// -z: rows and node columns that are all zero are left out.
	showCol := make([]bool, ncols)
	for c := 1; c < ncols; c++ {
		showCol[c] = !o.NoZero
		for r := range t.labels {
			if t.vals[r][c-1] != 0 {
				showCol[c] = true
			}
		}
	}
	just := func(s string, wd int, left bool) string {
		if len(s) > wd {
			s = s[:wd]
		}
		if left {
			return s + strings.Repeat(" ", wd-len(s))
		}
		return strings.Repeat(" ", wd-len(s)) + s
	}
	line := func(cells func(c int) string) {
		var b strings.Builder
		b.WriteString(just(cells(0), width[0], true))
		for c := 1; c < ncols; c++ {
			if showCol[c] {
				b.WriteString(just(cells(c), width[c], false))
			}
		}
		fmt.Fprintln(w, b.String())
	}
	line(func(c int) string { return header[c] })
	if !compat {
		line(func(c int) string {
			if c == 0 || width[c] == 0 {
				return ""
			}
			return strings.Repeat("-", width[c]-1)
		})
	}
	for r, l := range t.labels {
		if !seen[r] {
			continue
		}
		if o.NoZero {
			zero := true
			for _, v := range t.vals[r] {
				zero = zero && v == 0
			}
			if zero {
				continue
			}
		}
		line(func(c int) string {
			if c == 0 {
				return l
			}
			return cell(r, c)
		})
	}
}

// capitalizeWords is numastat's label for a numastat counter: the first
// letter and each one after '_' in upper case (Numa_Hit).
func capitalizeWords(s string) string {
	rs := []rune(s)
	for i := range rs {
		if i == 0 || rs[i-1] == '_' {
			rs[i] = unicode.ToUpper(rs[i])
		}
	}
	return string(rs)
}

// defaultHugeKB is the default huge page size (2048 kB where the node has
// it, else its smallest).
func defaultHugeKB(h map[int64][3]int64) int64 {
	if _, ok := h[2048]; ok || len(h) == 0 {
		return 2048
	}
	small := int64(0)
	for s := range h {
		if small == 0 || s < small {
			small = s
		}
	}
	return small
}
