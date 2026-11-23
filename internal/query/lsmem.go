// lsmem, following util-linux's sys-utils/lsmem.c (2.32, 2.37, 2.39, 2.41;
// GPL-2.0-or-later; packaging/notices/util-linux.txt): its blocks merged by
// the columns shown (or -S), its columns and summary, from the memory blocks
// clifrd records (snapshot source "memory", recorder/memblocks.go).

package query

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/store"
)

type memBlock struct {
	index, count int
	state        string // online, offline, going-offline
	removable    bool
	node         int
	zones        []string
}

// Lsmem is the recorded memory blocks at a moment.
type Lsmem struct {
	TS        int64 `json:"ts_ms"`
	blockSize uint64
	haveZones bool
	haveNodes bool
	blocks    []memBlock // one per block
}

// LsmemAt reads the blocks as last recorded at or before t.
func LsmemAt(db *store.DB, t int64) (*Lsmem, error) {
	lines, ts, ok, err := FileAt(db, "memory", t)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("lsmem: the memory blocks are recorded since 2026-11-23 (not at %s)", FormatMS(t))
	}
	return newLsmem(ts, lines)
}

func newLsmem(ts int64, lines []string) (*Lsmem, error) {
	m := &Lsmem{TS: ts}
	for _, l := range lines {
		f := strings.Split(l, "\t")
		switch {
		case f[0] == "block_size_bytes" && len(f) == 2:
			m.blockSize, _ = strconv.ParseUint(f[1], 16, 64)
		case f[0] == "zones":
			m.haveZones = true
		case len(f) == 6:
			first, _ := strconv.Atoi(f[0])
			last, _ := strconv.Atoi(f[1])
			node, _ := strconv.Atoi(f[4])
			if node != -1 {
				m.haveNodes = true
			}
			var zones []string
			if f[5] != "" {
				zones = strings.Fields(f[5])
			}
			for i := first; i <= last; i++ {
				m.blocks = append(m.blocks, memBlock{index: i, count: 1, state: f[2], removable: f[3] == "1", node: node, zones: zones})
			}
		}
	}
	if m.blockSize == 0 {
		return nil, fmt.Errorf("lsmem: This system does not support memory blocks")
	}
	return m, nil
}

// LsmemOpts are lsmem's options.
type LsmemOpts struct {
	All, Bytes, NoHead, Raw, Pairs bool
	Cols                           []string
	ColsAdd                        bool
	Split                          []string // -S (nil: by the columns; ["NONE"]: none)
	Summary                        string   // "" default, never, always, only
	Version                        string   // ToolStyle.Lsipc's releases: "" 2.41, "2.39", "2.37", "2.32"
}

var lsmemCols = []struct {
	name  string
	hint  int
	right bool
}{{"RANGE", 0, false}, {"SIZE", 5, true}, {"STATE", 0, true}, {"REMOVABLE", 0, true}, {"BLOCK", 0, true},
	{"NODE", 0, true}, {"ZONES", 0, true}}

// LsmemColumn reports whether name is one of lsmem's columns.
func LsmemColumn(name string) bool {
	for _, c := range lsmemCols {
		if c.name == name {
			return true
		}
	}
	return false
}

var lsmemZones = map[string]bool{"dma": true, "dma32": true, "normal": true, "highmem": true, "movable": true, "device": true, "none": true}

// merged is read_info's merging: consecutive blocks whose split attributes
// are equal (an unknown zone never merges), each one alone with --all.
func (m *Lsmem) merged(o LsmemOpts, cols []string) ([]memBlock, uint64, uint64) {
	split := cols
	if o.Split != nil {
		split = o.Split
	}
	by := map[string]bool{}
	for _, c := range split {
		by[c] = true
	}
	var out []memBlock
	var online, offline uint64
	for _, b := range m.blocks {
		if b.state == "online" {
			online += m.blockSize
		} else {
			offline += m.blockSize
		}
		if n := len(out); n > 0 && !o.All {
			c := &out[n-1]
			ok := c.index+c.count == b.index
			ok = ok && !(by["STATE"] && c.state != b.state)
			ok = ok && !(by["REMOVABLE"] && c.removable != b.removable)
			ok = ok && !(by["NODE"] && m.haveNodes && c.node != b.node)
			if by["ZONES"] && m.haveZones {
				if len(c.zones) != len(b.zones) {
					ok = false
				}
				for i := 0; ok && i < len(c.zones); i++ {
					if !lsmemZones[strings.ToLower(c.zones[i])] || !strings.EqualFold(c.zones[i], b.zones[i]) {
						ok = false
					}
				}
			}
			if ok {
				c.count++
				continue
			}
		}
		out = append(out, b)
	}
	return out, online, offline
}

// zoneName is lsmem's zone_names entry for a valid_zones word.
func zoneName(z string) string {
	for _, n := range []string{"DMA", "DMA32", "Normal", "Highmem", "Movable", "Device", "None"} {
		if strings.EqualFold(z, n) {
			return n
		}
	}
	return "Unknown"
}

func (o LsmemOpts) cols() []string {
	cols := []string{"RANGE", "SIZE", "STATE", "REMOVABLE", "BLOCK"}
	if len(o.Cols) > 0 {
		if o.ColsAdd {
			return append(cols, o.Cols...)
		}
		return o.Cols
	}
	return cols
}

// LsmemRows is the table: each merged range's cells by column.
func LsmemRows(m *Lsmem, o LsmemOpts) ([]string, [][]string) {
	cols := o.cols()
	blocks, _, _ := m.merged(o, cols)
	empty := ""
	if o.Version == "2.32" {
		empty = "-"
	}
	var rows [][]string
	for _, b := range blocks {
		r := make([]string, len(cols))
		for i, c := range cols {
			switch c {
			case "RANGE":
				start := uint64(b.index) * m.blockSize
				size := uint64(b.count) * m.blockSize
				r[i] = fmt.Sprintf("0x%016x-0x%016x", start, start+size-1)
			case "SIZE":
				size := uint64(b.count) * m.blockSize
				if o.Bytes {
					r[i] = strconv.FormatUint(size, 10)
				} else {
					r[i] = utilHuman(int64(size))
				}
			case "STATE":
				r[i] = map[string]string{"online": "online", "offline": "offline", "going-offline": "on->off"}[b.state]
				if r[i] == "" {
					r[i] = "?"
				}
			case "REMOVABLE":
				r[i] = empty
				if b.state == "online" {
					r[i] = map[bool]string{true: "yes", false: "no"}[b.removable]
				}
			case "BLOCK":
				r[i] = strconv.Itoa(b.index)
				if b.count > 1 {
					r[i] = fmt.Sprintf("%d-%d", b.index, b.index+b.count-1)
				}
			case "NODE":
				r[i] = empty
				if m.haveNodes {
					r[i] = strconv.Itoa(b.node)
				}
			case "ZONES":
				r[i] = empty
				if m.haveZones {
					var z []string
					for _, x := range b.zones {
						z = append(z, zoneName(x))
					}
					r[i] = strings.Join(z, "/")
				}
			}
		}
		rows = append(rows, r)
	}
	return cols, rows
}

// PrintLsmem prints the table (libsmartcols, -r raw, -P pairs) and the
// summary as lsmem does.
func PrintLsmem(w io.Writer, m *Lsmem, o LsmemOpts) {
	table := o.Summary != "only"
	summary := o.Summary != "never" && !(o.Raw || o.Pairs) || o.Summary == "always" || o.Summary == "only"
	if table {
		cols, rows := LsmemRows(m, o)
		switch {
		case o.Pairs:
			for _, r := range rows {
				var p []string
				for i, c := range cols {
					p = append(p, fmt.Sprintf("%s=%q", c, r[i]))
				}
				fmt.Fprintln(w, strings.Join(p, " "))
			}
		default:
			hint := func(c string) (int, bool) {
				for _, x := range lsmemCols {
					if x.name == c {
						return x.hint, x.right
					}
				}
				return 0, false
			}
			width := make([]int, len(cols))
			for i, c := range cols {
				head := len(c)
				if o.NoHead && o.Version == "" { // before 2.41 the header still sets the width
					head = 1
				}
				data := 0
				for _, r := range rows {
					data = max(data, len(r[i]))
				}
				h, _ := hint(c)
				width[i] = scolsWidth(head, data, h)
			}
			line := func(cells []string) {
				var b strings.Builder
				for i, v := range cells {
					if o.Raw {
						if i > 0 {
							b.WriteByte(' ')
						}
						b.WriteString(strings.ReplaceAll(v, " ", `\x20`))
						continue
					}
					_, right := hint(cols[i])
					switch {
					case right:
						fmt.Fprintf(&b, "%*s", width[i], v)
					case i == len(cells)-1:
						b.WriteString(v)
					default:
						fmt.Fprintf(&b, "%-*s", width[i], v)
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
		if summary {
			fmt.Fprintln(w)
		}
	}
	if summary {
		_, on, off := m.merged(o, o.cols())
		wd := 32
		if o.Version != "" {
			wd = 23
		}
		for _, l := range []struct {
			name string
			v    uint64
		}{{"Memory block size:", m.blockSize}, {"Total online memory:", on}, {"Total offline memory:", off}} {
			if o.Bytes {
				fmt.Fprintf(w, "%-*s %15d\n", wd, l.name, l.v)
			} else {
				fmt.Fprintf(w, "%-*s %5s\n", wd, l.name, utilHuman(int64(l.v)))
			}
		}
	}
}
