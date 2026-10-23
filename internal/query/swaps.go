package query

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// Swap is one swap area of /proc/swaps.
type Swap struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	SizeKB   int64  `json:"size_kb"`
	UsedKB   int64  `json:"used_kb"`
	Priority int    `json:"priority"`
}

// SwapsAt returns the swap areas at t and /proc/swaps as it was (swapon
// --summary prints it).
func SwapsAt(db *store.DB, t int64) ([]Swap, []string, error) {
	lines, _, ok, err := FileAt(db, "swaps", t)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, fmt.Errorf("swapon: swap areas not recorded at %s (recorded since schema 9)", FormatMS(t))
	}
	var out []Swap
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 5 || f[0] == "Filename" {
			continue
		}
		s := Swap{Name: procfs.UnescapeOctal(f[0]), Type: f[1]}
		s.SizeKB, _ = strconv.ParseInt(f[2], 10, 64)
		s.UsedKB, _ = strconv.ParseInt(f[3], 10, 64)
		s.Priority, _ = strconv.Atoi(f[4])
		out = append(out, s)
	}
	return out, lines, nil
}

// PrintSwapSummary prints swapon --summary: /proc/swaps as it was, or
// nothing at all (not even the header) without swap areas; util-linux
// 2.32 (own) prints the areas in its own columns.
func PrintSwapSummary(w io.Writer, swaps []Swap, raw []string, own bool) {
	if len(swaps) == 0 {
		return
	}
	if own {
		fmt.Fprintf(w, "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n")
		for _, s := range swaps {
			fmt.Fprintf(w, "%-39s\t%-8s\t%d\t%d\t%d\n", s.Name, s.Type, s.SizeKB, s.UsedKB, s.Priority)
		}
		return
	}
	for _, l := range raw {
		fmt.Fprintln(w, l)
	}
}

// SwapColumns are swapon --show's columns clifr knows (UUID and LABEL are
// not recorded), the first five being the default.
var SwapColumns = []string{"NAME", "TYPE", "SIZE", "USED", "PRIO"}

// PrintSwapon prints swapon --show as util-linux does (libsmartcols): no
// output at all without swap areas, columns one space apart, SIZE, USED
// and PRIO right-aligned, the last column not padded.
func PrintSwapon(w io.Writer, swaps []Swap, cols []string, bytes, noHeadings, raw bool) {
	if len(swaps) == 0 {
		return
	}
	size := func(kb int64) string {
		if bytes {
			return strconv.FormatInt(kb*1024, 10)
		}
		return utilHuman(kb * 1024)
	}
	var rows [][]string
	if !noHeadings {
		rows = append(rows, cols)
	}
	for _, s := range swaps {
		var r []string
		for _, c := range cols {
			switch c {
			case "NAME":
				r = append(r, s.Name)
			case "TYPE":
				r = append(r, s.Type)
			case "SIZE":
				r = append(r, size(s.SizeKB))
			case "USED":
				r = append(r, size(s.UsedKB))
			case "PRIO":
				r = append(r, strconv.Itoa(s.Priority))
			}
		}
		rows = append(rows, r)
	}
	right := map[string]bool{"SIZE": true, "USED": true, "PRIO": true}
	printScols(w, rows, func(i int) bool { return right[cols[i]] }, raw)
}

// printScols prints a libsmartcols table without a terminal: columns one
// space apart and as wide as their widest cell, right-aligned where right
// says, the last column not padded unless right-aligned. Raw: one space
// between cells, no alignment, spaces escaped as \x20.
func printScols(w io.Writer, rows [][]string, right func(int) bool, raw bool) {
	width := map[int]int{}
	for _, r := range rows {
		for i, c := range r {
			width[i] = max(width[i], len(c))
		}
	}
	for _, r := range rows {
		var b strings.Builder
		for i, c := range r {
			if i > 0 {
				b.WriteByte(' ')
			}
			switch {
			case raw:
				b.WriteString(strings.ReplaceAll(c, " ", `\x20`))
			case right(i):
				fmt.Fprintf(&b, "%*s", width[i], c)
			case i == len(r)-1:
				b.WriteString(c)
			default:
				fmt.Fprintf(&b, "%-*s", width[i], c)
			}
		}
		fmt.Fprintln(w, b.String())
	}
}

// utilHuman is util-linux's size_to_human_string with a one-letter suffix
// ("8G", "1.1M", "512B"): the largest power of 1024 below the value, one
// decimal rounded from three digits, a trailing zero dropped.
func utilHuman(bytes int64) string {
	n := uint64(bytes)
	exp := 0
	for exp = 10; exp <= 60; exp += 10 {
		if n < 1<<exp {
			break
		}
	}
	exp -= 10
	letter := "BKMGTPE"[exp/10]
	dec, frac := n, uint64(0)
	if exp > 0 {
		dec, frac = n>>exp, n&(1<<exp-1)
	}
	if frac > 0 {
		if frac >= (1<<64-1)/1000 {
			frac = frac / 1024 * 1000 / (1 << (exp - 10))
		} else {
			frac = frac * 1000 / (1 << exp)
		}
		frac = (frac + 50) / 100 * 10
		if frac == 100 {
			dec++
			frac = 0
		}
	}
	if frac == 0 {
		return fmt.Sprintf("%d%c", dec, letter)
	}
	s := fmt.Sprintf("%d.%02d", dec, frac)
	return strings.TrimSuffix(s, "0") + string(letter)
}
