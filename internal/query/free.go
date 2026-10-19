package query

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// FreeRow is what `free` (procps-ng 4) prints for one sample, in KiB.
type FreeRow struct {
	TS        int64 `json:"ts_ms"`
	Total     int64 `json:"mem_total_kb"`
	Used      int64 `json:"mem_used_kb"` // total - available
	Free      int64 `json:"mem_free_kb"`
	Shared    int64 `json:"shared_kb"`
	Buffers   int64 `json:"buffers_kb"`
	Cache     int64 `json:"cache_kb"` // Cached + SReclaimable
	Available int64 `json:"available_kb"`
	SwapTotal int64 `json:"swap_total_kb"`
	SwapUsed  int64 `json:"swap_used_kb"`
	SwapFree  int64 `json:"swap_free_kb"`
}

// Free reads the memory counters at the end of each span (the sample itself:
// free reports the moment, not a difference).
func Free(db *store.DB, spans []Span) ([]FreeRow, error) {
	var out []FreeRow
	for _, sp := range spans {
		s, err := loadSys(db, sp.To)
		if err != nil {
			return nil, err
		}
		r := FreeRow{TS: s.TS, Total: s.MemTotal, Free: s.MemFree, Shared: s.Shmem, Buffers: s.Buffers,
			Cache: s.Cached + s.SReclaimable, Available: s.MemAvailable,
			SwapTotal: s.SwapTotal, SwapFree: s.SwapFree, SwapUsed: s.SwapTotal - s.SwapFree}
		r.Used = r.Total - r.Available
		if r.Available > r.Total {
			r.Used = r.Total - r.Free
		}
		out = append(out, r)
	}
	return out, nil
}

// FreeFormat holds free's output options.
type FreeFormat struct {
	Unit  string // b, k (default), m, g, h
	Wide  bool   // -w: buffers and cache in separate columns
	Total bool   // -t: a Total line
}

func (f FreeFormat) value(kb int64) string {
	switch f.Unit {
	case "b":
		return strconv.FormatInt(kb*1024, 10)
	case "m":
		return strconv.FormatInt(kb/1024, 10)
	case "g":
		return strconv.FormatInt(kb/1024/1024, 10)
	case "h":
		return humanSize(kb * 1024)
	}
	return strconv.FormatInt(kb, 10)
}

// humanSize is procps's -h: the first unit in which the value fits in four
// characters ("999B") or five with an "i" unit ("9.1Gi", "42Gi"), one
// decimal (rounded) when it fits, else whole units (truncated).
func humanSize(bytes int64) string {
	if s := strconv.FormatInt(bytes, 10) + "B"; len(s) <= 4 {
		return s
	}
	v := float64(bytes)
	for _, u := range []string{"Ki", "Mi", "Gi", "Ti", "Pi", "Ei"} {
		v /= 1024
		if s := strconv.FormatFloat(v, 'f', 1, 64) + u; len(s) <= 5 {
			return s
		}
		if s := strconv.FormatInt(int64(v), 10) + u; len(s) <= 5 {
			return s
		}
	}
	return strconv.FormatInt(bytes, 10) + "B"
}

// PrintFree prints the rows like free, a blank line between samples (free -s).
func PrintFree(w io.Writer, rows []FreeRow, f FreeFormat) {
	cols := []string{"total", "used", "free", "shared", "buff/cache", "available"}
	if f.Wide {
		cols = []string{"total", "used", "free", "shared", "buffers", "cache", "available"}
	}
	line := func(label string, vals ...string) {
		var b strings.Builder
		fmt.Fprintf(&b, "%-8s", label)
		for _, v := range vals {
			fmt.Fprintf(&b, " %11s", v)
		}
		fmt.Fprintln(w, b.String())
	}
	for i, r := range rows {
		if i > 0 {
			fmt.Fprintln(w)
		}
		line("", cols...)
		mem := []string{f.value(r.Total), f.value(r.Used), f.value(r.Free), f.value(r.Shared)}
		if f.Wide {
			mem = append(mem, f.value(r.Buffers), f.value(r.Cache))
		} else {
			mem = append(mem, f.value(r.Buffers+r.Cache))
		}
		line("Mem:", append(mem, f.value(r.Available))...)
		line("Swap:", f.value(r.SwapTotal), f.value(r.SwapUsed), f.value(r.SwapFree))
		if f.Total {
			line("Total:", f.value(r.Total+r.SwapTotal), f.value(r.Used+r.SwapUsed), f.value(r.Free+r.SwapFree))
		}
	}
}
