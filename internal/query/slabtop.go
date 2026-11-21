// Parts of this file follow procps-ng 3.3's slabtop.c and proc/slab.c (LGPL-2.1-or-later), used under the
// GPL-3.0: see LICENSING.md and packaging/notices/procps.txt.

package query

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// Slab is one cache of /proc/slabinfo.
type Slab struct {
	Name                      string `json:"name"`
	ActiveObjs, Objs, ObjSize uint32
	ObjsPerSlab, PagesPerSlab uint32
	ActiveSlabs, Slabs        uint32
	Use                       uint32 `json:"use"`
	CacheSize                 uint64 `json:"cache_size"`
}

// SlabsAt returns /proc/slabinfo's caches as clifrd last read it at or
// before t (every minute), in the file's order, and the page size.
func SlabsAt(db *store.DB, t int64) ([]Slab, int64, error) {
	lines, _, ok, err := FileAt(db, "slabinfo", t)
	if err != nil {
		return nil, 0, err
	}
	if !ok {
		return nil, 0, fmt.Errorf("slabtop: slabinfo not recorded at %s (recorded since schema 9)", FormatMS(t))
	}
	page := PageBytes(db)
	var out []Slab
	for _, l := range lines {
		if strings.HasPrefix(l, "#") || strings.HasPrefix(l, "slabinfo ") {
			continue
		}
		// name active_objs num_objs objsize objperslab pagesperslab : tunables ... : slabdata active_slabs num_slabs ...
		f := strings.Fields(l)
		if len(f) < 16 {
			continue
		}
		n := func(i int) uint32 { v, _ := strconv.ParseUint(f[i], 10, 32); return uint32(v) }
		s := Slab{Name: f[0], ActiveObjs: n(1), Objs: n(2), ObjSize: n(3), ObjsPerSlab: n(4), PagesPerSlab: n(5),
			ActiveSlabs: n(13), Slabs: n(14)}
		s.CacheSize = uint64(s.Slabs) * uint64(s.PagesPerSlab) * uint64(page)
		out = append(out, s)
	}
	return out, page, nil
}

// slabUse is the USE column: procps 3.3 computes 100 * (float)a / b,
// 4.0 100 * ((float)a / b), both in single precision and truncated, which
// can differ by one.
func slabUse(active, objs uint32, v3 bool) uint32 {
	if objs == 0 {
		return 0
	}
	if v3 {
		return uint32(float32(100) * float32(active) / float32(objs))
	}
	return uint32(float32(100) * (float32(active) / float32(objs)))
}

// slabSort3 is procps 3.3's merge sort of the cache list by number of
// objects, descending: of two equal caches the one from the later half
// comes first.
func slabSort3(l []Slab) []Slab {
	if len(l) < 2 {
		return l
	}
	s, f := 0, 1
	for f < len(l) && f+1 < len(l) {
		s, f = s+1, f+2
	}
	a, b := slabSort3(append([]Slab(nil), l[:s+1]...)), slabSort3(append([]Slab(nil), l[s+1:]...))
	out := make([]Slab, 0, len(l))
	for len(a) > 0 && len(b) > 0 {
		if a[0].Objs > b[0].Objs {
			out, a = append(out, a[0]), a[1:]
		} else {
			out, b = append(out, b[0]), b[1:]
		}
	}
	return append(append(out, a...), b...)
}

// PrintSlabtop prints slabtop -o: the summary, then every cache by number
// of objects (procps 3.3's sort and USE with v3, else 4.0's).
func PrintSlabtop(w io.Writer, slabs []Slab, v3 bool) {
	var objs, active, sl, asl, caches, acaches uint32
	var total, activeSize uint64
	minSize, maxSize := uint32(1<<31-1), uint32(0)
	for i := range slabs {
		s := &slabs[i]
		s.Use = slabUse(s.ActiveObjs, s.Objs, v3)
		minSize, maxSize = min(minSize, s.ObjSize), max(maxSize, s.ObjSize)
		if s.Objs != 0 {
			acaches++
		}
		caches++
		objs += s.Objs
		active += s.ActiveObjs
		total += uint64(s.Objs) * uint64(s.ObjSize)
		activeSize += uint64(s.ActiveObjs) * uint64(s.ObjSize)
		sl += s.Slabs
		asl += s.ActiveSlabs
	}
	var avg uint32
	if objs != 0 {
		avg = uint32(total / uint64(objs))
	}
	pct := func(a, b float64) float64 { return 100.0 * a / b }
	fmt.Fprintf(w, " %-35s: %d / %d (%.1f%%)\n", "Active / Total Objects (% used)", active, objs, pct(float64(active), float64(objs)))
	fmt.Fprintf(w, " %-35s: %d / %d (%.1f%%)\n", "Active / Total Slabs (% used)", asl, sl, pct(float64(asl), float64(sl)))
	fmt.Fprintf(w, " %-35s: %d / %d (%.1f%%)\n", "Active / Total Caches (% used)", acaches, caches, pct(float64(acaches), float64(caches)))
	fmt.Fprintf(w, " %-35s: %.2fK / %.2fK (%.1f%%)\n", "Active / Total Size (% used)", float64(activeSize)/1024, float64(total)/1024,
		pct(float64(activeSize), float64(total)))
	fmt.Fprintf(w, " %-35s: %.2fK / %.2fK / %.2fK\n\n", "Minimum / Average / Maximum Object", float64(minSize)/1024,
		float64(avg)/1024, float64(maxSize)/1024)
	sorted := append([]Slab(nil), slabs...)
	if v3 {
		sorted = slabSort3(sorted)
	} else {
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Objs > sorted[j].Objs })
	}
	fmt.Fprintf(w, "%-78s\n", "  OBJS ACTIVE  USE OBJ SIZE  SLABS OBJ/SLAB CACHE SIZE NAME")
	for _, s := range sorted {
		fmt.Fprintf(w, "%6d %6d %3d%% %7.2fK %6d %8d %9dK %-23s\n", s.Objs, s.ActiveObjs, s.Use, float64(s.ObjSize)/1024,
			s.Slabs, s.ObjsPerSlab, s.CacheSize/1024, s.Name)
	}
}
