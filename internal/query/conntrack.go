// Parts of this file follow conntrack-tools' src/conntrack.c (GPL-2.0-or-later): its counter names, used under the
// GPL-3.0: see LICENSING.md and packaging/notices/conntrack-tools.txt.

package query

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// ConntrackCPU is one CPU's connection tracking counters: CTA_STATS_*
// attribute numbers and values in ctnetlink's order.
type ConntrackCPU struct {
	CPU   int         `json:"cpu"`
	Attrs [][2]uint64 `json:"attrs"`
}

// ConntrackAt returns the counters as clifrd last asked ctnetlink at or
// before t (every minute; none when nf_conntrack_netlink was not loaded).
func ConntrackAt(db *store.DB, t int64) ([]ConntrackCPU, error) {
	lines, _, ok, err := FileAt(db, "conntrack", t)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("conntrack: not recorded at %s (recorded since schema 9)", FormatMS(t))
	}
	var out []ConntrackCPU
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		c := ConntrackCPU{}
		c.CPU, _ = strconv.Atoi(f[0])
		for _, kv := range f[1:] {
			k, v, _ := strings.Cut(kv, "=")
			a, _ := strconv.ParseUint(k, 10, 64)
			b, _ := strconv.ParseUint(v, 10, 64)
			c.Attrs = append(c.Attrs, [2]uint64{a, b})
		}
		out = append(out, c)
	}
	return out, nil
}

// conntrackNames are conntrack-tools' names for CTA_STATS_*; 1.4.7 and
// later name four numbers past the last one "unknownN". Older versions name
// up to search_restart (13) and print clash_resolve and chaintoolong, which
// their headers know, as "(null)" (glibc's printf of a NULL name).
var conntrackNames = []string{1: "searched", 2: "found", 3: "new", 4: "invalid", 5: "ignore", 6: "delete", 7: "delete_list",
	8: "insert", 9: "insert_failed", 10: "drop", 11: "early_drop", 12: "error", 13: "search_restart", 14: "clash_resolve",
	15: "chaintoolong"}

// PrintConntrackStats prints conntrack -S. old: conntrack-tools before
// 1.4.7.
func PrintConntrackStats(w io.Writer, cpus []ConntrackCPU, old bool) {
	for _, c := range cpus {
		var b strings.Builder
		fmt.Fprintf(&b, "cpu=%-4d\t", c.CPU)
		vals := map[uint64]uint64{}
		for _, a := range c.Attrs {
			vals[a[0]] = a[1]
		}
		last := uint64(len(conntrackNames) - 1 + 4)
		if old {
			last = 15
		}
		for i := uint64(1); i <= last; i++ {
			v, ok := vals[i]
			if !ok {
				continue
			}
			name := "unknown" + strconv.FormatUint(i-uint64(len(conntrackNames)-1), 10)
			switch {
			case old && i > 13:
				name = "(null)"
			case i < uint64(len(conntrackNames)):
				name = conntrackNames[i]
			}
			fmt.Fprintf(&b, "%s=%d ", name, v)
		}
		fmt.Fprintln(w, b.String())
	}
}
