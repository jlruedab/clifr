package query

import (
	"database/sql"
	"fmt"
	"strings"

	"clifr/internal/store"
)

// BalloonChange is a memory balloon inflating or deflating (the hypervisor
// taking memory from the guest or giving it back), or the guest's memory
// total changing, over consecutive system samples: one change per run of
// samples that each differ from the one before in the same way.
type BalloonChange struct {
	TS    int64 `json:"ts_ms"`     // the first sample that shows it
	EndTS int64 `json:"end_ts_ms"` // the last
	// DeltaKB: how much went into the balloon (negative: came out);
	// BalloonKB: its size after (-1: this kernel does not report it).
	DeltaKB   int64 `json:"delta_kb"`
	BalloonKB int64 `json:"balloon_kb"`
	// TotalDeltaKB, TotalKB: MemTotal's change and value after. Virtio
	// without deflate-on-oom, Hyper-V and Xen take ballooned pages out of
	// the total; VMware and virtio with deflate-on-oom leave it (the pages
	// look used); memory hotplug changes it too.
	TotalDeltaKB int64 `json:"mem_total_delta_kb"`
	TotalKB      int64 `json:"mem_total_kb"`
}

// balloonKB is the balloon's size at a sample: nr_balloon_pages (Linux
// 6.14+: virtio, VMware, Hyper-V, Xen), else the pages put in minus those
// taken out since boot (virtio, VMware); invalid before schema 16.
func balloonKB(pages, inflate, deflate sql.NullInt64, pageKB int64) (kb int64, known bool) {
	switch {
	case pages.Valid && pages.Int64 >= 0:
		return pages.Int64 * pageKB, true
	case inflate.Valid && deflate.Valid:
		return (inflate.Int64 - deflate.Int64) * pageKB, true
	}
	return 0, false
}

// BalloonChanges lists the balloon's and MemTotal's changes in [from, to],
// each against the sample before it (a boot starts over: the counters are
// since boot). Recordings before schema 16 have only MemTotal.
func BalloonChanges(db *store.DB, from, to int64) ([]BalloonChange, error) {
	pageKB := metaInt(db, "page_kb")
	if pageKB <= 0 {
		pageKB = 4
	}
	cols := "balloon_pages, balloon_inflate, balloon_deflate"
	if !hasColumn(db, "sys_samples", "balloon_pages") {
		cols = "NULL, NULL, NULL" // recorded before schema 16
	}
	rows, err := db.Query(`SELECT ts, uptime_ms, mem_total, `+cols+` FROM sys_samples
		WHERE ts >= COALESCE((SELECT max(ts) FROM sys_samples WHERE ts < ?), ?) AND ts <= ?
		ORDER BY ts`, from, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BalloonChange
	var cur *BalloonChange
	var prevTS, prevUp, prevTotal, prevBal int64
	prevKnown, have := false, false
	for rows.Next() {
		var ts, up, total int64
		var pages, inflate, deflate sql.NullInt64
		if err := rows.Scan(&ts, &up, &total, &pages, &inflate, &deflate); err != nil {
			return nil, err
		}
		bal, known := balloonKB(pages, inflate, deflate, pageKB)
		if have && up >= prevUp && ts >= from { // the same boot
			dBal := int64(0)
			if known && prevKnown {
				dBal = bal - prevBal
			}
			dTotal := total - prevTotal
			if dBal != 0 || dTotal != 0 {
				// One change: consecutive samples moving the same way
				// (inflating, deflating, or only MemTotal).
				if cur == nil || cur.EndTS != prevTS || sign(cur.DeltaKB) != sign(dBal) {
					out = append(out, BalloonChange{TS: ts})
					cur = &out[len(out)-1]
				}
				cur.EndTS, cur.DeltaKB, cur.TotalDeltaKB = ts, cur.DeltaKB+dBal, cur.TotalDeltaKB+dTotal
				cur.TotalKB, cur.BalloonKB = total, -1
				if known {
					cur.BalloonKB = bal
				}
			}
		}
		prevTS, prevUp, prevTotal, prevBal, prevKnown, have = ts, up, total, bal, known, true
	}
	return out, rows.Err()
}

// BalloonText describes a change in a line: "balloon inflated by 2.0 GiB
// (the hypervisor took it back; 2.0 GiB in the balloon, MemTotal 6.0 GiB)".
func BalloonText(c BalloonChange) string {
	var b strings.Builder
	switch {
	case c.DeltaKB > 0:
		fmt.Fprintf(&b, "memory balloon inflated by %s (the hypervisor took it", SizeKB(c.DeltaKB))
	case c.DeltaKB < 0:
		fmt.Fprintf(&b, "memory balloon deflated by %s (the hypervisor gave it back", SizeKB(-c.DeltaKB))
	default:
		sign := "+"
		if c.TotalDeltaKB < 0 {
			sign = "-"
		}
		return fmt.Sprintf("MemTotal changed by %s%s to %s (memory hotplug, or a balloon this kernel does not count)",
			sign, SizeKB(abs64(c.TotalDeltaKB)), SizeKB(c.TotalKB))
	}
	switch {
	case c.BalloonKB > 0:
		fmt.Fprintf(&b, "; %s in the balloon", SizeKB(c.BalloonKB))
	case c.BalloonKB == 0:
		b.WriteString("; the balloon is empty")
	}
	if c.TotalDeltaKB != 0 {
		fmt.Fprintf(&b, "; MemTotal %s", SizeKB(c.TotalKB))
	}
	b.WriteString(")")
	return b.String()
}

// BalloonNote is a header line for free and vmstat over [from, to] (from ==
// to: a moment): the balloon's changes, or its size when it holds memory;
// "" when there is no balloon or it is empty.
func BalloonNote(db *store.DB, from, to int64) string {
	ch, err := BalloonChanges(db, from, to)
	if err != nil {
		return ""
	}
	if len(ch) > 0 && from < to {
		var parts []string
		for i, c := range ch {
			if i == 3 {
				parts = append(parts, fmt.Sprintf("%d more", len(ch)-3))
				break
			}
			parts = append(parts, FormatMS(c.TS)+" "+strings.TrimPrefix(BalloonText(c), "memory balloon "))
		}
		return "memory balloon: " + strings.Join(parts, "; ")
	}
	if !hasColumn(db, "sys_samples", "balloon_pages") {
		return ""
	}
	var pages, inflate, deflate sql.NullInt64
	if db.QueryRow(`SELECT balloon_pages, balloon_inflate, balloon_deflate FROM sys_samples
		WHERE ts <= ? ORDER BY ts DESC LIMIT 1`, to).Scan(&pages, &inflate, &deflate) != nil {
		return ""
	}
	pageKB := metaInt(db, "page_kb")
	if pageKB <= 0 {
		pageKB = 4
	}
	if kb, known := balloonKB(pages, inflate, deflate, pageKB); known && kb > 0 {
		return fmt.Sprintf("memory balloon: %s held by the hypervisor (not available to this machine: shown as used, or left out of the total, depending on the driver)", SizeKB(kb))
	}
	return ""
}

// SizeKB is a size in KiB as "2.0 GiB", "512 MiB" or "64 KiB".
func SizeKB(kb int64) string {
	switch {
	case kb >= 1<<20:
		return fmt.Sprintf("%.1f GiB", float64(kb)/(1<<20))
	case kb >= 1<<10:
		return fmt.Sprintf("%d MiB", kb>>10)
	}
	return fmt.Sprintf("%d KiB", kb)
}

func sign(n int64) int {
	switch {
	case n > 0:
		return 1
	case n < 0:
		return -1
	}
	return 0
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// hasColumn: table has column (a window recorded only by an older clifrd
// lacks the newer columns: the tables are made from the files).
func hasColumn(db *store.DB, table, column string) bool {
	rows, err := db.Query(`SELECT ` + column + ` FROM ` + table + ` LIMIT 0`)
	if err != nil {
		return false
	}
	rows.Close()
	return true
}
