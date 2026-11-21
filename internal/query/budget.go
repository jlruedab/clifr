package query

import (
	"cmp"
	"database/sql"
	"fmt"
	"math"
	"strings"

	"clifr/internal/store"
)

// BudgetShed reports the events_shed guard events (clifrd's event budget)
// of kind ("processes" or "tcp") that cover from..to (0, 0: the whole
// recording): how many, the first and last. Each one is written at the
// sample after the events it counts, so one up to a minute after to still
// covers it.
func BudgetShed(db *store.DB, from, to int64, kind string) (n int, first, last int64) {
	if to == 0 {
		to = math.MaxInt64 - 60_000
	}
	rows, err := db.Query(`SELECT ts, detail FROM guard_events WHERE kind = 'events_shed' AND ts >= ? AND ts <= ? ORDER BY ts`,
		from, to+60_000)
	if err != nil {
		return 0, 0, 0
	}
	defer rows.Close()
	for rows.Next() {
		var ts int64
		var detail string
		if rows.Scan(&ts, &detail) != nil || !strings.HasPrefix(detail, kind+":") {
			continue
		}
		if n == 0 {
			first = ts
		}
		n, last = n+1, ts
	}
	return n, first, last
}

// BudgetNote is the header line for a list that BudgetShed says is
// incomplete ("" when it is complete).
func BudgetNote(db *store.DB, from, to int64, kind string) string {
	n, first, last := BudgetShed(db, from, to, kind)
	if n == 0 {
		return ""
	}
	what := "process events (fork, exec) above clifrd's event budget were recorded without command lines or only counted"
	if kind == "tcp" {
		what = "new TCP connections above clifrd's event budget were only counted"
	}
	return "incomplete: " + what + " (" + FormatMS(first) + " .. " + FormatMS(last) + "; clifr events --type guard says how many and from whom)"
}

// TCPLoss reports TCP events lost (the kernel's buffer or clifrd's queue
// was full; not the budget's shedding) that can make the TCP view of
// from..to wrong: a lost close leaves a connection open until a keyframe
// finds it gone. Losses count from the last keyframe at or before from (it
// repaired the earlier ones) to the sample after to. lostFrom..lostTo is
// when they happened (from the sample before the first count), kf the
// keyframe after them (0: none recorded).
func TCPLoss(db *store.DB, from, to int64) (n, lostFrom, lostTo, kf int64) {
	var k0 sql.NullInt64
	db.QueryRow(`SELECT max(ts) FROM reconcile WHERE ts <= ?`, from).Scan(&k0)
	rows, err := db.Query(`
		WITH lost AS (
			SELECT ts, dropped AS n FROM recorder_stats
			WHERE dropped > 0 AND starts_with(source, 'tcp_') AND source <> 'tcp_missed_runs'
			UNION ALL
			SELECT ts, TRY_CAST(regexp_extract(detail, '(\d+) TCP events dropped', 1) AS BIGINT) FROM guard_events
			WHERE kind = 'events_lost' AND starts_with(detail, 'TCP ')
		)
		SELECT l.ts, sum(l.n), (SELECT max(s.ts) FROM samples s WHERE s.ts < l.ts)
		FROM lost l WHERE l.ts > ? GROUP BY l.ts ORDER BY l.ts`, k0.Int64)
	if err != nil {
		return 0, 0, 0, 0
	}
	defer rows.Close()
	for rows.Next() {
		var ts, c int64
		var prev sql.NullInt64
		if rows.Scan(&ts, &c, &prev) != nil || prev.Valid && prev.Int64 >= to {
			continue
		}
		if n == 0 {
			lostFrom = cmp.Or(prev.Int64, ts)
		}
		n, lostTo = n+c, ts
	}
	if n > 0 {
		var k sql.NullInt64
		db.QueryRow(`SELECT min(ts) FROM reconcile WHERE ts >= ?`, lostFrom+1).Scan(&k)
		kf = k.Int64
	}
	return n, lostFrom, lostTo, kf
}

// TCPLossNote is the header line for a TCP view that TCPLoss says may show
// closed connections as open ("" when no loss applies).
func TCPLossNote(db *store.DB, from, to int64) string {
	n, a, b, kf := TCPLoss(db, from, to)
	if n == 0 {
		return ""
	}
	until := "the end of the recording (no keyframe after them)"
	if kf != 0 {
		until = "the keyframe at " + FormatMS(kf)
	}
	return fmt.Sprintf("incomplete: %d TCP events lost between %s and %s (the kernel's event buffer was full): "+
		"connections that closed then may show as still open until %s", n, FormatMS(a), FormatMS(b), until)
}
