package query

import (
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
