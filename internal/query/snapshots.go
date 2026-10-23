package query

import (
	"database/sql"

	"clifr/internal/store"
)

// FileAt returns the lines of a snapshot source (procfs.SnapSources) as
// they were at t: the last full copy at or before t with the lines that
// changed after it. ts is that of the newest row used; ok is false when the
// source was not recorded by then (recordings before schema 9, or more than
// store.NetCountersFullMS before the loaded window).
func FileAt(db *store.DB, source string, t int64) (lines []string, ts int64, ok bool, err error) {
	var full sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM snapshots WHERE source = ? AND whole = 1 AND ts <= ?`, source, t).Scan(&full); err != nil || !full.Valid {
		return nil, 0, false, err
	}
	rows, err := db.Query(`SELECT ts, key, pos, whole, line FROM snapshots
		WHERE source = ? AND ts >= ? AND ts <= ? AND (whole = 0 OR ts = ?) ORDER BY ts, pos`, source, full.Int64, t, full.Int64)
	if err != nil {
		return nil, 0, false, err
	}
	defer rows.Close()
	pos := map[string]int{}
	for rows.Next() {
		var key, line string
		var rts int64
		var p, f int
		if err := rows.Scan(&rts, &key, &p, &f, &line); err != nil {
			return nil, 0, false, err
		}
		ts = rts
		if p < 0 {
			continue // a full copy of an empty file
		}
		if f == 1 {
			pos[key] = len(lines)
			lines = append(lines, line)
		} else if i, ok := pos[key]; ok {
			lines[i] = line
		}
	}
	return lines, ts, true, rows.Err()
}

// HostnameAt is the host name at t: as last read at a system sample (since
// schema 9, so a change while clifrd runs is seen), else as the run
// covering t recorded it when it started.
func HostnameAt(db *store.DB, t int64) string {
	if l, _, ok, err := FileAt(db, "hostname", t); err == nil && ok && len(l) == 1 {
		return l[0]
	}
	return MetaAt(db, "hostname", t)
}
