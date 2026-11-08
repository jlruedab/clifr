package query

import (
	"database/sql"

	"clifr/internal/store"
)

// EndMS is the recording's last sample on disk (0: none). clifrd keeps newer
// samples in memory until its next flush (every 5 minutes by default).
func EndMS(db *store.DB) int64 {
	var v sql.NullInt64
	db.QueryRow(`SELECT max(ts) FROM samples`).Scan(&v)
	return v.Int64
}

// RecordingHeaders prints which host a recording is of (local and bundle
// queries; --host prints its own "remote:" line), as of t (a range: its
// end), and for a range that ends after the recording does a warning: the
// answer stops at the recording's end (the user, 2026-11-08: an agent must
// not take minutes-old data for the moment of an alert). A moment (--at)
// after the end is an error already (Covered); the same threshold applies.
func RecordingHeaders(db *store.DB, w Window, remote bool) {
	t := w.At
	if w.IsRange() {
		t = w.To
	}
	if !remote {
		name, id := HostnameAt(db, t), MetaAt(db, "machine_id", t)
		if name == "" { // no run's meta at or after t: the newest run's, as clifr info
			name = db.Meta("hostname")
		}
		if id == "" {
			id = db.Meta("machine_id")
		}
		if name == "" {
			name = "unknown host"
		}
		if id != "" {
			Header("host: %s (machine-id %.8s)", name, id)
		} else {
			Header("host: %s", name)
		}
	}
	if !w.IsRange() || w.From == 0 { // a moment, or the whole recording
		return
	}
	end := EndMS(db)
	if end == 0 || end < w.From || w.To-end <= IntervalMS(db)*5/2 {
		return
	}
	Header("warning: the recording ends at %s, %s before the end of the range (%s): nothing later is in this answer. "+
		"clifrd writes to disk %s, so the latest minutes may not be there yet, or it was not running",
		FormatMS(end), fmtDur(w.To-end), FormatMS(w.To), flushEvery(db))
}
