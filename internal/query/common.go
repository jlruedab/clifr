// Package query reconstructs ps/lsof/ss/life output from a clifr database.
package query

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"time"

	"clifr/internal/store"
)

const TimeLayout = "2006-01-02 15:04:05"

// open is the "last_seen" value used for rows that are still open.
const openEnd = int64(1) << 62

// ParseTime parses a CLI time in local time and returns unix ms.
func ParseTime(s string) (int64, error) {
	t, err := time.ParseInLocation(TimeLayout, s, time.Local)
	if err != nil {
		return 0, fmt.Errorf("bad time %q, want \"YYYY-MM-DD HH:MM:SS\"", s)
	}
	return t.UnixMilli(), nil
}

func FormatMS(ms int64) string {
	if ms == 0 {
		return "-"
	}
	return time.UnixMilli(ms).Format(TimeLayout)
}

// Window is either a point in time (At) or a range (From..To).
type Window struct {
	At, From, To int64
}

func (w Window) IsRange() bool { return w.At == 0 }

// SnapshotAt returns the latest recorded (non-skipped) sample at or before t.
// If fdWalk is set, only samples that included a full open-file walk count.
func SnapshotAt(db *store.DB, t int64, fdWalk bool) (int64, error) {
	q := `SELECT MAX(ts) FROM samples WHERE skipped = 0 AND ts <= ?`
	if fdWalk {
		q += ` AND fd_walk = 1`
	}
	var s sql.NullInt64
	if err := db.QueryRow(q, t).Scan(&s); err != nil {
		return 0, err
	}
	if !s.Valid {
		var first sql.NullInt64
		db.QueryRow(`SELECT MIN(ts) FROM samples WHERE skipped = 0`).Scan(&first)
		if first.Valid {
			return 0, fmt.Errorf("no recorded sample at or before %s (recording starts %s)", FormatMS(t), FormatMS(first.Int64))
		}
		return 0, fmt.Errorf("database has no samples")
	}
	return s.Int64, nil
}

// Header prints an informational line to stderr.
func Header(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "# "+format+"\n", args...)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

var userCache = map[int]string{}

// UserName resolves a uid the way ps does: names longer than 8 characters
// are cut to 7 plus '+'.
func UserName(uid int, truncate bool) string {
	name, ok := userCache[uid]
	if !ok {
		name = strconv.Itoa(uid)
		if u, err := user.LookupId(name); err == nil {
			name = u.Username
		}
		userCache[uid] = name
	}
	if truncate && len(name) > 8 {
		return name[:7] + "+"
	}
	return name
}

func metaInt(db *store.DB, key string) int64 {
	n, _ := strconv.ParseInt(db.Meta(key), 10, 64)
	return n
}

// IntervalMS is the recorder's sample interval from the metadata (30 s if
// unknown).
// Covered returns an error when the recording has nothing for the moment t:
// t is after its last sample (the recorder stopped, or its latest rows are
// not flushed to disk yet) or in a gap between samples. Before the first
// sample SnapshotAt says so.
func Covered(db *store.DB, t int64) error {
	iv := IntervalMS(db)
	var prev, next sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM samples WHERE ts <= ?`, t).Scan(&prev); err != nil {
		return err
	}
	if !prev.Valid || t-prev.Int64 <= iv*5/2 {
		return nil
	}
	if err := db.QueryRow(`SELECT MIN(ts) FROM samples WHERE ts > ?`, t).Scan(&next); err != nil {
		return err
	}
	if next.Valid {
		return fmt.Errorf("nothing was recorded at %s: no samples from %s to %s (clifrd was not running)",
			FormatMS(t), FormatMS(prev.Int64), FormatMS(next.Int64))
	}
	flush := "every flush interval"
	var v string
	db.QueryRow(`SELECT value FROM meta WHERE key = 'flush_interval_s'`).Scan(&v)
	if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
		flush = "every " + fmtDur(int64(f*1000))
	}
	return fmt.Errorf("%s is after the end of the recording (last sample %s): clifrd writes to disk %s, "+
		"so the latest minutes may not be there yet, or it was not running", FormatMS(t), FormatMS(prev.Int64), flush)
}

func IntervalMS(db *store.DB) int64 {
	var v string
	db.QueryRow(`SELECT value FROM meta WHERE key = 'interval_s'`).Scan(&v)
	if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
		return int64(f * 1000)
	}
	return 30_000
}
