// Package query reconstructs ps/lsof/ss/life output from a clifr database.
package query

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"clifr/internal/pqstore"
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
	var w io.Writer = os.Stderr
	if HeaderOut != nil {
		w = HeaderOut
	}
	fmt.Fprintf(w, "# "+format+"\n", args...)
}

// HeaderOut is where Header writes; nil: os.Stderr. clifr filters it
// (headers quote recorded values such as the host name).
var HeaderOut io.Writer

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

var userCache = map[int]string{}

// recordedUsers is the recording's uid -> name table at the queried moment
// (snapshots source "passwd", since 2026-11-08); nil for a recording without
// it, whose names are then this machine's.
var recordedUsers map[int]string

// recordedGroups is the recording's gid -> name table (snapshots source
// "group", schema 12), loaded with the users; nil without it.
var recordedGroups, groupCache = map[int]string(nil), map[int]string{}

// localGroups: without recorded group names, use this machine's (the
// recording is from it, or has no recorded names at all, users included).
var localGroups = true

// LoadUsers takes the recorded user names of the host at t (the copy at or
// before t, else the first after it: names rarely change). It reports
// whether the recording has them; without, a recording made on another
// machine gets a header saying its names are this machine's.
func LoadUsers(db *store.DB, t int64) (bool, error) {
	recordedUsers, userCache = nil, map[int]string{}
	recordedGroups, groupCache = nil, map[int]string{}
	if groups, ok, err := idNamesAt(db, "group", t); err == nil && ok {
		recordedGroups = groups
	}
	m, ok, err := idNamesAt(db, "passwd", t)
	localGroups = !ok || db.Meta("machine_id") == "" || db.Meta("machine_id") == localMachineID()
	if err != nil || !ok {
		if err == nil && db.Meta("machine_id") != "" && db.Meta("machine_id") != localMachineID() {
			Header("user names: this machine's, not the recorded host's (recorded with names since 2026-11-08)")
		}
		return false, err
	}
	recordedUsers = m
	return true, nil
}

// idNamesAt is the "id name" table of snapshots source passwd or group at t:
// the copy at or before t, else (before the run's first read) its first
// copy after t.
func idNamesAt(db *store.DB, source string, t int64) (map[int]string, bool, error) {
	lines, _, ok, err := FileAt(db, source, t)
	if err == nil && !ok {
		var next sql.NullInt64
		db.QueryRow(`SELECT MIN(ts) FROM snapshots WHERE source = ? AND whole = 1 AND ts > ?`, source, t).Scan(&next)
		if next.Valid {
			lines, _, ok, err = FileAt(db, source, next.Int64)
		}
	}
	if err != nil || !ok {
		return nil, false, err
	}
	m := make(map[int]string, len(lines))
	for _, l := range lines {
		id, name, _ := strings.Cut(l, " ")
		if n, err := strconv.Atoi(id); err == nil && name != "" {
			m[n] = name
		}
	}
	return m, true, nil
}

// GroupName is a gid's name: the recording's (LoadUsers) when it has group
// names (schema 12), else this machine's; a gid without a name stays a
// number.
func GroupName(gid int) string {
	name, ok := groupCache[gid]
	if !ok {
		name = strconv.Itoa(gid)
		if recordedGroups != nil {
			if n, ok := recordedGroups[gid]; ok {
				name = n
			}
		} else if localGroups {
			if g, err := user.LookupGroupId(name); err == nil {
				name = g.Name
			}
		}
		groupCache[gid] = name
	}
	return name
}

func localMachineID() string {
	b, _ := os.ReadFile("/etc/machine-id")
	return strings.TrimSpace(string(b))
}

// UserName resolves a uid the way ps does: names longer than 8 characters
// are cut to 7 plus '+'. With the recording's names (LoadUsers) a uid it does
// not name stays a number, as on the host.
func UserName(uid int, truncate bool) string {
	name, ok := userCache[uid]
	if !ok {
		name = strconv.Itoa(uid)
		if recordedUsers != nil {
			if n, ok := recordedUsers[uid]; ok {
				name = n
			}
		} else if u, err := user.LookupId(name); err == nil {
			name = u.Username
		}
		userCache[uid] = name
	}
	if truncate && len(name) > 8 {
		return name[:7] + "+"
	}
	return name
}

// UserID is the uid of a user name: the recording's (LoadUsers) when it has
// names, else this machine's; a number is taken as a uid.
func UserID(name string) (int, bool) {
	if n, err := strconv.Atoi(name); err == nil {
		return n, true
	}
	if recordedUsers != nil {
		for id, n := range recordedUsers {
			if n == name {
				return id, true
			}
		}
		return 0, false
	}
	if u, err := user.Lookup(name); err == nil {
		if n, err := strconv.Atoi(u.Uid); err == nil {
			return n, true
		}
	}
	return 0, false
}

func metaInt(db *store.DB, key string) int64 {
	n, _ := strconv.ParseInt(db.Meta(key), 10, 64)
	return n
}

// CompleteFrom is the oldest moment with the whole state recorded, the
// oldest mount table snapshot, when samples come before it (else 0). Each
// UTC hour begins with copies of what does not change (mounts, idle
// processes' values, cgroups, units, addresses); retention deletes whole
// hours, and a flush that straddles an hour is filed under the later one, so
// the samples of the deleted hour's last minutes come before any copy.
func CompleteFrom(db *store.DB) int64 {
	var base, first sql.NullInt64
	db.QueryRow(`SELECT MIN(ts) FROM mounts WHERE action = 'present'`).Scan(&base)
	db.QueryRow(`SELECT MIN(ts) FROM samples`).Scan(&first)
	if base.Valid && first.Valid && first.Int64 < base.Int64 {
		return base.Int64
	}
	return 0
}

// UpToSecond rounds a recording's start up to a whole second, as clifr info
// prints it: a time given back to --at at second precision is then inside it.
func UpToSecond(ms int64) int64 { return (ms + 999) / 1000 * 1000 }

// Covered returns an error when the recording has nothing for the moment t:
// t is after its last sample (the recorder stopped, or its latest rows are
// not flushed to disk yet), in a gap between samples, or before
// CompleteFrom. Before the first sample SnapshotAt says so.
func Covered(db *store.DB, t int64) error {
	if from := CompleteFrom(db); t < from {
		return fmt.Errorf("%s is before the recording kept (it starts %s): retention deleted the older hours, "+
			"and the few samples left before %s lack the hourly copies of the mounts, processes and cgroups",
			FormatMS(t), FormatMS(UpToSecond(from)), FormatMS(UpToSecond(from)))
	}
	iv := IntervalMS(db)
	var prev, next sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM samples WHERE ts <= ?`, t).Scan(&prev); err != nil {
		return err
	}
	if !prev.Valid || t == prev.Int64 {
		return nil
	}
	if err := db.QueryRow(`SELECT MIN(ts) FROM samples WHERE ts > ?`, t).Scan(&next); err != nil {
		return err
	}
	// A sample stands for the moments after it only within its own run:
	// after a run's last sample clifrd stopped (a shutdown, a restart), and
	// a moment before the next run's first sample was not recorded at all,
	// however short the gap.
	if next.Valid {
		if why := runBetween(db, prev.Int64, next.Int64); why != "" {
			return fmt.Errorf("%s is between two runs: clifrd's last sample was %s, the next %s (%s)",
				FormatMS(t), FormatMS(prev.Int64), FormatMS(next.Int64), why)
		}
	}
	if t-prev.Int64 <= iv*5/2 {
		return nil
	}
	if next.Valid {
		return fmt.Errorf("nothing was recorded at %s: no samples from %s to %s (clifrd was not running)",
			FormatMS(t), FormatMS(prev.Int64), FormatMS(next.Int64))
	}
	return fmt.Errorf("%s is after the end of the recording (last sample %s): clifrd writes to disk %s, "+
		"so the latest minutes may not be there yet, or it was not running", FormatMS(t), FormatMS(prev.Int64), flushEvery(db))
}

// runBetween says why the samples at prev and next belong to different
// clifrd runs ("after a reboot", "clifrd restarted"), "" when they are of one
// run. A run is named by its start in Unix seconds; a sample belongs to the
// newest run started at or before its second, as MetaAt reads it.
func runBetween(db *store.DB, prev, next int64) string {
	var a, b sql.NullInt64
	db.QueryRow(`SELECT MAX(run) FILTER (WHERE run <= ?2 // 1000), MAX(run) FILTER (WHERE run <= ?3 // 1000)
		FROM read_parquet(?1, union_by_name = true)`,
		filepath.Join(pqstore.TableDir(db.DataDir, "meta"), "**", "*.parquet"), prev, next).Scan(&a, &b)
	if !a.Valid || !b.Valid || a.Int64 == b.Int64 {
		return ""
	}
	if x, y := MetaAt(db, "boot_id", prev), MetaAt(db, "boot_id", next); x != "" && y != "" && x != y {
		return "after a reboot"
	}
	return "clifrd restarted"
}

// flushEvery is how often clifrd writes to disk, as text ("every 5m0s").
func flushEvery(db *store.DB) string {
	var v string
	db.QueryRow(`SELECT value FROM meta WHERE key = 'flush_interval_s'`).Scan(&v)
	if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
		return "every " + fmtDur(int64(f*1000))
	}
	return "every flush interval"
}

// IntervalMS is the recorder's sample interval from the metadata (30 s if
// unknown): the longest of every run's, as the meta table keeps only the
// newest run's and gaps are found with it. A run with a shorter interval
// then has gaps shorter than 2.5 of the longest interval go unreported;
// with the newest one, every sample of a run with a longer interval looked
// like the end of a gap.
func IntervalMS(db *store.DB) int64 {
	var v sql.NullFloat64
	db.QueryRow(`SELECT max(TRY_CAST(value AS DOUBLE)) FROM read_parquet(?, union_by_name = true) WHERE key = 'interval_s'`,
		filepath.Join(pqstore.TableDir(db.DataDir, "meta"), "**", "*.parquet")).Scan(&v)
	if v.Valid && v.Float64 > 0 {
		return int64(v.Float64 * 1000)
	}
	return 30_000
}
