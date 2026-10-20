// Package duck loads a clifr Parquet data directory (internal/pqstore) into an
// in-memory DuckDB database with the v1 table names and columns, so the
// query and verify packages run on it unchanged.
//
// Entity tables keep one row per id: the closed row if there is one, else
// the open row with the latest last_seen (several recorder runs, or a crash
// between writing a closed row and the next open file). meta keeps the
// latest value per key.
package duck

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"

	"clifr/internal/pqstore"
	"clifr/internal/store"
)

// Window limits what the large TCP tables load to a time range: the
// connections alive in it, their transitions, and the keyframes from the one
// before it. The zero Window loads everything (info, verify, export).
type Window struct{ From, To int64 }

// windowSlackMS widens a window a little: the queries look only at the
// moment itself (a time-wait socket is kept by its linger_until, and the
// keyframe before the window is loaded on its own).
const windowSlackMS = 15 * 1000

// Open loads every table of dataDir, each when a query first names it.
func Open(dataDir string) (*store.DB, error) { return OpenWindow(dataDir, Window{}) }

// OpenWindow is Open with the TCP tables limited to w.
func OpenWindow(dataDir string, w Window) (*store.DB, error) {
	if _, err := os.Stat(filepath.Join(dataDir, "samples")); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, fmt.Errorf("%s: permission denied (the recording is readable by root and the clifr group)", dataDir)
		}
		return nil, fmt.Errorf("%s: not a clifr data directory (no samples/)", dataDir)
	}
	db, err := sql.Open("duckdb", "")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one in-memory database per connection
	l := &loader{db: db, dir: dataDir, w: w, loaded: map[string]bool{}}
	if err := checkSchema(db, l.files("meta")); err != nil {
		db.Close()
		return nil, err
	}
	return &store.DB{DB: db, DataDir: dataDir, Prepare: l.prepare}, nil
}

// loader loads tables on demand.
type loader struct {
	db     *sql.DB
	dir    string
	w      Window
	loaded map[string]bool
}

var tableRe = func() map[string]*regexp.Regexp {
	m := map[string]*regexp.Regexp{}
	for _, t := range pqstore.Tables {
		m[t] = regexp.MustCompile(`\b` + t + `\b`)
	}
	return m
}()

var countRe = regexp.MustCompile(`^SELECT COUNT\(\*\) FROM ([a-z_]+)$`)

// prepare loads the tables a query names that are not loaded yet. A bare
// row count of a table not loaded is answered from the files instead
// (clifr info counts every table; loading them all would take gigabytes).
func (l *loader) prepare(q string) (string, error) {
	if m := countRe.FindStringSubmatch(q); m != nil && !l.loaded[m[1]] && slices.Contains(pqstore.Tables, m[1]) &&
		l.w == (Window{}) && m[1] != "meta" {
		files := l.files(m[1])
		if len(files) == 0 {
			return `SELECT 0`, nil
		}
		if slices.Contains(pqstore.EntityTables, m[1]) {
			return fmt.Sprintf(`SELECT COUNT(DISTINCT id) FROM read_parquet([%s], union_by_name = true)`, quoteList(files)), nil
		}
		return fmt.Sprintf(`SELECT COUNT(*) FROM read_parquet([%s], union_by_name = true)`, quoteList(files)), nil
	}
	for _, t := range pqstore.Tables {
		if !l.loaded[t] && tableRe[t].MatchString(q) {
			if err := l.load(t); err != nil {
				return q, fmt.Errorf("load %s: %w", t, err)
			}
		}
	}
	return q, nil
}

func (l *loader) files(table string) []string {
	files, _ := filepath.Glob(filepath.Join(l.dir, table, "*", "*.parquet"))
	return files
}

// filesIn keeps the files that can hold rows with times in [lo, hi]
// (pqstore.FileSpan). Open files and unknown names are always kept.
func (l *loader) filesIn(table string, lo, hi int64) []string {
	flush := time.Duration(l.flushMS()) * time.Millisecond
	var out []string
	for _, f := range l.files(table) {
		fLo, fHi, ok := pqstore.FileSpan(f, flush)
		if !ok || fHi >= lo && fLo <= hi {
			out = append(out, f)
		}
	}
	return out
}

// flushMS is the recorder's flush interval from meta (0 if not recorded).
func (l *loader) flushMS() int64 {
	if err := l.load("meta"); err != nil {
		return 0
	}
	var v sql.NullFloat64
	l.db.QueryRow(`SELECT TRY_CAST(value AS DOUBLE) FROM meta WHERE key = 'flush_interval_s'`).Scan(&v)
	return int64(v.Float64 * 1000)
}

func (l *loader) load(table string) error {
	if l.loaded[table] {
		return nil
	}
	l.loaded[table] = true
	// Every table exists even without files: an empty file of its schema
	// also gives older recordings the columns added since (NULL).
	tmp, err := os.MkdirTemp("", "clifr-schema-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	empty := filepath.Join(tmp, table+".parquet")
	if err := pqstore.WriteEmpty(table, empty); err != nil {
		return err
	}
	files := l.files(table)
	where := ""
	if l.w != (Window{}) {
		from, to := l.w.From-windowSlackMS, l.w.To+windowSlackMS
		switch table {
		case "processes":
			// Alive at some moment the queries look at: from the sample
			// at or before the window (a gap in the recording can put it
			// far back) and the keyframe before it (UDP owners) on.
			pfrom := from - 2*60_000
			var s0 sql.NullInt64
			if err := l.load("samples"); err != nil {
				return err
			}
			l.db.QueryRow(fmt.Sprintf(`SELECT max(ts) FROM samples WHERE ts <= %d`, l.w.From)).Scan(&s0)
			if s0.Valid {
				pfrom = min(pfrom, s0.Int64-60_000)
			}
			if k0, ok, err := l.keyframeBefore(l.w.From); err != nil {
				return err
			} else if ok {
				pfrom = min(pfrom, k0-60_000)
			}
			files = l.filesIn(table, pfrom, math.MaxInt64)
			where = fmt.Sprintf(` WHERE first_seen <= %d AND (last_seen IS NULL OR COALESCE(ended, last_seen) >= %d)`, to, pfrom)
		case "proc_samples":
			if err := l.load("processes"); err != nil {
				return err
			}
			where = ` WHERE proc_id IN (SELECT id FROM processes)`
		case "tcp_conns":
			// Closed before the window: written before it too. Opened after
			// it: skipped by the row groups' statistics on open_ts.
			files = l.filesIn(table, from, math.MaxInt64)
			where = fmt.Sprintf(` WHERE open_ts <= %d AND (close_ts IS NULL OR close_ts >= %d OR linger_until >= %d)`, to, from, from)
		case "tcp_transitions":
			if err := l.load("tcp_conns"); err != nil {
				return err
			}
			t0 := time.Now()
			err := l.loadTransitions(empty, from, to)
			l.debug(table, t0)
			return err
		case "tcp_keyframes":
			// From the last keyframe at or before the window.
			first := from
			if k0, ok, err := l.keyframeBefore(l.w.From); err != nil {
				return err
			} else if ok {
				first = min(first, k0)
			}
			files = l.filesIn(table, first, to)
			where = fmt.Sprintf(` WHERE ts >= %d AND ts <= %d`, first, to)
		}
	}
	src := source(append([]string{empty}, files...))
	var q string
	switch {
	case table == "meta":
		q = `CREATE TABLE meta AS SELECT key, arg_max(value, ts) AS value FROM ` + src + ` GROUP BY key`
	case slices.Contains(pqstore.EntityTables, table):
		q = `CREATE TABLE ` + table + ` AS SELECT * EXCLUDE (filename) FROM ` + src + where + `
			QUALIFY row_number() OVER (PARTITION BY id
				ORDER BY contains(filename, '/open/'), last_seen DESC NULLS LAST) = 1`
	default:
		q = `CREATE TABLE ` + table + ` AS SELECT * EXCLUDE (filename) FROM ` + src + where
	}
	t0 := time.Now()
	_, err = l.db.Exec(q)
	l.debug(table, t0)
	return err
}

// keyframeBefore is the time of the last keyframe at or before t.
func (l *loader) keyframeBefore(t int64) (int64, bool, error) {
	files := l.filesIn("tcp_keyframes", 0, t)
	if len(files) == 0 {
		return 0, false, nil
	}
	var k sql.NullInt64
	err := l.db.QueryRow(fmt.Sprintf(`SELECT max(ts) FROM read_parquet([%s]) WHERE ts <= %d`, quoteList(files), t)).Scan(&k)
	return k.Int64, k.Valid, err
}

// loadTransitions loads, for the connections loaded, their transitions in
// [from, to] and each one's state when the window starts. That state is
// taken from the last keyframe before the window (a row at the keyframe's
// time, seq -1, so a real transition at the same instant wins), so the
// files before it need not be read: a long-lived connection would otherwise
// make every query read the whole recording. Connections the keyframe does
// not have (none, normally) get their last transition before it by a
// lookup of their ids only. Without a keyframe: every transition before
// the window, reduced to each connection's last.
func (l *loader) loadTransitions(empty string, from, to int64) error {
	const ids = `(SELECT id FROM tcp_conns)`
	k0, ok, err := l.keyframeBefore(from)
	if err != nil {
		return err
	}
	if !ok {
		var first sql.NullInt64
		l.db.QueryRow(`SELECT min(open_ts) FROM tcp_conns`).Scan(&first)
		src := source(append([]string{empty}, l.filesIn("tcp_transitions", min(first.Int64, from), to)...))
		_, err := l.db.Exec(fmt.Sprintf(`CREATE TABLE tcp_transitions AS
			SELECT * EXCLUDE (filename) FROM %s WHERE ts >= %d AND ts <= %d AND conn_id IN %s
			UNION ALL BY NAME
			SELECT * EXCLUDE (filename) FROM %s WHERE ts < %d AND conn_id IN %s
			QUALIFY row_number() OVER (PARTITION BY conn_id ORDER BY ts DESC, seq DESC) = 1`, src, from, to, ids, src, from, ids))
		return err
	}
	src := source(append([]string{empty}, l.filesIn("tcp_transitions", k0, to)...))
	kf := quoteList(l.filesIn("tcp_keyframes", k0, k0))
	if _, err := l.db.Exec(fmt.Sprintf(`CREATE TABLE tcp_transitions AS
		SELECT conn_id, ts, seq, old_state, new_state FROM %s WHERE ts >= %d AND ts <= %d AND conn_id IN %s
		UNION ALL
		SELECT conn_id, %d AS ts, -1 AS seq, state AS old_state, state AS new_state
		FROM read_parquet([%s], union_by_name = true) WHERE ts = %d AND proto = 'tcp' AND conn_id IN %s`,
		src, k0, to, ids, k0, kf, k0, ids)); err != nil {
		return err
	}
	// Connections open before the keyframe that it does not list.
	var missing int64
	l.db.QueryRow(`SELECT COUNT(*) FROM tcp_conns c WHERE c.open_ts < ? AND NOT EXISTS
		(SELECT 1 FROM tcp_transitions x WHERE x.conn_id = c.id AND x.ts = ? AND x.seq = -1)`, k0, k0).Scan(&missing)
	if missing == 0 {
		return nil
	}
	all := source(append([]string{empty}, l.filesIn("tcp_transitions", 0, k0)...))
	_, err = l.db.Exec(fmt.Sprintf(`INSERT INTO tcp_transitions
		SELECT conn_id, ts, seq, old_state, new_state FROM %s
		WHERE ts < %d AND conn_id IN (SELECT c.id FROM tcp_conns c WHERE c.open_ts < %d AND NOT EXISTS
			(SELECT 1 FROM tcp_transitions x WHERE x.conn_id = c.id AND x.ts = %d AND x.seq = -1))
		QUALIFY row_number() OVER (PARTITION BY conn_id ORDER BY ts DESC, seq DESC) = 1`, all, k0, k0, k0))
	return err
}

func quoteList(files []string) string {
	quoted := make([]string, len(files))
	for i, f := range files {
		quoted[i] = "'" + strings.ReplaceAll(f, "'", "''") + "'"
	}
	return strings.Join(quoted, ", ")
}

// debug reports a table's load with CLIFR_DEBUG_LOAD set.
func (l *loader) debug(table string, t0 time.Time) {
	if os.Getenv("CLIFR_DEBUG_LOAD") == "" {
		return
	}
	var n int64
	l.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n)
	fmt.Fprintf(os.Stderr, "load %-16s %9d rows %6.3f s\n", table, n, time.Since(t0).Seconds())
}

func source(files []string) string {
	return fmt.Sprintf("read_parquet([%s], union_by_name = true, filename = true)", quoteList(files))
}

// checkSchema refuses recordings written by a newer clifrd than this reader
// knows (any run's schema_version, not just the latest).
func checkSchema(db *sql.DB, files []string) error {
	if len(files) == 0 {
		return nil
	}
	quoted := make([]string, len(files))
	for i, f := range files {
		quoted[i] = "'" + strings.ReplaceAll(f, "'", "''") + "'"
	}
	var v sql.NullInt64
	q := fmt.Sprintf(`SELECT max(TRY_CAST(value AS INTEGER)) FROM read_parquet([%s], union_by_name = true) WHERE key = 'schema_version'`,
		strings.Join(quoted, ", "))
	if err := db.QueryRow(q).Scan(&v); err != nil {
		return fmt.Errorf("meta: %w", err)
	}
	if v.Valid && v.Int64 > store.SchemaVersion {
		return fmt.Errorf("recorded by a newer clifrd (schema %d); this clifr reads schemas up to %d: update clifr", v.Int64, store.SchemaVersion)
	}
	return nil
}
