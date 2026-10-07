// Package store owns the SQLite schema and the per-sample batch writer.
//
// Entities (processes, sockets, socket owners, open files) are stored as time
// ranges. While an entity is open its last_seen column is NULL: it was seen at
// every sample since first_seen. last_seen is written when the entity closes,
// on clean shutdown, or by Recover after a crash.
package store

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS samples (
	id INTEGER PRIMARY KEY,
	ts INTEGER NOT NULL,           -- unix ms
	fd_walk INTEGER NOT NULL,      -- 1 if a full open-file walk ran
	skipped INTEGER NOT NULL DEFAULT 0,
	dur_proc_us INTEGER, dur_sock_us INTEGER, dur_fd_us INTEGER, dur_db_us INTEGER,
	nproc INTEGER, nsock INTEGER, nfd INTEGER, nevents INTEGER,
	rows INTEGER,                  -- rows inserted/updated in this sample's tx (previous tx for dur_db)
	cpu_us INTEGER,                -- recorder's cumulative user+sys CPU
	rss_kb INTEGER, db_bytes INTEGER, -- logical size: page_count * page_size
	fd_interval_s INTEGER
);
CREATE INDEX IF NOT EXISTS samples_ts ON samples(ts);

CREATE TABLE IF NOT EXISTS processes (
	id INTEGER PRIMARY KEY,
	pid INTEGER NOT NULL,
	start_time INTEGER NOT NULL,   -- unix ms, from stat field 22
	ppid INTEGER, uid INTEGER, comm TEXT, cmdline TEXT,
	tty INTEGER, sid INTEGER, pgrp INTEGER, locked INTEGER,
	first_seen INTEGER NOT NULL,
	last_seen INTEGER,             -- NULL while open
	ended INTEGER,                 -- exit time (event) or time it was found gone
	source TEXT NOT NULL           -- 'sample' or 'event' (never seen by a sample)
);
CREATE INDEX IF NOT EXISTS processes_first ON processes(first_seen);
CREATE INDEX IF NOT EXISTS processes_open ON processes(last_seen);
CREATE INDEX IF NOT EXISTS processes_pid ON processes(pid);

-- Written only when a value changed since the previous stored row.
CREATE TABLE IF NOT EXISTS proc_samples (
	proc_id INTEGER NOT NULL, ts INTEGER NOT NULL,
	state TEXT, nice INTEGER, tpgid INTEGER,
	cpu_ticks INTEGER, rss_kb INTEGER, vsz_kb INTEGER, threads INTEGER,
	PRIMARY KEY (proc_id, ts)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS sockets (
	id INTEGER PRIMARY KEY,
	inode INTEGER NOT NULL,
	proto TEXT NOT NULL,           -- tcp, udp
	family INTEGER NOT NULL,       -- 4 or 6
	laddr TEXT, lport INTEGER, raddr TEXT, rport INTEGER,
	ifname TEXT, uid INTEGER,
	first_seen INTEGER NOT NULL, last_seen INTEGER
);
CREATE INDEX IF NOT EXISTS sockets_first ON sockets(first_seen);
CREATE INDEX IF NOT EXISTS sockets_open ON sockets(last_seen);
CREATE INDEX IF NOT EXISTS sockets_inode ON sockets(inode);

CREATE TABLE IF NOT EXISTS sock_samples (
	sock_id INTEGER NOT NULL, ts INTEGER NOT NULL,
	state INTEGER, rxq INTEGER, txq INTEGER,
	PRIMARY KEY (sock_id, ts)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS sock_owners (
	id INTEGER PRIMARY KEY,
	sock_id INTEGER NOT NULL, proc_id INTEGER NOT NULL, fd INTEGER NOT NULL,
	first_seen INTEGER NOT NULL, last_seen INTEGER
);
CREATE INDEX IF NOT EXISTS sock_owners_sock ON sock_owners(sock_id);
CREATE INDEX IF NOT EXISTS sock_owners_proc ON sock_owners(proc_id);
CREATE INDEX IF NOT EXISTS sock_owners_open ON sock_owners(last_seen);

CREATE TABLE IF NOT EXISTS open_files (
	id INTEGER PRIMARY KEY,
	proc_id INTEGER NOT NULL,
	fd INTEGER NOT NULL,           -- -1 cwd, -2 rtd (root), -3 txt (exe)
	target TEXT NOT NULL,          -- readlink of /proc/<pid>/fd/<fd>
	deleted INTEGER NOT NULL,      -- target ends in " (deleted)"
	ftype TEXT,                    -- lsof TYPE: REG DIR CHR FIFO unix netlink a_inode sock
	mode TEXT,                     -- lsof FD mode: r w u
	name TEXT,                     -- lsof NAME when it differs from target
	node INTEGER,                  -- inode of the file (statx, cached attributes)
	first_seen INTEGER NOT NULL, last_seen INTEGER
);
CREATE INDEX IF NOT EXISTS open_files_proc ON open_files(proc_id);
CREATE INDEX IF NOT EXISTS open_files_first ON open_files(first_seen);
CREATE INDEX IF NOT EXISTS open_files_open ON open_files(last_seen);

CREATE TABLE IF NOT EXISTS guard_events (
	ts INTEGER NOT NULL, kind TEXT NOT NULL, detail TEXT
);

CREATE TABLE IF NOT EXISTS verify_snapshots (
	id INTEGER PRIMARY KEY,
	ts INTEGER NOT NULL,           -- when the real command started
	end_ts INTEGER,                -- when it finished
	cmd TEXT NOT NULL,             -- "ps aux", "ss -tanp", "lsof -n -P"
	sample_ts INTEGER,             -- the sample it is compared with
	ignore_pids TEXT,              -- recorder and tool PIDs, comma separated
	output TEXT NOT NULL
);
`

type DB struct {
	*sql.DB
	Path string
}

// Open opens (and creates if needed) the database. readOnly is used by the
// query commands so they never take the write lock.
func Open(path string, readOnly bool) (*DB, error) {
	if readOnly {
		if _, err := os.Stat(path); err != nil {
			return nil, err
		}
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	if readOnly {
		dsn = "file:" + path + "?mode=ro&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if !readOnly {
		if _, err := db.Exec(schema); err != nil {
			db.Close()
			return nil, fmt.Errorf("create schema: %w", err)
		}
	}
	return &DB{DB: db, Path: path}, nil
}

// SizeBytes is the size of the database file plus its WAL.
func (d *DB) SizeBytes() int64 {
	var n int64
	for _, p := range []string{d.Path, d.Path + "-wal"} {
		if st, err := os.Stat(p); err == nil {
			n += st.Size()
		}
	}
	return n
}

// LogicalBytes is page_count * page_size: the data the database retains,
// including pages still in the WAL. Unlike the file sizes it does not jump
// when the WAL grows to its checkpoint size.
func (d *DB) LogicalBytes() int64 {
	var pages, size int64
	d.QueryRow(`PRAGMA page_count`).Scan(&pages)
	d.QueryRow(`PRAGMA page_size`).Scan(&size)
	return pages * size
}

func (d *DB) SetMeta(key, value string) error {
	_, err := d.Exec(`INSERT INTO meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (d *DB) Meta(key string) string {
	var v string
	d.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	return v
}

// MaxID returns the largest id in table, so in-memory id counters can continue.
func (d *DB) MaxID(table string) (int64, error) {
	var n sql.NullInt64
	err := d.QueryRow(`SELECT MAX(id) FROM ` + table).Scan(&n)
	return n.Int64, err
}

// Recover closes rows left open by a recorder that did not shut down cleanly.
// An open row was seen at every sample until the recorder stopped, so its
// last_seen is the last sample of the relevant kind.
func (d *DB) Recover() (int64, error) {
	var lastAny, lastFD sql.NullInt64
	d.QueryRow(`SELECT MAX(ts) FROM samples WHERE skipped = 0`).Scan(&lastAny)
	d.QueryRow(`SELECT MAX(ts) FROM samples WHERE skipped = 0 AND fd_walk = 1`).Scan(&lastFD)
	var total int64
	for _, q := range []struct {
		table string
		ts    sql.NullInt64
	}{{"processes", lastAny}, {"sockets", lastAny}, {"sock_owners", lastAny}, {"open_files", lastFD}} {
		var res sql.Result
		var err error
		if q.ts.Valid {
			res, err = d.Exec(`UPDATE `+q.table+` SET last_seen = MAX(first_seen, ?) WHERE last_seen IS NULL`, q.ts.Int64)
		} else {
			res, err = d.Exec(`UPDATE ` + q.table + ` SET last_seen = first_seen WHERE last_seen IS NULL`)
		}
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}
