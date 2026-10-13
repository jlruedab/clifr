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
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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
	source TEXT NOT NULL,          -- 'sample', or 'ebpf'/'proc_connector' (never seen by a sample)
	exe TEXT,                      -- from exec events
	exec_ts INTEGER, exit_ts INTEGER, -- last exec, exit (events)
	exit_code INTEGER, signal INTEGER, -- how it ended (events)
	oom_killed INTEGER NOT NULL DEFAULT 0
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

-- v2: fds held across at least two consecutive walks of their process, and
-- deleted files still open (stored at first sight).
CREATE TABLE IF NOT EXISTS fds_held (
	id INTEGER PRIMARY KEY,
	pid INTEGER NOT NULL, start_time INTEGER NOT NULL, -- process key
	fd INTEGER NOT NULL, target TEXT NOT NULL, deleted INTEGER NOT NULL,
	ftype TEXT, mode TEXT, name TEXT, node INTEGER,
	first_seen INTEGER NOT NULL, last_seen INTEGER
);
CREATE INDEX IF NOT EXISTS fds_held_proc ON fds_held(pid, start_time);

CREATE TABLE IF NOT EXISTS mounts (
	ts INTEGER NOT NULL, action TEXT NOT NULL, -- mount, unmount, present
	mount_id INTEGER, mount_point TEXT, source TEXT, fstype TEXT, options TEXT
);

-- System-wide counters, one row per sample: the kernel's raw values, cumulative
-- since boot unless they describe the moment (loads in hundredths, memory in kB).
CREATE TABLE IF NOT EXISTS sys_samples (
	ts INTEGER NOT NULL,
	uptime_ms INTEGER,                       -- since boot
	load1 INTEGER, load5 INTEGER, load15 INTEGER,
	runnable INTEGER, threads INTEGER,       -- /proc/loadavg: scheduling entities
	procs_running INTEGER, procs_blocked INTEGER,
	intr INTEGER, ctxt INTEGER, forks INTEGER, softirq INTEGER,
	mem_total INTEGER, mem_free INTEGER, mem_available INTEGER, buffers INTEGER, cached INTEGER,
	swap_cached INTEGER, active INTEGER, inactive INTEGER, swap_total INTEGER, swap_free INTEGER,
	dirty INTEGER, writeback INTEGER, shmem INTEGER, slab INTEGER, sreclaimable INTEGER,
	pgpgin INTEGER, pgpgout INTEGER, pswpin INTEGER, pswpout INTEGER, pgfault INTEGER, pgmajfault INTEGER
);
CREATE INDEX IF NOT EXISTS sys_samples_ts ON sys_samples(ts);

-- CPU times in clock ticks; cpu -1 is the total over all CPUs.
CREATE TABLE IF NOT EXISTS cpu_samples (
	ts INTEGER NOT NULL, cpu INTEGER NOT NULL,
	user INTEGER, nice INTEGER, system INTEGER, idle INTEGER, iowait INTEGER,
	irq INTEGER, softirq INTEGER, steal INTEGER, guest INTEGER, guest_nice INTEGER
);
CREATE INDEX IF NOT EXISTS cpu_samples_ts ON cpu_samples(ts);

-- /proc/diskstats of the devices that have done I/O (sectors of 512 bytes, times in ms).
CREATE TABLE IF NOT EXISTS disk_samples (
	ts INTEGER NOT NULL, major INTEGER, minor INTEGER, name TEXT NOT NULL,
	part INTEGER NOT NULL,         -- 1: a partition (iostat lists whole devices)
	rd_ios INTEGER, rd_merges INTEGER, rd_sectors INTEGER, rd_ticks INTEGER,
	wr_ios INTEGER, wr_merges INTEGER, wr_sectors INTEGER, wr_ticks INTEGER,
	dc_ios INTEGER, dc_merges INTEGER, dc_sectors INTEGER, dc_ticks INTEGER,
	in_flight INTEGER, io_ticks INTEGER, time_in_queue INTEGER, fl_ios INTEGER, fl_ticks INTEGER
);
CREATE INDEX IF NOT EXISTS disk_samples_ts ON disk_samples(ts);

CREATE TABLE IF NOT EXISTS oom_events (
	ts INTEGER NOT NULL, pid INTEGER NOT NULL,
	start_time INTEGER,            -- with pid, identifies the victim in processes
	comm TEXT, rss_kb INTEGER,     -- RSS at the kill
	snapshot INTEGER NOT NULL      -- 1: proc_samples has a row for the victim at ts
);

-- TCP connections from eBPF events (or first seen in a keyframe). One row per
-- connection; INSERT OR REPLACE keeps its newest version.
CREATE TABLE IF NOT EXISTS tcp_conns (
	id INTEGER PRIMARY KEY,
	pid INTEGER, start_time INTEGER, fd INTEGER, -- owner (0/-1: unknown)
	owner_until INTEGER,           -- the application closed the socket
	ifname TEXT,                   -- bound device
	inode INTEGER, family INTEGER,
	laddr TEXT, lport INTEGER, raddr TEXT, rport INTEGER,
	direction TEXT,                -- active, passive, listen, unknown
	open_ts INTEGER NOT NULL, close_ts INTEGER,
	first_state INTEGER, final_state INTEGER,
	linger_state INTEGER, linger_until INTEGER, -- time-wait continuation (estimated end)
	retransmits INTEGER, resets_sent INTEGER, resets_received INTEGER,
	source TEXT, last_seen INTEGER,
	v6only INTEGER                 -- 1: IPv6 socket that does not accept IPv4 (listeners)
);
CREATE INDEX IF NOT EXISTS tcp_conns_open ON tcp_conns(open_ts);

CREATE TABLE IF NOT EXISTS tcp_transitions (
	conn_id INTEGER NOT NULL, ts INTEGER NOT NULL, seq INTEGER, old_state INTEGER, new_state INTEGER
);
CREATE INDEX IF NOT EXISTS tcp_transitions_conn ON tcp_transitions(conn_id, ts);

-- Full sock_diag dumps (TCP and UDP) every keyframe interval.
CREATE TABLE IF NOT EXISTS tcp_keyframes (
	ts INTEGER NOT NULL, proto TEXT, family INTEGER,
	laddr TEXT, lport INTEGER, raddr TEXT, rport INTEGER, inode INTEGER,
	state INTEGER, recv_q INTEGER, send_q INTEGER, uid INTEGER,
	conn_id INTEGER, pid INTEGER, start_time INTEGER, fd INTEGER,
	v6only INTEGER
);
CREATE INDEX IF NOT EXISTS tcp_keyframes_ts ON tcp_keyframes(ts);

CREATE TABLE IF NOT EXISTS reconcile (
	ts INTEGER NOT NULL, kind TEXT, dump_rows INTEGER,
	missing_from_events INTEGER, extra_in_events INTEGER, initial INTEGER
);

-- Counters per interval, e.g. events received and dropped per source.
CREATE TABLE IF NOT EXISTS recorder_stats (
	ts INTEGER NOT NULL, source TEXT NOT NULL, events INTEGER, dropped INTEGER
);

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
	// DataDir is set when the tables were loaded from Parquet files
	// (internal/duck); Path is then empty.
	DataDir string
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
		if err := migrate(db); err != nil {
			db.Close()
			return nil, fmt.Errorf("migrate schema: %w", err)
		}
	}
	return &DB{DB: db, Path: path}, nil
}

// SizeBytes is the size of the database file plus its WAL, or of the
// Parquet data directory.
func (d *DB) SizeBytes() int64 {
	if d.DataDir != "" {
		return dirSize(d.DataDir)
	}
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

func dirSize(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// migrate adds the columns newer versions added to tables of an existing
// database (CREATE TABLE IF NOT EXISTS leaves old tables as they are).
func migrate(db *sql.DB) error {
	add := map[string][]string{"processes": {"exe TEXT", "exec_ts INTEGER", "exit_ts INTEGER",
		"exit_code INTEGER", "signal INTEGER", "oom_killed INTEGER NOT NULL DEFAULT 0"},
		"tcp_conns": {"v6only INTEGER"}, "tcp_keyframes": {"v6only INTEGER"}}
	for table, cols := range add {
		have := map[string]bool{}
		rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			return err
		}
		for rows.Next() {
			var n string
			rows.Scan(&n)
			have[n] = true
		}
		rows.Close()
		for _, c := range cols {
			if name, _, _ := strings.Cut(c, " "); !have[name] {
				if _, err := db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + c); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
