// Package store holds what the recorder writes per sample (Batch and its
// rows), the Backend interface it writes to (internal/pqstore), and DB, the
// read side: a recording loaded into DuckDB (internal/duck).
//
// Entities (processes, sockets, socket owners, open files) are stored as time
// ranges. While an entity is open its last_seen is unset: it was seen at
// every sample since first_seen. last_seen is written when the entity closes,
// on clean shutdown, or recovered after a crash.
package store

import (
	"database/sql"
	"io/fs"
	"path/filepath"
)

// SchemaVersion is the version of the recorded data, stored in meta as
// schema_version. 1: recordings before 2026-10-19 (no key); 2: argv0_len,
// host identity and time zone; 3 (2026-10-21): sockstat columns in
// sys_samples, uname in meta; 4: net_counters; 5: links, addrs, routing; 6: kmsg; 7: units;
// 8: process fields (faults, scheduling, SHR, context switches, wchan,
// label, cgroup); 9: snapshots (whole files: swaps, modules, hostname),
// blockdevs, neighs.
// Readers refuse versions newer than theirs.
const SchemaVersion = 9

type DB struct {
	*sql.DB
	// DataDir is the Parquet data directory the tables were loaded from.
	DataDir string
	// Prepare, if set, runs before every query and may rewrite it
	// (internal/duck: load the tables it names, or count rows without
	// loading them).
	Prepare func(query string) (string, error)
	// OnClose, if set, runs after the database is closed.
	OnClose func()
}

// Close closes the database, then runs OnClose.
func (d *DB) Close() error {
	err := d.DB.Close()
	if d.OnClose != nil {
		d.OnClose()
	}
	return err
}

// SizeBytes is the size of the Parquet data directory.
func (d *DB) SizeBytes() int64 { return dirSize(d.DataDir) }

func (d *DB) Meta(key string) string {
	var v string
	d.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	return v
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
