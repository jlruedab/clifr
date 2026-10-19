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
	"os"
	"path/filepath"
	"slices"
	"strings"

	_ "github.com/duckdb/duckdb-go/v2"

	"clifr/internal/pqstore"
	"clifr/internal/store"
)

// Open loads every table of dataDir.
func Open(dataDir string) (*store.DB, error) {
	if _, err := os.Stat(filepath.Join(dataDir, "samples")); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, fmt.Errorf("%s: permission denied (the recording is readable by root only)", dataDir)
		}
		return nil, fmt.Errorf("%s: not a clifr data directory (no samples/)", dataDir)
	}
	tmp, err := os.MkdirTemp("", "clifr-schema-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	db, err := sql.Open("duckdb", "")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one in-memory database per connection
	for _, t := range pqstore.Tables {
		empty := filepath.Join(tmp, t+".parquet")
		if err := pqstore.WriteEmpty(t, empty); err != nil {
			db.Close()
			return nil, err
		}
		files, _ := filepath.Glob(filepath.Join(dataDir, t, "*", "*.parquet"))
		if err := load(db, t, append([]string{empty}, files...)); err != nil {
			db.Close()
			return nil, fmt.Errorf("load %s: %w", t, err)
		}
	}
	return &store.DB{DB: db, DataDir: dataDir}, nil
}

func load(db *sql.DB, table string, files []string) error {
	quoted := make([]string, len(files))
	for i, f := range files {
		quoted[i] = "'" + strings.ReplaceAll(f, "'", "''") + "'"
	}
	src := fmt.Sprintf("read_parquet([%s], union_by_name = true, filename = true)", strings.Join(quoted, ", "))
	var q string
	switch {
	case table == "meta":
		q = `CREATE TABLE meta AS SELECT key, arg_max(value, ts) AS value FROM ` + src + ` GROUP BY key`
	case slices.Contains(pqstore.EntityTables, table):
		q = `CREATE TABLE ` + table + ` AS SELECT * EXCLUDE (filename) FROM ` + src + `
			QUALIFY row_number() OVER (PARTITION BY id
				ORDER BY contains(filename, '/open/'), last_seen DESC NULLS LAST) = 1`
	default:
		q = `CREATE TABLE ` + table + ` AS SELECT * EXCLUDE (filename) FROM ` + src
	}
	_, err := db.Exec(q)
	return err
}
