package store

import (
	"database/sql"
	"regexp"
	"strconv"
)

// The query code uses SQLite's numbered parameters (?1, ?2, ...), may skip
// some and may repeat them. The DuckDB driver binds parameters by count, so
// for a DuckDB-backed DB (DataDir set) each ?N becomes a plain ? and the
// arguments are listed in order of appearance.

var numberedParam = regexp.MustCompile(`\?(\d+)`)

func positional(q string, args []any) (string, []any) {
	if !numberedParam.MatchString(q) {
		return q, args
	}
	var out []any
	q = numberedParam.ReplaceAllStringFunc(q, func(m string) string {
		n, _ := strconv.Atoi(m[1:])
		if n >= 1 && n <= len(args) {
			out = append(out, args[n-1])
		}
		return "?"
	})
	return q, out
}

func (d *DB) Query(q string, args ...any) (*sql.Rows, error) {
	if d.Prepare != nil {
		var err error
		if q, err = d.Prepare(q); err != nil {
			return nil, err
		}
	}
	if d.DataDir != "" {
		q, args = positional(q, args)
	}
	return d.DB.Query(q, args...)
}

func (d *DB) QueryRow(q string, args ...any) *sql.Row {
	if d.Prepare != nil {
		var err error
		if q, err = d.Prepare(q); err != nil {
			return d.DB.QueryRow(`SELECT error(?)`, err.Error()) // the error, at Scan
		}
	}
	if d.DataDir != "" {
		q, args = positional(q, args)
	}
	return d.DB.QueryRow(q, args...)
}
