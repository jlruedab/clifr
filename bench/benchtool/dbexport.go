package main

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"os"
	"regexp"

	_ "modernc.org/sqlite"
)

var tableRe = regexp.MustCompile(`^[a-z_]+$`)

// dbexport writes one table of a clifr database as CSV to stdout, so the
// benchmark keeps per-sample self-metrics (samples, guard_events) after the
// database itself is deleted to save disk.
//
//	benchtool dbexport DB TABLE
func dbexport(args []string) error {
	if len(args) != 2 || !tableRe.MatchString(args[1]) {
		return fmt.Errorf("usage: dbexport DB TABLE")
	}
	db, err := sql.Open("sqlite", "file:"+args[0]+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.Query("SELECT * FROM " + args[1])
	if err != nil {
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	w := csv.NewWriter(os.Stdout)
	w.Write(cols)
	vals := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	rec := make([]string, len(cols))
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		for i, v := range vals {
			rec[i] = v.String // NULL -> empty field
		}
		w.Write(rec)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return rows.Err()
}
