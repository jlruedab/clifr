package main

import (
	"database/sql"
	"encoding/csv"
	"errors"
	"os"
	"regexp"

	"clifr/internal/query"
	"clifr/internal/store"
	"clifr/internal/verify"
)

// cmdInfo: what the recording covers and what recording cost.
func cmdInfo(g *globals, db *store.DB) error {
	s, err := query.ComputeStats(db)
	if err != nil {
		return err
	}
	if g.json {
		return writeLines(s, nil)
	}
	query.PrintStats(os.Stdout, s)
	return nil
}

// cmdVerify compares the real tools' output saved by clifrd --verify-every
// with the reconstructions.
func cmdVerify(g *globals, db *store.DB) error {
	rep, err := verify.Run(db)
	if err != nil {
		return err
	}
	if g.json {
		return writeLines(rep, nil)
	}
	verify.Print(os.Stdout, rep, g.verbose)
	return nil
}

var tableRe = regexp.MustCompile(`^[a-z_]+$`)

// cmdExport writes one table as CSV (NULL as an empty field).
func cmdExport(db *store.DB, table string) error {
	if !tableRe.MatchString(table) {
		return errors.New("export: bad table name")
	}
	rows, err := db.DB.Query("SELECT * FROM " + table)
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
			rec[i] = v.String
		}
		w.Write(rec)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return rows.Err()
}
