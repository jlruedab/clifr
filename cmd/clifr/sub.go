package main

import (
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"regexp"
	"time"

	"clifr/internal/pqstore"
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
	out, done := stdout()
	defer done()
	query.PrintStats(out, s)
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
	out, done := stdout()
	defer done()
	verify.Print(out, rep, g.verbose)
	return nil
}

var tableRe = regexp.MustCompile(`^[a-z_]+$`)

// cmdExport writes one table as CSV (NULL as an empty field).
func cmdExport(db *store.DB, table string) error {
	if !tableRe.MatchString(table) {
		return errors.New("export: bad table name")
	}
	rows, err := db.Query("SELECT * FROM " + table)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	out, done := stdout()
	defer done()
	w := csv.NewWriter(out)
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

// cmdIntegrity is clifr verify --integrity: every data file checked against
// the integrity log clifrd keeps, or read whole (pqstore.CheckIntegrity).
// No DuckDB: a damaged file cannot stop it.
func cmdIntegrity(g *globals) error {
	if err := pqstore.IsDataDir(g.dataDir); err != nil {
		return fmt.Errorf("%s: not a clifr data directory (no samples table)", g.dataDir)
	}
	r := pqstore.CheckIntegrity(g.dataDir)
	if g.json {
		if err := writeLines(r, nil); err != nil {
			return err
		}
	} else {
		out, done := stdout()
		fmt.Fprintf(out, "Data files:   %d, %s, checked in %s\n", r.Files, humanBytes(r.Bytes), r.Duration.Round(time.Millisecond))
		fmt.Fprintf(out, "              %d against the SHA-256 logged when written, %d read whole (written before the\n"+
			"              integrity log, or by an older clifrd)\n", r.Logged, r.Unlogged)
		if len(r.Damaged) == 0 {
			fmt.Fprintln(out, "Damaged:      none")
		} else {
			fmt.Fprintf(out, "Damaged:      %d (queries leave out a file they cannot read, with a warning; one that still\n"+
				"              reads may give wrong values: move it out of the data directory)\n", len(r.Damaged))
			for _, d := range r.Damaged {
				span := ""
				if lo, hi, ok := pqstore.FileSpan(d.Path, 5*time.Minute); ok {
					const f = "2006-01-02 15:04"
					span = ", rows from about " + time.UnixMilli(lo).Format(f) + " to " + time.UnixMilli(hi).Format(f)
				}
				fmt.Fprintf(out, "  %s (table %s%s): %s\n", d.Path, d.Table, span, d.Error)
			}
		}
		done()
	}
	if len(r.Damaged) > 0 {
		return fmt.Errorf("%d damaged data files", len(r.Damaged))
	}
	return nil
}
