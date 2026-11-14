package main

import (
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"clifr/internal/bundle"
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
	bad := 0
	if g.bundle != nil {
		bad = len(g.bundle.bad)
		if g.bundle.manifest == nil {
			bad++ // no bundle.json: cut short
		}
	}
	if g.json {
		v := any(r)
		if g.bundle != nil {
			v = struct {
				Bundle    *bundle.Manifest        `json:"bundle"`
				Bad       []string                `json:"bundle_files_bad"`
				Integrity pqstore.IntegrityReport `json:"integrity"`
			}{g.bundle.manifest, g.bundle.bad, r}
		}
		if err := writeLines(v, nil); err != nil {
			return err
		}
	} else {
		out, done := stdout()
		if g.bundle != nil {
			printBundle(out, g.bundle)
		}
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
	switch {
	case g.bundle != nil && g.bundle.manifest == nil:
		return fmt.Errorf("the bundle was cut short (no bundle.json); %d damaged data files among those that arrived", len(r.Damaged))
	case len(r.Damaged)+bad > 0:
		return fmt.Errorf("%d damaged or missing data files", len(r.Damaged)+bad)
	}
	return nil
}

// printBundle prints a bundle's manifest summary and the files that failed
// their checksum (verify --integrity -D FILE.tar).
func printBundle(out io.Writer, b *bundleInfo) {
	const f = "2006-01-02 15:04:05"
	ms := func(v int64) string { return time.UnixMilli(v).Format(f) }
	fmt.Fprintf(out, "Bundle:       %s\n", b.path)
	m := b.manifest
	if m == nil {
		fmt.Fprintln(out, "              no bundle.json: cut short in transfer; the files that arrived whole are checked, unverified")
	} else {
		fmt.Fprintf(out, "              written %s by %s (bundle version %d)\n", ms(m.CreatedMS), m.Writer, m.BundleVersion)
		fmt.Fprintf(out, "Host:         %s, machine-id %.8s, time zone %s\n", m.Hostname, m.MachineID, m.TimeZone)
		if m.ToMS == 0 {
			fmt.Fprintln(out, "Window:       the whole recording")
		} else {
			fmt.Fprintf(out, "Window:       %s .. %s\n", ms(m.FromMS), ms(m.ToMS))
		}
		if s := m.Samples; s != nil {
			fmt.Fprintf(out, "Samples:      %d, %s .. %s, every %gs; gaps: %d\n", s.Count, ms(s.FirstMS), ms(s.LastMS), s.IntervalS, len(s.Gaps))
			for _, gp := range s.Gaps {
				fmt.Fprintf(out, "                %s .. %s (%s without samples)\n", ms(gp.FromMS), ms(gp.ToMS), time.Duration(gp.ToMS-gp.FromMS)*time.Millisecond)
			}
		} else if m.Tables == nil {
			fmt.Fprintln(out, "Samples:      (a bundle from before 2026-11-14: no summary)")
		}
		for _, e := range m.Events {
			fmt.Fprintf(out, "Event:        %s %s: %s\n", ms(e.TS), e.Kind, e.Detail)
		}
		fmt.Fprintf(out, "Files:        %d listed, %d match their SHA-256\n", len(m.Files), len(m.Files)-len(b.bad))
	}
	for _, p := range b.bad {
		fmt.Fprintf(out, "  %s\n", salvageNote(p))
	}
}
