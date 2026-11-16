package main

import (
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
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
	if g.host == "" {
		st := pqstore.ReadSealStatus(g.dataDir, g.fromBundle)
		s.Sealing = &st
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
	keys, err := sealKeys(g.sealKeys)
	if err != nil {
		return usageError{err}
	}
	r := pqstore.CheckIntegrity(g.dataDir)
	var seals *pqstore.SealCheck
	status := pqstore.ReadSealStatus(g.dataDir, g.fromBundle)
	if len(keys) > 0 {
		c := pqstore.CheckSeals(g.dataDir, keys, g.sealAnchors, r, g.bundle != nil)
		seals = &c
	}
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
				Sealing   pqstore.SealStatus      `json:"sealing"`
				Seals     *pqstore.SealCheck      `json:"seals,omitempty"`
			}{g.bundle.manifest, g.bundle.bad, r, status, seals}
		} else if status.State != "off" || seals != nil {
			v = struct {
				pqstore.IntegrityReport
				Sealing pqstore.SealStatus `json:"sealing"`
				Seals   *pqstore.SealCheck `json:"seals,omitempty"`
			}{r, status, seals}
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
		printSeals(out, status, seals)
		done()
	}
	switch {
	case g.bundle != nil && partsNote(g.bundle.parts) != "" && g.bundle.manifest != nil && g.bundle.manifest.Parts > 0:
		return fmt.Errorf("%s", partsNote(g.bundle.parts))
	case g.bundle != nil && g.bundle.manifest == nil:
		return fmt.Errorf("the bundle was cut short (no bundle.json); %d damaged data files among those that arrived", len(r.Damaged))
	case seals != nil && seals.Bad() > 0:
		return fmt.Errorf("the recording was altered after it was sealed (%d findings)", seals.Bad())
	case len(r.Damaged)+bad > 0:
		return fmt.Errorf("%d damaged or missing data files", len(r.Damaged)+bad)
	}
	return nil
}

// sealKeys reads --seal-key values: a key, or @FILE holding one.
func sealKeys(vals []string) ([][]byte, error) {
	var keys [][]byte
	for _, v := range vals {
		if f, ok := strings.CutPrefix(v, "@"); ok {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("--seal-key: %w", err)
			}
			v = string(b)
		}
		k, err := pqstore.ParseVerifyKey(v)
		if err != nil {
			return nil, fmt.Errorf("--seal-key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// printSeals prints the sealing part of verify --integrity.
func printSeals(out io.Writer, st pqstore.SealStatus, c *pqstore.SealCheck) {
	const f = "2006-01-02 15:04:05"
	ms := func(v int64) string { return time.UnixMilli(v).Format(f) }
	if c == nil {
		switch st.State {
		case "off":
			fmt.Fprintln(out, "Sealing:      off (clifrd seal-setup starts it)")
		case "set up":
			fmt.Fprintln(out, "Sealing:      set up, no seal yet (clifrd seals at its next flush)")
		case "unsealed":
			fmt.Fprintf(out, "Sealing:      LOST (%s): nothing written since is sealed; clifrd seal-setup --new\n", st.Why)
		default:
			fmt.Fprintf(out, "Sealing:      on, chain %s, last seal %s (%d); not verified: give --seal-key\n", st.KeyID, ms(st.LastMS), st.Epoch)
		}
		return
	}
	if c.Seals == 0 {
		fmt.Fprintln(out, "Seals:        none verified")
	} else {
		fmt.Fprintf(out, "Seals:        %d verified, %s .. %s, chain %s\n", c.Seals, ms(c.First), ms(c.Last), strings.Join(c.Chains, ", "))
		for _, id := range c.Chains {
			if e := c.StartEpoch[id]; e > 1 {
				fmt.Fprintf(out, "              chain %s starts at seal %d: the older logs were removed (retention)\n", id, e)
			}
		}
		fmt.Fprintf(out, "              %d run starts, %d clean stops", len(c.Starts), len(c.Ends))
		if len(c.Late) > 0 {
			fmt.Fprintf(out, "; %d after a crash (what the crashed run logged last was sealed at the next start, at %s", len(c.Late), ms(c.Late[0]))
			for _, l := range c.Late[1:] {
				fmt.Fprintf(out, ", %s", ms(l))
			}
			fmt.Fprint(out, ")")
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintf(out, "Sealed files: %d match their sealed SHA-256, %d removed by clifrd as sealed", c.Verified, c.Removed)
	if c.NotInBundle > 0 {
		fmt.Fprintf(out, ", %d not in the bundle", c.NotInBundle)
	}
	fmt.Fprintln(out)
	if c.After > 0 || c.AfterLastSeal > 0 || len(c.NoLine) > 0 || len(c.Unsealed) > 0 {
		fmt.Fprintln(out, "Not protected:")
		if c.After > 0 || c.AfterLastSeal > 0 {
			fmt.Fprintf(out, "  %d log lines (%d files) after the last seal: written since %s, sealed at the next flush\n", c.After, c.AfterLastSeal, ms(c.Last))
		}
		if n := len(c.NoLine); n > 0 {
			fmt.Fprintf(out, "  %d files without a log line (written before the integrity log, or not by clifrd), e.g. %s\n", n, c.NoLine[0])
		}
		for _, u := range c.Unsealed {
			fmt.Fprintf(out, "  sealing stopped: %s\n", u)
		}
	}
	findings := append(append(append(append([]string{}, c.SealReport.Bad...), c.Modified...), c.Deleted...), c.Premature...)
	if len(findings) == 0 {
		fmt.Fprintln(out, "Altered:      nothing found")
	} else {
		fmt.Fprintf(out, "ALTERED:      %d finding(s): changed, removed or reordered after they were sealed\n", len(findings))
		for _, x := range findings {
			fmt.Fprintf(out, "  %s\n", x)
		}
	}
	if len(c.Anchors) > 0 {
		fmt.Fprintln(out, "Anchors:")
		for _, a := range c.Anchors {
			fmt.Fprintf(out, "  %s\n", a)
		}
	}
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
		if m.Parts > 0 {
			var got []string
			for _, p := range b.parts {
				got = append(got, strconv.Itoa(p.Part))
			}
			fmt.Fprintf(out, "Parts:        %s of %d (bundle %s)\n", strings.Join(got, ", "), m.Parts, m.BundleID)
			if n := partsNote(b.parts); n != "" {
				fmt.Fprintf(out, "              %s\n", n)
			}
		}
		fmt.Fprintf(out, "Files:        %d listed, %d match their SHA-256\n", b.listed, b.listed-len(b.bad))
	}
	for _, p := range b.bad {
		fmt.Fprintf(out, "  %s\n", salvageNote(p))
	}
}
