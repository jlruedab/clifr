package query

import (
	"database/sql"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"clifr/internal/store"
)

// UnitsAt is every systemd unit loaded at t: the snapshot at or before t
// with the changes after it.
func UnitsAt(db *store.DB, t int64) ([]store.UnitRow, error) {
	var snap sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM units WHERE action = 'present' AND ts <= ?`, t).Scan(&snap); err != nil || !snap.Valid {
		return nil, fmt.Errorf("systemd units are not recorded at or before %s (recorded since schema 7)", FormatMS(t))
	}
	rows, err := db.Query(`SELECT ts, action, seq, name, description, load, active, sub, following, job_id, job_type FROM units
		WHERE (ts = ?1 AND action = 'present') OR (ts > ?1 AND ts <= ?2 AND action != 'present') ORDER BY ts, seq`, snap.Int64, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	by := map[string]store.UnitRow{}
	for rows.Next() {
		var u store.UnitRow
		if err := rows.Scan(&u.TS, &u.Action, &u.Seq, &u.Name, &u.Description, &u.Load, &u.Active, &u.Sub, &u.Following,
			&u.JobID, &u.JobType); err != nil {
			return nil, err
		}
		if u.Action == "gone" {
			delete(by, u.Name)
		} else {
			by[u.Name] = u
		}
	}
	out := make([]store.UnitRow, 0, len(by))
	for _, u := range by {
		out = append(out, u)
	}
	return out, rows.Err()
}

// ListUnitsOptions: systemctl list-units' --all, --state (--failed is
// state "failed"), --type, --plain, --no-legend and unit name patterns.
// ASCII: a locale without UTF-8 ("*" and "->" for "●" and "→").
type ListUnitsOptions struct {
	All, Plain, NoLegend   bool
	ASCII                  bool
	States, Types, Pattern []string
}

// showUnit is systemctl's output_show_unit (and ListUnitsFiltered's state
// match: load, active or sub state).
func showUnit(u *store.UnitRow, o ListUnitsOptions) bool {
	if len(o.Pattern) > 0 && !slices.ContainsFunc(o.Pattern, func(p string) bool { ok, _ := path.Match(p, u.Name); return ok }) {
		return false
	}
	if len(o.States) > 0 && !slices.ContainsFunc(o.States, func(s string) bool { return s == u.Load || s == u.Active || s == u.Sub }) {
		return false
	}
	if len(o.Types) > 0 && !slices.Contains(o.Types, unitType(u.Name)) {
		return false
	}
	switch {
	case o.All:
		return true
	case u.Following != "":
		return false
	case len(o.States) > 0, u.JobID > 0:
		return true
	}
	return u.Active != "inactive"
}

// FilterUnits returns the units systemctl list-units shows with o, in its
// order (the rows of the text output and of --json alike).
func FilterUnits(all []store.UnitRow, o ListUnitsOptions) []store.UnitRow {
	var units []store.UnitRow
	for i := range all {
		if showUnit(&all[i], o) {
			units = append(units, all[i])
		}
	}
	slices.SortFunc(units, unitCompare)
	return units
}

func unitType(name string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return ""
}

// unitCompare is systemd's unit_info_compare: by type, then name, both
// case-insensitive.
func unitCompare(a, b store.UnitRow) int {
	dot := func(s string) string {
		if i := strings.LastIndexByte(s, '.'); i >= 0 {
			return s[i:]
		}
		return ""
	}
	if c := strings.Compare(strings.ToLower(dot(a.Name)), strings.ToLower(dot(b.Name))); c != 0 {
		return c
	}
	return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
}

// PrintListUnits prints systemctl list-units as the recorded host's systemd
// does into a pipe (no colors, no truncation): systemd 239's own layout, or
// its table (249 and later) with the legend of 249/252 or of 258 and later.
func PrintListUnits(w io.Writer, all []store.UnitRow, o ListUnitsOptions, st ToolStyle) {
	circleGlyph, arrow := "●", "→"
	if o.ASCII {
		circleGlyph, arrow = "*", "->"
	}
	units := FilterUnits(all, o)
	jobs := 0
	for i := range units {
		if units[i].JobID > 0 {
			jobs++
		}
	}
	circled := func(u *store.UnitRow) bool {
		return !o.Plain && (u.Active == "failed" || slices.Contains([]string{"error", "not-found", "bad-setting", "masked"}, u.Load))
	}
	var b strings.Builder
	if st.SystemdList == "239" {
		listUnits239(&b, units, o, jobs, circled, circleGlyph)
		io.WriteString(w, b.String())
		return
	}
	// systemd's table: columns separated by a space, each as wide as its
	// widest cell, the last one not padded; an empty cell is "-".
	cols := [][]string{{""}, {"UNIT"}, {"LOAD"}, {"ACTIVE"}, {"SUB"}, {"JOB"}, {"DESCRIPTION"}}
	for i := range units {
		u := &units[i]
		glyph := " "
		if st.SystemdList == "" {
			// 258 and later: also units in a transition state.
			if circled(u) || !o.Plain && slices.Contains([]string{"reloading", "activating", "maintenance", "refreshing", "deactivating"}, u.Active) {
				glyph = circleGlyph
			}
		} else if circled(u) {
			glyph = circleGlyph
		}
		job := ""
		if u.JobID > 0 {
			job = u.JobType
		}
		for c, v := range []string{glyph, u.Name, u.Load, u.Active, u.Sub, job, u.Description} {
			if v == "" {
				v = "-"
			}
			cols[c] = append(cols[c], v)
		}
	}
	show := []int{0, 1, 2, 3, 4, 5, 6}
	if o.Plain {
		show = slices.DeleteFunc(show, func(c int) bool { return c == 0 })
	}
	if jobs == 0 {
		show = slices.DeleteFunc(show, func(c int) bool { return c == 5 })
	}
	width := make([]int, len(cols))
	for _, c := range show {
		width[c] = 1
		for _, v := range cols[c] {
			width[c] = max(width[c], utf8.RuneCountInString(v))
		}
	}
	first := 1
	if o.NoLegend {
		first = 2
	}
	for r := first - 1; r < len(cols[0]); r++ {
		var line strings.Builder
		for i, c := range show {
			v := cols[c][r]
			if i > 0 {
				line.WriteString(" ")
			}
			line.WriteString(v)
			if i < len(show)-1 {
				line.WriteString(strings.Repeat(" ", width[c]-utf8.RuneCountInString(v)))
			}
		}
		b.WriteString(line.String() + "\n")
	}
	if !o.NoLegend {
		n := len(units)
		if st.SystemdList == "" {
			if n > 0 {
				fmt.Fprintf(&b, "\nLegend: LOAD   %[1]s Reflects whether the unit definition was properly loaded.\n"+
					"        ACTIVE %[1]s The high-level unit activation state, i.e. generalization of SUB.\n"+
					"        SUB    %[1]s The low-level unit activation state, values depend on unit type.\n", arrow)
				if jobs > 0 {
					fmt.Fprintf(&b, "        JOB    %s Pending job for the unit.\n", arrow)
				}
			}
			b.WriteString("\n")
		} else if n > 0 {
			b.WriteString("\nLOAD   = Reflects whether the unit definition was properly loaded.\n" +
				"ACTIVE = The high-level unit activation state, i.e. generalization of SUB.\n" +
				"SUB    = The low-level unit activation state, values depend on unit type.\n")
			if jobs > 0 {
				b.WriteString("JOB    = Pending job for the unit.\n\n")
			}
		}
		pass := " Pass --all to see loaded but inactive units, too."
		switch {
		case o.All || slices.Contains(o.States, "inactive"):
			fmt.Fprintf(&b, "%d loaded units listed.\nTo show all installed unit files use 'systemctl list-unit-files'.\n", n)
		case len(o.States) == 0:
			fmt.Fprintf(&b, "%d loaded units listed.%s\nTo show all installed unit files use 'systemctl list-unit-files'.\n", n, pass)
		default:
			fmt.Fprintf(&b, "%d loaded units listed.\n", n)
		}
	}
	io.WriteString(w, b.String())
}

// listUnits239 is systemd 239's output_units_list into a pipe.
func listUnits239(b *strings.Builder, units []store.UnitRow, o ListUnitsOptions, jobs int, circled func(*store.UnitRow) bool, glyph string) {
	idLen, loadLen, activeLen, subLen, jobLen, descLen := 4, 4, 6, 3, 3, 11
	circle := false
	for i := range units {
		u := &units[i]
		idLen, loadLen = max(idLen, len(u.Name)), max(loadLen, len(u.Load))
		activeLen, subLen, descLen = max(activeLen, len(u.Active)), max(subLen, len(u.Sub)), max(descLen, len(u.Description))
		if u.JobID > 0 {
			jobLen = max(jobLen, len(u.JobType))
		}
		if !o.NoLegend && (u.Active == "failed" || slices.Contains([]string{"error", "not-found", "bad-setting", "masked"}, u.Load)) {
			circle = true
		}
	}
	for i := range units {
		u := &units[i]
		if i == 0 && !o.NoLegend {
			if circle {
				b.WriteString("  ")
			}
			fmt.Fprintf(b, "%-*s %-*s %-*s %-*s ", idLen, "UNIT", loadLen, "LOAD", activeLen, "ACTIVE", subLen, "SUB")
			if jobs > 0 {
				fmt.Fprintf(b, "%-*s ", jobLen, "JOB")
			}
			fmt.Fprintf(b, "%-*s\n", descLen, "DESCRIPTION")
		}
		if circle {
			if circled(u) {
				b.WriteString(glyph + " ")
			} else {
				b.WriteString("  ")
			}
		}
		job, jw := "", 0
		if jobs > 0 {
			jw = jobLen + 1
		}
		if u.JobID > 0 {
			job = u.JobType
		}
		fmt.Fprintf(b, "%-*s %-*s %-*s %-*s %-*s%-*s\n", idLen, u.Name, loadLen, u.Load, activeLen, u.Active, subLen, u.Sub,
			jw, job, descLen, u.Description)
	}
	if o.NoLegend {
		return
	}
	if len(units) > 0 {
		b.WriteString("\nLOAD   = Reflects whether the unit definition was properly loaded.\n" +
			"ACTIVE = The high-level unit activation state, i.e. generalization of SUB.\n" +
			"SUB    = The low-level unit activation state, values depend on unit type.\n")
		if jobs > 0 {
			b.WriteString("JOB    = Pending job for the unit.\n\n")
		} else {
			b.WriteString("\n")
		}
	}
	if o.All {
		fmt.Fprintf(b, "%d loaded units listed.\nTo show all installed unit files use 'systemctl list-unit-files'.\n", len(units))
	} else {
		fmt.Fprintf(b, "%d loaded units listed. Pass --all to see loaded but inactive units, too.\n"+
			"To show all installed unit files use 'systemctl list-unit-files'.\n", len(units))
	}
}
