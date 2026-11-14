package query

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"clifr/internal/store"
)

// PstoreRecord is one kernel crash record (pstore) clifrd stored at the
// start of the boot after the crash: kmsg rows of kind "pstore" (recorder/
// pstore.go), one per line, under the crashed boot's id.
type PstoreRecord struct {
	BootID  string   `json:"boot_id"`  // the boot that crashed ("" if unknown)
	File    string   `json:"file"`     // the record's name (dmesg-efi-..., NNN/dmesg.txt)
	SavedMS int64    `json:"saved_ms"` // its time: when the kernel saved it, or when systemd-pstore copied it
	Reason  string   `json:"reason,omitempty"`
	Lines   []string `json:"lines"`
}

// PstoreRecords lists the crash records saved between from and to (Unix ms;
// 0, 0: all), oldest first.
func PstoreRecords(db *store.DB, from, to int64) ([]PstoreRecord, error) {
	q := `SELECT boot_id, caller, min(ts), list(msg ORDER BY seq) FROM (
			SELECT DISTINCT boot_id, caller, ts, seq, msg FROM kmsg WHERE kind = 'pstore')`
	var args []any
	if to != 0 {
		q += ` WHERE ts >= ? AND ts <= ?`
		args = append(args, from, to)
	}
	q += ` GROUP BY boot_id, caller ORDER BY min(ts), caller`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PstoreRecord
	for rows.Next() {
		var r PstoreRecord
		var lines []any
		if err := rows.Scan(&r.BootID, &r.File, &r.SavedMS, &lines); err != nil {
			return nil, err
		}
		for _, l := range lines {
			r.Lines = append(r.Lines, fmt.Sprint(l))
		}
		r.Reason = PanicReason(r.Lines)
		out = append(out, r)
	}
	return out, rows.Err()
}

// panicRes find the line that says why the kernel died, most telling first
// (the recorder's guard event uses the same).
var panicRes = []*regexp.Regexp{
	regexp.MustCompile(`Kernel panic - not syncing:.*`),
	regexp.MustCompile(`(BUG: .*|Oops: .*|general protection fault.*|kernel BUG at .*|watchdog: .*lockup.*|Machine check.*|\[Hardware Error\].*|sysrq: Trigger a crash.*)`),
	regexp.MustCompile(`RIP: .*`),
}

// PanicReason is the line of a crash record that says why, or "".
func PanicReason(lines []string) string {
	for _, re := range panicRes {
		for _, l := range lines {
			if m := re.FindString(l); m != "" {
				return strings.TrimSpace(m)
			}
		}
	}
	return ""
}

// PrintPstore prints each record: a header line, then its text as the
// kernel wrote it.
func PrintPstore(w io.Writer, recs []PstoreRecord) {
	for i, r := range recs {
		if i > 0 {
			fmt.Fprintln(w)
		}
		boot := r.BootID
		if len(boot) > 8 {
			boot = boot[:8]
		}
		if boot == "" {
			boot = "unknown"
		}
		fmt.Fprintf(w, "== %s, boot %s, saved %s", r.File, boot, FormatMS(r.SavedMS))
		if r.Reason != "" {
			fmt.Fprintf(w, ": %s", r.Reason)
		}
		fmt.Fprintln(w)
		for _, l := range r.Lines {
			fmt.Fprintln(w, l)
		}
	}
}
