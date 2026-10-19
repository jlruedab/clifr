package query

import (
	"fmt"
	"io"

	"clifr/internal/store"
)

// OOMKill is one OOM kill with the processes using the most memory at the
// time (their last sample at or before the kill).
type OOMKill struct {
	TS       int64     `json:"ts_ms"`
	PID      int       `json:"pid"`
	Command  string    `json:"command"`
	RSSKB    int64     `json:"rss_kb"`   // the victim's RSS at the kill
	Snapshot bool      `json:"snapshot"` // ps shows the victim with that RSS from the kill on
	Top      []OOMProc `json:"top_rss"`
}

type OOMProc struct {
	PID      int    `json:"pid"`
	RSSKB    int64  `json:"rss_kb"`
	SampleTS int64  `json:"sample_ts_ms"`
	Command  string `json:"command"`
}

// OOMKills lists the kills in [from, to], each with the top n processes by RSS.
func OOMKills(db *store.DB, from, to int64, n int) ([]OOMKill, error) {
	rows, err := db.Query(`
		SELECT o.ts, o.pid, o.comm, COALESCE(p.cmdline, ''), o.rss_kb, o.snapshot
		FROM oom_events o
		LEFT JOIN processes p ON p.pid = o.pid AND p.start_time = o.start_time
		WHERE o.ts >= ?1 AND o.ts <= ?2
		ORDER BY o.ts`, from, to)
	if err != nil {
		return nil, err
	}
	var out []OOMKill
	for rows.Next() {
		var k OOMKill
		var comm, cmdline string
		var snap int
		if err := rows.Scan(&k.TS, &k.PID, &comm, &cmdline, &k.RSSKB, &snap); err != nil {
			rows.Close()
			return nil, err
		}
		k.Command, k.Snapshot = commandOf(cmdline, comm, ""), snap != 0
		out = append(out, k)
	}
	rows.Close()
	for i := range out {
		if n > 0 {
			if out[i].Top, err = topRSS(db, out[i].TS, n); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// topRSS: processes alive at t with their latest RSS at or before t.
func topRSS(db *store.DB, t int64, n int) ([]OOMProc, error) {
	s, err := SnapshotAt(db, t, false)
	if err != nil {
		return nil, nil // the kill came before the first sample
	}
	rows, err := db.Query(`
		SELECT p.pid, p.comm, p.cmdline, x.rss_kb, x.ts
		FROM processes p JOIN proc_samples x ON x.proc_id = p.id
		WHERE p.first_seen <= ?2 AND COALESCE(p.last_seen, ?3) >= ?2
		  AND x.ts = (SELECT MAX(ts) FROM proc_samples WHERE proc_id = p.id AND ts <= ?1)
		ORDER BY x.rss_kb DESC, p.pid
		LIMIT ?4`, t, s, openEnd, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OOMProc
	for rows.Next() {
		var p OOMProc
		var comm, cmdline string
		if err := rows.Scan(&p.PID, &comm, &cmdline, &p.RSSKB, &p.SampleTS); err != nil {
			return nil, err
		}
		p.Command = commandOf(cmdline, comm, "")
		out = append(out, p)
	}
	return out, rows.Err()
}

func PrintOOM(w io.Writer, kills []OOMKill) {
	if len(kills) == 0 {
		fmt.Fprintln(w, "no OOM kills in this range")
		return
	}
	for i, k := range kills {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s  OOM kill: pid %d, RSS at the kill %d kB  %s\n",
			FormatMS(k.TS), k.PID, k.RSSKB, k.Command)
		if len(k.Top) == 0 {
			continue
		}
		fmt.Fprintf(w, "  %7s %10s %-19s %s\n", "PID", "RSS_KB", "SAMPLED", "COMMAND")
		for _, p := range k.Top {
			fmt.Fprintf(w, "  %7d %10d %-19s %s\n", p.PID, p.RSSKB, FormatMS(p.SampleTS), p.Command)
		}
	}
}
