package query

import (
	"database/sql"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"

	"clifr/internal/store"
)

// OOMKill is one OOM kill with the processes using the most memory at the
// time (their last sample at or before the kill).
type OOMKill struct {
	TS       int64  `json:"ts_ms"`
	PID      int    `json:"pid"`
	Command  string `json:"command"`
	RSSKB    int64  `json:"rss_kb"`   // the victim's RSS at the kill
	Snapshot bool   `json:"snapshot"` // ps shows the victim with that RSS from the kill on
	// FromLog: known only from the kernel log's "Killed process" line (no
	// OOM event recorded: clifrd without eBPF), its time the line's.
	FromLog bool      `json:"from_kernel_log,omitempty"`
	Top     []OOMProc `json:"top_rss"`
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
	logged, err := logOOMKills(db, from, to)
	if err != nil {
		return nil, err
	}
	for _, l := range logged {
		if !slices.ContainsFunc(out, func(k OOMKill) bool { return sameKill(k, l) }) {
			out = append(out, l)
		}
	}
	slices.SortStableFunc(out, func(a, b OOMKill) int { return int(a.TS - b.TS) })
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
		if k.FromLog {
			fmt.Fprintln(w, "  (from the kernel log: no OOM event was recorded, as clifrd ran without eBPF)")
		}
		if len(k.Top) == 0 {
			continue
		}
		fmt.Fprintf(w, "  %7s %10s %-19s %s\n", "PID", "RSS_KB", "SAMPLED", "COMMAND")
		for _, p := range k.Top {
			fmt.Fprintf(w, "  %7d %10d %-19s %s\n", p.PID, p.RSSKB, FormatMS(p.SampleTS), p.Command)
		}
	}
}

// killedProcess is the kernel's line for an OOM kill (oom_kill.c,
// __oom_kill_process), the same on kernels 4.18, 5.15 and 7.0: "Memory cgroup
// out of memory: Killed process 7999 (truthproc) total-vm:1360768kB,
// anon-rss:100016kB, file-rss:2388kB, shmem-rss:0kB, UID:0 ...".
var killedProcess = regexp.MustCompile(`Killed process (\d+) \((.*)\) total-vm:\d+kB, anon-rss:(\d+)kB, file-rss:(\d+)kB, shmem-rss:(\d+)kB`)

// logOOMKills returns the OOM kills in [from, to] that the recorded kernel
// log names. clifrd records kills as events only with eBPF; without it (the
// proc connector fallback) the kernel log is the only record. The RSS is
// anon + file + shmem as the line gives it; the command comes from the
// process recorded with that pid then, else the line's name.
//
// The time: clifrd reads the kernel log as it is written, so a record read
// within seconds of when dmesg -T's formula (boot time + the kernel's
// timestamp) puts it was written at most milliseconds before it was read;
// that formula drifts with the wall clock's adjustments since boot (0.4 and
// 0.9 s early in the RHEL 8 and 9 VMs, 2026-11-10: before the victim
// started). Older records (the buffer read at clifrd's start) keep the
// formula's time. A kill comes before its victim's exit: at most that.
func logOOMKills(db *store.DB, from, to int64) ([]OOMKill, error) {
	// A record is read (ts) after it was written: look a minute further.
	recs, err := KmsgBetween(db, from, to+60_000)
	if err != nil {
		return nil, nil // no kernel log recorded (before schema 6)
	}
	var out []OOMKill
	for _, r := range recs {
		m := killedProcess.FindStringSubmatch(r.Msg)
		if m == nil {
			continue
		}
		ts := floorDiv(r.BootUS+r.SuspUS+r.MonoUS, 1000)
		if d := r.TS - ts; d > -5_000 && d < 5_000 {
			ts = r.TS // read as written
		}
		pid, _ := strconv.Atoi(m[1])
		var rss int64
		for _, s := range m[3:6] {
			n, _ := strconv.ParseInt(s, 10, 64)
			rss += n
		}
		k := OOMKill{TS: ts, PID: pid, Command: m[2], RSSKB: rss, FromLog: true}
		// The victim: that pid, alive within 5 s of the kill (the nearest).
		var comm, cmdline string
		var ended sql.NullInt64
		if db.QueryRow(`SELECT comm, cmdline, ended FROM processes WHERE pid = ?1 AND first_seen <= ?2 + 5000
			AND COALESCE(ended, last_seen, ?3) >= ?2 - 5000 ORDER BY abs(first_seen - ?2) LIMIT 1`, pid, ts, openEnd).
			Scan(&comm, &cmdline, &ended) == nil {
			k.Command = commandOf(cmdline, comm, "")
			if ended.Valid && ended.Int64 < k.TS {
				k.TS = ended.Int64
			}
		}
		if k.TS < from || k.TS > to {
			continue
		}
		out = append(out, k)
	}
	return out, nil
}

// sameKill: a kill from the kernel log that an OOM event already recorded
// (same pid, within 10 s).
func sameKill(event, logged OOMKill) bool {
	return event.PID == logged.PID && event.TS-logged.TS < 10_000 && logged.TS-event.TS < 10_000
}
