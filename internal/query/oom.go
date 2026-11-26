package query

import (
	"database/sql"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"

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
	FromLog bool `json:"from_kernel_log,omitempty"`
	// The victim's parent and user, when recorded.
	PPID int    `json:"ppid,omitempty"`
	User string `json:"user,omitempty"`
	// From the kernel's report (its "oom-kill:" line, Linux 4.19+, and the
	// memory cgroup's "memory: usage ..., limit ..." line): Constraint is
	// "system" (the machine was out of memory), "cgroup" (a memory cgroup
	// reached its limit: Cgroup, LimitKB, UsageKB), "cpuset" or
	// "mempolicy"; "" when the report was not recorded.
	Constraint string `json:"constraint,omitempty"`
	Cgroup     string `json:"cgroup,omitempty"`
	LimitKB    int64  `json:"limit_kb,omitempty"`
	UsageKB    int64  `json:"usage_kb,omitempty"`
	// Top: the processes using the most memory at the kill, in Cgroup
	// (and its children) for a cgroup's kill, else on the machine.
	Top []OOMProc `json:"top_rss"`
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
		SELECT o.ts, o.pid, o.comm, COALESCE(p.cmdline, ''), o.rss_kb, o.snapshot, COALESCE(p.ppid, 0), p.uid
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
		var uid sql.NullInt64
		if err := rows.Scan(&k.TS, &k.PID, &comm, &cmdline, &k.RSSKB, &snap, &k.PPID, &uid); err != nil {
			rows.Close()
			return nil, err
		}
		if uid.Valid && uid.Int64 >= 0 {
			k.User = UserName(int(uid.Int64), false)
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
	reports := oomReports(db, from, to)
	for i := range out {
		k := &out[i]
		for _, r := range reports {
			if r.pid == k.PID && r.ts-k.TS < 10_000 && k.TS-r.ts < 10_000 {
				k.Constraint, k.Cgroup, k.LimitKB, k.UsageKB = r.constraint, r.memcg, r.limitKB, r.usageKB
				if k.User == "" && r.uid >= 0 {
					k.User = UserName(r.uid, false)
				}
				break
			}
		}
		if n > 0 {
			cg := ""
			if k.Constraint == "cgroup" {
				cg = k.Cgroup
			}
			if k.Top, err = topRSS(db, k.TS, n, cg); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// oomReport is what the kernel's OOM report says about a kill.
type oomReport struct {
	ts, limitKB, usageKB int64
	pid, uid             int
	constraint, memcg    string
}

// oomKillLine: the report's summary line (oom_kill.c, dump_oom_summary,
// Linux 4.19+): "oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),
// cpuset=...,mems_allowed=0,oom_memcg=/a/b,task_memcg=/a/b,task=python3,
// pid=481875,uid=1000" (oom_memcg only for a cgroup's kill).
var (
	oomKillLine   = regexp.MustCompile(`^oom-kill:constraint=CONSTRAINT_(\w+),.*?(?:,oom_memcg=([^,]*))?,task_memcg=[^,]*,task=.*,pid=(\d+),uid=(\d+)`)
	oomUsageLine  = regexp.MustCompile(`^memory: usage (\d+)kB, limit (\d+)kB`)
	oomConstraint = map[string]string{"NONE": "system", "MEMCG": "cgroup", "CPUSET": "cpuset", "MEMORY_POLICY": "mempolicy"}
)

// oomReports reads the OOM reports in the recorded kernel log around
// [from, to]; none when the log was not recorded.
func oomReports(db *store.DB, from, to int64) []oomReport {
	recs, err := KmsgBetween(db, from-60_000, to+60_000)
	if err != nil {
		return nil
	}
	var out []oomReport
	var usage, limit int64
	for _, r := range recs {
		switch {
		case strings.Contains(r.Msg, " invoked oom-killer: "): // a new report
			usage, limit = 0, 0
		case strings.HasPrefix(r.Msg, "memory: usage "):
			if m := oomUsageLine.FindStringSubmatch(r.Msg); m != nil {
				usage, _ = strconv.ParseInt(m[1], 10, 64)
				limit, _ = strconv.ParseInt(m[2], 10, 64)
			}
		case strings.HasPrefix(r.Msg, "oom-kill:"):
			m := oomKillLine.FindStringSubmatch(r.Msg)
			if m == nil {
				continue
			}
			rep := oomReport{ts: r.TS, constraint: oomConstraint[m[1]], memcg: m[2], uid: -1}
			if rep.constraint == "" {
				rep.constraint = strings.ToLower(m[1])
			}
			rep.pid, _ = strconv.Atoi(m[3])
			rep.uid, _ = strconv.Atoi(m[4])
			if rep.constraint == "cgroup" {
				rep.usageKB, rep.limitKB = usage, limit
			}
			out = append(out, rep)
		}
	}
	return out
}

// inCgroup: a process's recorded cgroup (/proc/PID/cgroup's lines) is cg or
// below it, in the unified hierarchy or v1's memory controller.
func inCgroup(lines, cg string) bool {
	for _, l := range strings.Split(lines, "\n") {
		f := strings.SplitN(l, ":", 3)
		if len(f) != 3 || f[1] != "" && !slices.Contains(strings.Split(f[1], ","), "memory") {
			continue
		}
		if f[2] == cg || strings.HasPrefix(f[2], strings.TrimSuffix(cg, "/")+"/") {
			return true
		}
	}
	return false
}

// topRSS: processes alive at t with their latest RSS at or before t; in
// cgroup cg (and below) when cg is set.
func topRSS(db *store.DB, t int64, n int, cg string) ([]OOMProc, error) {
	limit := n
	if cg != "" {
		limit = 4*n + 50 // room for LIKE's false matches, dropped below
	}
	s, err := SnapshotAt(db, t, false)
	if err != nil {
		return nil, nil // the kill came before the first sample
	}
	rows, err := db.Query(`
		SELECT p.pid, p.comm, p.cmdline, x.rss_kb, x.ts, COALESCE(p.cgroup, '')
		FROM processes p JOIN proc_samples x ON x.proc_id = p.id
		WHERE p.first_seen <= ?2 AND COALESCE(p.last_seen, ?3) >= ?2
		  AND x.ts = (SELECT MAX(ts) FROM proc_samples WHERE proc_id = p.id AND ts <= ?1)
		  AND (?5 = '' OR p.cgroup LIKE '%' || ?5 || '%')
		ORDER BY x.rss_kb DESC, p.pid
		LIMIT ?4`, t, s, openEnd, limit, cg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OOMProc
	for rows.Next() {
		var p OOMProc
		var comm, cmdline, cgroup string
		if err := rows.Scan(&p.PID, &comm, &cmdline, &p.RSSKB, &p.SampleTS, &cgroup); err != nil {
			return nil, err
		}
		if cg != "" && !inCgroup(cgroup, cg) { // the LIKE matched elsewhere in the text
			continue
		}
		p.Command = commandOf(cmdline, comm, "")
		if out = append(out, p); len(out) == n {
			break
		}
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
		ppid, user, limit := "-", k.User, k.Constraint
		if k.PPID != 0 {
			ppid = fmt.Sprint(k.PPID)
		}
		if user == "" {
			user = "-"
		} else if r := []rune(user); len(r) > 8 {
			user = string(r[:7]) + "+"
		}
		if limit == "" {
			limit = "-"
		}
		fmt.Fprintf(w, "%-19s %7s %7s %-8s %10s %-9s %s\n", "OOM KILL", "PID", "PPID", "USER", "RSS_KB", "LIMIT", "COMMAND")
		fmt.Fprintf(w, "%-19s %7d %7s %-8s %10d %-9s %s\n", FormatMS(k.TS), k.PID, ppid, user, k.RSSKB, limit, k.Command)
		switch k.Constraint {
		case "cgroup":
			l := "  the memory cgroup " + k.Cgroup + " reached its limit"
			if k.LimitKB > 0 {
				l += fmt.Sprintf(" (%s; usage %s)", SizeKB(k.LimitKB), SizeKB(k.UsageKB))
			}
			fmt.Fprintln(w, l+": the machine itself was not out of memory")
		case "system":
			fmt.Fprintln(w, "  the machine was out of memory (RAM and swap)")
		case "cpuset", "mempolicy":
			fmt.Fprintf(w, "  the victim's allowed memory (%s) was full, not the whole machine's\n", k.Constraint)
		}
		if k.FromLog {
			fmt.Fprintln(w, "  (from the kernel log: no OOM event was recorded, as clifrd ran without eBPF)")
		}
		if len(k.Top) == 0 {
			if k.Constraint == "cgroup" {
				fmt.Fprintln(w, "  (no other process of that cgroup was sampled before the kill)")
			}
			continue
		}
		where := "on the machine"
		if k.Constraint == "cgroup" {
			where = "in that cgroup"
		}
		fmt.Fprintf(w, "  the largest processes %s at the kill:\n", where)
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
