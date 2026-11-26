package query

import (
	"database/sql"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"clifr/internal/store"
)

// Event is one line of the clifr events timeline.
type Event struct {
	TS    int64  `json:"ts_ms"`
	Kind  string `json:"kind"` // start, exit, oom, mount, unmount, remount, gap, skipped, guard
	Exact bool   `json:"exact"`
	PID   int    `json:"pid,omitempty"`
	// Detail: the whole event as one text (the table's columns together).
	Detail string `json:"detail"`
	// The table's columns, for process events (start, exit, oom): PPID, the
	// user, STATUS (an exit's code, signal name or "OOM"; an OOM kill's RSS),
	// LIFE (exit: how long it ran; at least that when the exit is bounded by
	// samples), SENT BY (who sent the fatal signal) and the command line.
	PPID     int    `json:"ppid,omitempty"`
	User     string `json:"user,omitempty"`
	Status   string `json:"status,omitempty"`
	ExitCode *int64 `json:"exit_code,omitempty"`
	Signal   string `json:"signal,omitempty"`
	LifeMS   *int64 `json:"life_ms,omitempty"`
	SentBy   string `json:"sent_by,omitempty"`
	Command  string `json:"command,omitempty"`
}

// killerCmdMax: runes of a signal sender's command line in an exit's
// detail (--json has it whole, in life).
const killerCmdMax = 60

// EventKinds are the kinds Events can return, in the order help lists them.
var EventKinds = []string{"start", "exit", "oom", "mount", "unmount", "remount", "gap", "skipped", "guard"}

// Events merges what happened in [from, to]: process starts and exits
// (exact from events, else bounded by samples), OOM kills, mount changes,
// recorder gaps and skipped samples, and guard-rail events. re filters the
// process events by command line; kinds (nil = all) selects kinds.
func Events(db *store.DB, from, to int64, re *regexp.Regexp, kinds map[string]bool) ([]Event, error) {
	want := func(k string) bool { return kinds == nil || kinds[k] }
	var out []Event
	if want("start") || want("exit") {
		rows, err := Life(db, from, to, re)
		if err != nil {
			return nil, err
		}
		sampled, err := sampledAfter(db, from, to)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			user := ""
			if r.UID != nil {
				user = UserName(int(*r.UID), false)
			}
			if want("start") && r.Start >= from && r.Start <= to {
				out = append(out, Event{TS: r.Start, Kind: "start", Exact: true, PID: r.PID,
					Detail: fmt.Sprintf("ppid %d: %s", r.PPID, r.Command),
					PPID:   r.PPID, User: user, Command: r.Command})
			}
			// Without an exit event, a process that was not seen again is an
			// exit only if the recorder took another sample; otherwise the
			// recorder stopped.
			if want("exit") && (r.EndKind == "exact" || r.EndKind == "after" && sampled(r.End)) && r.End >= from && r.End <= to {
				exit := r.Exit()
				if by := r.SentBy(); by != "" {
					exit += " from " + by
					if c := []rune(r.KillerCommand); len(c) > killerCmdMax {
						exit += " [" + string(c[:killerCmdMax]) + "...]"
					} else if len(c) > 0 {
						exit += " [" + r.KillerCommand + "]"
					}
				}
				d := fmt.Sprintf("%s after %s: %s", exit, fmtDur(r.Duration), r.Command)
				if r.EndKind == "after" {
					d = "between this sample and the next, " + d
				}
				e := Event{TS: r.End, Kind: "exit", Exact: r.EndKind == "exact", PID: r.PID, Detail: d,
					PPID: r.PPID, User: user, Status: r.Exit(), ExitCode: r.ExitCode, SentBy: r.SentBy(), Command: r.Command}
				if r.Signal != nil {
					e.Signal = r.Exit()
					if r.OOMKilled {
						e.Signal = "SIGKILL"
					}
				}
				life := r.Duration
				e.LifeMS = &life
				out = append(out, e)
			}
		}
	}
	if want("oom") {
		kills, err := OOMKills(db, from, to, 0)
		if err != nil {
			return nil, err
		}
		for _, k := range kills {
			if re == nil || re.MatchString(k.Command) {
				out = append(out, Event{TS: k.TS, Kind: "oom", Exact: true, PID: k.PID,
					Detail: fmt.Sprintf("RSS %d kB: %s", k.RSSKB, k.Command),
					Status: "RSS " + shortKB(k.RSSKB), Command: k.Command})
			}
		}
	}
	if want("mount") || want("unmount") || want("remount") {
		ms, err := MountChanges(db, from, to)
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			if want(m.Action) {
				out = append(out, Event{TS: m.TS, Kind: m.Action, Exact: true,
					Detail: fmt.Sprintf("%s type %s from %s (%s)", m.Point, m.FSType, m.Source, m.Options)})
			}
		}
	}
	if want("gap") || want("skipped") {
		ev, err := recorderGaps(db, from, to, want("gap"), want("skipped"))
		if err != nil {
			return nil, err
		}
		out = append(out, ev...)
	}
	if want("guard") {
		rows, err := db.Query(`SELECT ts, kind, COALESCE(detail, '') FROM guard_events WHERE ts BETWEEN ? AND ? ORDER BY ts`, from, to)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var e Event
			var kind, detail string
			if err := rows.Scan(&e.TS, &kind, &detail); err != nil {
				rows.Close()
				return nil, err
			}
			e.Kind, e.Exact, e.Detail = "guard", true, kind+": "+detail
			out = append(out, e)
		}
		rows.Close()
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS < out[j].TS })
	return out, nil
}

// RecordingStart is the time of the first sample (0 if there is none).
func RecordingStart(db *store.DB) int64 {
	var ts sql.NullInt64
	db.QueryRow(`SELECT MIN(ts) FROM samples`).Scan(&ts)
	return ts.Int64
}

// sampledAfter reports for a time t in [from, to] whether the recorder took
// a sample within 2.5 intervals after it.
func sampledAfter(db *store.DB, from, to int64) (func(t int64) bool, error) {
	iv := IntervalMS(db)
	if iv <= 0 {
		iv = 30_000
	}
	rows, err := db.Query(`SELECT ts FROM samples WHERE ts > ? AND ts <= ? ORDER BY ts`, from, to+3*iv)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ts []int64
	for rows.Next() {
		var t int64
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		ts = append(ts, t)
	}
	return func(t int64) bool {
		i := sort.Search(len(ts), func(i int) bool { return ts[i] > t })
		return i < len(ts) && ts[i]-t <= iv*5/2
	}, rows.Err()
}

// SampleTimes lists the samples in [from, to] at least every apart (all
// when every is 0), skipped ones left out.
func SampleTimes(db *store.DB, from, to, every int64) ([]int64, error) {
	rows, err := db.Query(`SELECT ts FROM samples WHERE skipped = 0 AND ts >= ? AND ts <= ? ORDER BY ts`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var ts int64
		if err := rows.Scan(&ts); err != nil {
			return nil, err
		}
		if len(out) == 0 || ts-out[len(out)-1] >= every {
			out = append(out, ts)
		}
	}
	return out, rows.Err()
}

// recorderGaps: time without samples (more than 2.5 intervals between two
// samples: the recorder was stopped or stalled) and skipped samples.
func recorderGaps(db *store.DB, from, to int64, gaps, skipped bool) ([]Event, error) {
	iv := IntervalMS(db)
	if iv <= 0 {
		iv = 30_000
	}
	rows, err := db.Query(`SELECT ts, skipped FROM samples WHERE ts BETWEEN ? AND ? ORDER BY ts`, from-3*iv, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	var prev int64
	for rows.Next() {
		var ts int64
		var skip int
		if err := rows.Scan(&ts, &skip); err != nil {
			return nil, err
		}
		if gaps && prev != 0 && ts-prev > iv*5/2 && ts >= from {
			out = append(out, Event{TS: prev, Kind: "gap", Exact: true,
				Detail: fmt.Sprintf("no samples for %s, until %s", fmtDur(ts-prev), FormatMS(ts))})
		}
		if skipped && skip != 0 && ts >= from {
			out = append(out, Event{TS: ts, Kind: "skipped", Exact: true, Detail: "sample skipped (the previous one overran the interval)"})
		}
		prev = ts
	}
	return out, rows.Err()
}

// PrintEvents prints the timeline as a table; "~" marks times bounded by
// samples, ">" a lifetime known to be at least that. SENT BY is as wide as
// its widest value, and left out when no event has a sender.
func PrintEvents(w io.Writer, evs []Event) {
	by := 0
	for _, e := range evs {
		by = max(by, len([]rune(e.SentBy)))
	}
	if by > 0 {
		by = max(by, len("SENT BY"))
	}
	PrintEventsWidth(w, evs, by)
}

// EventsHeader is the table's header with a SENT BY column of width by (0:
// none).
func EventsHeader(by int) string {
	return eventsLine("TIME", "EVENT", "PID", "PPID", "USER", "STATUS", "LIFE", "SENT BY", "COMMAND / DETAIL", by)
}

// PrintEventsWidth prints the table with a fixed SENT BY width (0: no such
// column; a longer value is cut): the tui prints one event at a time.
func PrintEventsWidth(w io.Writer, evs []Event, by int) {
	fmt.Fprintln(w, EventsHeader(by))
	for _, e := range evs {
		t := time.UnixMilli(e.TS).Format(msLayout)
		if !e.Exact {
			t = "~" + t
		}
		pid, ppid := "-", "-"
		if e.PID != 0 {
			pid = fmt.Sprint(e.PID)
		}
		if e.PPID != 0 {
			ppid = fmt.Sprint(e.PPID)
		}
		user := e.User
		if user == "" {
			user = "-"
		} else if r := []rune(user); len(r) > 8 {
			user = string(r[:7]) + "+" // as ps cuts names
		}
		status, life, sentBy := e.Status, "", e.SentBy
		if e.LifeMS != nil {
			life = fmtDur(*e.LifeMS)
			if !e.Exact {
				life = ">" + life
			}
		}
		if r := []rune(sentBy); by > 0 && len(r) > by {
			sentBy = string(r[:by-1]) + "+"
		}
		text := e.Command
		if text == "" {
			text = strings.TrimSpace(e.Detail)
		}
		fmt.Fprintln(w, eventsLine(t, e.Kind, pid, ppid, user, status, life, sentBy, text, by))
	}
}

func eventsLine(t, kind, pid, ppid, user, status, life, sentBy, text string, by int) string {
	l := fmt.Sprintf("%-24s %-7s %7s %7s %-8s %-9s %7s ", t, kind, pid, ppid, user, status, life)
	if by > 0 {
		l += fmt.Sprintf("%-*s ", by, sentBy)
	}
	return l + text
}

// shortKB is a size in KiB as top prints memory: 812K, 512M, 3.2G.
func shortKB(kb int64) string {
	switch {
	case kb >= 1<<20:
		return fmt.Sprintf("%.1fG", float64(kb)/(1<<20))
	case kb >= 1<<10:
		return fmt.Sprintf("%dM", kb>>10)
	}
	return fmt.Sprintf("%dK", kb)
}
