// Package verify compares the real ps/ss/lsof output saved by
// `sosv record --verify-every` with sosv's reconstruction of the same moment.
//
// A row present on only one side counts as churn rather than missing/extra
// when the database shows the entity appearing or disappearing between the
// checkpoint sample and the next sample that could have seen it: the real
// command simply ran a moment after the sample.
package verify

import (
	"database/sql"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"sosv/internal/query"
	"sosv/internal/store"
)

// Result is the comparison of one command at one checkpoint.
type Result struct {
	Cmd          string         `json:"cmd"`
	Real         int            `json:"real_rows"`
	Recon        int            `json:"reconstructed_rows"`
	Matched      int            `json:"matched"`
	Exact        int            `json:"exact"` // matched with no compared field different
	Missing      int            `json:"missing"`
	Extra        int            `json:"extra"`
	ChurnMissing int            `json:"churn_missing"`
	ChurnExtra   int            `json:"churn_extra"`
	FieldDiffs   map[string]int `json:"field_mismatches"`
	Ignored      map[string]int `json:"ignored"`
	Examples     []string       `json:"examples,omitempty"`
	// GapMS is how long after the sample the real command finished (max).
	GapMS int64 `json:"gap_ms"`
}

type Checkpoint struct {
	SampleTS int64    `json:"sample_ts_ms"`
	Results  []Result `json:"results"`
}

// Report holds every checkpoint plus per-command totals.
type Report struct {
	Checkpoints   []Checkpoint      `json:"checkpoints"`
	Totals        map[string]Result `json:"totals"`
	IgnoredFields map[string]string `json:"ignored_fields"`
}

var ignoredFields = map[string]string{
	"ps aux": "%CPU and %MEM (rounding; derived from TIME and RSS, which are compared); " +
		"the work-item suffix of kernel worker names ([kworker/1:3-events]), which changes every few ms",
	"ss -tanp":   "none",
	"lsof -n -P": "DEVICE and SIZE/OFF (not recorded); mem/DEL/mmap rows (mapped files are not recorded); thread (TID) rows; kernel-thread txt placeholders",
}

const maxExamples = 15

type snapshot struct {
	ts, endTS, sampleTS int64
	cmd, output         string
	ignore              map[int]bool
}

// Run compares every saved checkpoint.
func Run(db *store.DB) (*Report, error) {
	rows, err := db.Query(`SELECT ts, COALESCE(end_ts, ts), cmd, sample_ts, COALESCE(ignore_pids,''), output
		FROM verify_snapshots ORDER BY sample_ts, id`)
	if err != nil {
		return nil, err
	}
	var snaps []snapshot
	for rows.Next() {
		var s snapshot
		var ign string
		if err := rows.Scan(&s.ts, &s.endTS, &s.cmd, &s.sampleTS, &ign, &s.output); err != nil {
			rows.Close()
			return nil, err
		}
		s.ignore = map[int]bool{}
		for _, p := range strings.Split(ign, ",") {
			if n, err := strconv.Atoi(p); err == nil {
				s.ignore[n] = true
			}
		}
		snaps = append(snaps, s)
	}
	rows.Close()
	rep := &Report{Totals: map[string]Result{}, IgnoredFields: ignoredFields}
	for _, s := range snaps {
		var res Result
		var err error
		switch s.cmd {
		case "ps aux":
			res, err = comparePS(db, s)
		case "ss -tanp":
			res, err = compareSS(db, s)
		case "lsof -n -P":
			res, err = compareLsof(db, s)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s at %s: %w", s.cmd, query.FormatMS(s.sampleTS), err)
		}
		res.GapMS = s.endTS - s.sampleTS
		if n := len(rep.Checkpoints); n == 0 || rep.Checkpoints[n-1].SampleTS != s.sampleTS {
			rep.Checkpoints = append(rep.Checkpoints, Checkpoint{SampleTS: s.sampleTS})
		}
		cp := &rep.Checkpoints[len(rep.Checkpoints)-1]
		cp.Results = append(cp.Results, res)
		rep.Totals[s.cmd] = add(rep.Totals[s.cmd], res)
	}
	return rep, nil
}

func newResult(cmd string) Result {
	return Result{Cmd: cmd, FieldDiffs: map[string]int{}, Ignored: map[string]int{}}
}

func add(a, b Result) Result {
	if a.FieldDiffs == nil {
		a = newResult(b.Cmd)
	}
	a.Real += b.Real
	a.Recon += b.Recon
	a.Matched += b.Matched
	a.Exact += b.Exact
	a.Missing += b.Missing
	a.Extra += b.Extra
	a.ChurnMissing += b.ChurnMissing
	a.ChurnExtra += b.ChurnExtra
	a.GapMS = max(a.GapMS, b.GapMS)
	for k, v := range b.FieldDiffs {
		a.FieldDiffs[k] += v
	}
	for k, v := range b.Ignored {
		a.Ignored[k] += v
	}
	if len(a.Examples) < maxExamples {
		a.Examples = append(a.Examples, b.Examples[:min(len(b.Examples), maxExamples-len(a.Examples))]...)
	}
	return a
}

func (r *Result) example(format string, args ...any) {
	if len(r.Examples) < maxExamples {
		r.Examples = append(r.Examples, fmt.Sprintf(format, args...))
	}
}

// nextSample is the first sample after s (of the kind that could observe
// the entity), or a far-future value if recording stopped.
func nextSample(db *store.DB, s int64, fdWalk bool) int64 {
	q := `SELECT MIN(ts) FROM samples WHERE skipped = 0 AND ts > ?`
	if fdWalk {
		q += ` AND fd_walk = 1`
	}
	var n sql.NullInt64
	db.QueryRow(q, s).Scan(&n)
	if !n.Valid {
		return noNext
	}
	return n.Int64
}

func exists(db *store.DB, q string, args ...any) bool {
	var n int
	db.QueryRow(`SELECT EXISTS(`+q+`)`, args...).Scan(&n)
	return n == 1
}

const noNext = int64(1) << 62

// procChurn reports whether a process with this pid started or ended
// between the sample and the next one. Without a next sample (the
// checkpoint was the last sample) an ending cannot be told apart from an
// error, so only starts count.
func procChurn(db *store.DB, pid int, s, next int64) bool {
	return exists(db, `SELECT 1 FROM processes WHERE pid = ?1 AND (
		(first_seen > ?2 AND first_seen <= ?3) OR (start_time > ?2 AND start_time <= ?3) OR
		(?3 < ?4 AND first_seen <= ?2 AND (
			(last_seen >= ?2 AND last_seen < ?3) OR (ended >= ?2 AND ended < ?3))))`,
		pid, s, next, noNext)
}

// ---- ps aux ----

type psLine struct {
	user, vsz, rss, tty, stat, start, time, cmd string
}

func parsePS(out string) map[int]psLine {
	m := map[int]psLine{}
	lines := strings.Split(out, "\n")
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) < 11 {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		// COMMAND is everything after the 10th field (it may contain runs of spaces).
		cmd := l
		for i := 0; i < 10; i++ {
			cmd = strings.TrimLeft(cmd, " ")
			cmd = cmd[strings.IndexByte(cmd, ' ')+1:]
		}
		m[pid] = psLine{user: f[0], vsz: f[4], rss: f[5], tty: f[6], stat: f[7], start: f[8], time: f[9], cmd: strings.TrimLeft(cmd, " ")}
	}
	return m
}

func comparePS(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	recon, s, err := query.PSAt(db, snap.ts)
	if err != nil {
		return res, err
	}
	next := nextSample(db, s, false)
	real := parsePS(snap.output)
	rec := map[int]query.PSRow{}
	for _, r := range recon {
		rec[r.PID] = r
	}
	for pid := range snap.ignore {
		if _, ok := real[pid]; ok {
			res.Ignored["recorder/tool processes"]++
		}
		delete(real, pid)
		delete(rec, pid)
	}
	res.Real, res.Recon = len(real), len(rec)
	for pid, r := range real {
		x, ok := rec[pid]
		if !ok {
			if procChurn(db, pid, s, next) {
				res.ChurnMissing++
			} else {
				res.Missing++
				res.example("ps missing pid %d: %s", pid, r.cmd)
			}
			continue
		}
		res.Matched++
		diff := false
		check := func(field, a, b string) {
			if a != b {
				res.FieldDiffs[field]++
				diff = true
				if res.FieldDiffs[field] <= 3 {
					res.example("ps pid %d %s: real %q, sosv %q", pid, field, a, b)
				}
			}
		}
		check("USER", r.user, x.User)
		check("VSZ", r.vsz, strconv.FormatInt(x.VSZ, 10))
		check("RSS", r.rss, strconv.FormatInt(x.RSS, 10))
		check("TTY", r.tty, x.TTY)
		check("STAT", r.stat, x.Stat)
		check("START", r.start, strings.TrimSpace(x.Start))
		check("TIME", r.time, x.Time)
		check("COMMAND", kworkerBase(r.cmd), kworkerBase(x.Command))
		if !diff {
			res.Exact++
		}
	}
	for pid, x := range rec {
		if _, ok := real[pid]; ok {
			continue
		}
		if procChurn(db, pid, s, next) {
			res.ChurnExtra++
		} else {
			res.Extra++
			res.example("ps extra pid %d: %s", pid, x.Command)
		}
	}
	return res, nil
}

// kworkerBase drops the current work item from a kernel worker's name:
// "[kworker/1:3-events]" -> "[kworker/1:3]".
func kworkerBase(cmd string) string {
	if strings.HasPrefix(cmd, "[kworker/") {
		if i := strings.IndexAny(cmd, "-+"); i > 0 { // '+' marks a busy worker
			return cmd[:i] + "]"
		}
	}
	return cmd
}

// ---- ss -tanp ----

type ssLine struct {
	state, recvQ, sendQ string
	users               string // sorted, normalised
}

var ssUserRe = regexp.MustCompile(`\("([^"]*)",pid=(\d+),fd=(\d+)\)`)

// normUsers returns the users:(...) list as a sorted string, dropping
// processes in ignore.
func normUsers(s string, ignore map[int]bool) string {
	var parts []string
	for _, m := range ssUserRe.FindAllStringSubmatch(s, -1) {
		pid, _ := strconv.Atoi(m[2])
		if ignore[pid] {
			continue
		}
		parts = append(parts, m[1]+"/"+m[2]+"/"+m[3])
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func parseSS(out string, ignore map[int]bool) map[string]ssLine {
	m := map[string]ssLine{}
	lines := strings.Split(out, "\n")
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		key := f[3] + " " + f[4]
		m[key] = ssLine{state: f[0], recvQ: f[1], sendQ: f[2], users: normUsers(l, ignore)}
	}
	return m
}

// splitSSAddr turns "127.0.0.53%lo:53", "[::1]:22" or "0.0.0.0:*" into the
// address and port stored in the database.
func splitSSAddr(s string) (string, int) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, 0
	}
	host, port := s[:i], s[i+1:]
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if j := strings.IndexByte(host, '%'); j >= 0 {
		host = host[:j]
	}
	if strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(host, "]")
	}
	p, _ := strconv.Atoi(port)
	return host, p
}

func sockChurn(db *store.DB, key string, s, next int64) bool {
	f := strings.Fields(key)
	la, lp := splitSSAddr(f[0])
	ra, rp := splitSSAddr(f[1])
	return exists(db, `SELECT 1 FROM sockets WHERE proto = 'tcp' AND laddr = ?1 AND lport = ?2 AND raddr = ?3 AND rport = ?4
		AND ((first_seen > ?5 AND first_seen <= ?6) OR (?6 < ?7 AND last_seen IS NOT NULL AND last_seen >= ?5 AND last_seen < ?6))`,
		la, lp, ra, rp, s, next, noNext)
}

func compareSS(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	s, err := query.SnapshotAt(db, snap.ts, false)
	if err != nil {
		return res, err
	}
	recon, err := query.SocketsAt(db, s, "tcp", query.SockFilter{})
	if err != nil {
		return res, err
	}
	next := nextSample(db, s, false)
	real := parseSS(snap.output, snap.ignore)
	rec := map[string]query.SSRow{}
	for _, r := range recon {
		rec[r.Local+":"+portStr(r.LPort)+" "+r.Peer+":"+portStr(r.RPort)] = r
	}
	res.Real, res.Recon = len(real), len(rec)
	for key, r := range real {
		x, ok := rec[key]
		if !ok {
			if sockChurn(db, key, s, next) {
				res.ChurnMissing++
			} else {
				res.Missing++
				res.example("ss missing %s %s %s", r.state, key, r.users)
			}
			continue
		}
		res.Matched++
		var us []string
		for _, o := range x.Owners {
			if !snap.ignore[o.PID] {
				us = append(us, fmt.Sprintf("%s/%d/%d", o.Comm, o.PID, o.FD))
			}
		}
		sort.Strings(us)
		diff := false
		check := func(field, a, b string) {
			if a != b {
				res.FieldDiffs[field]++
				diff = true
				if res.FieldDiffs[field] <= 3 {
					res.example("ss %s %s: real %q, sosv %q", key, field, a, b)
				}
			}
		}
		check("State", r.state, x.State)
		check("Recv-Q", r.recvQ, strconv.FormatInt(x.RecvQ, 10))
		check("Send-Q", r.sendQ, strconv.FormatInt(x.SendQ, 10))
		check("Process", r.users, strings.Join(us, ","))
		if !diff {
			res.Exact++
		}
	}
	for key, x := range rec {
		if _, ok := real[key]; ok {
			continue
		}
		if sockChurn(db, key, s, next) {
			res.ChurnExtra++
		} else {
			res.Extra++
			res.example("ss extra %s %s", x.State, key)
		}
	}
	return res, nil
}

func portStr(p int) string {
	if p == 0 {
		return "*"
	}
	return strconv.Itoa(p)
}

// ---- lsof -n -P ----

type lsofLine struct {
	command, mode, typ, name string
}

var fdRe = regexp.MustCompile(`^(\d+)([rwu]?)`)

// splitFD separates "3u" (or "3uW") into "3" and "u"; named FDs pass through.
func splitFD(fd string) (string, string) {
	if m := fdRe.FindStringSubmatch(fd); m != nil {
		return m[1], m[2]
	}
	return fd, ""
}

var aInodeRe = regexp.MustCompile(`^\[([^:\]]*)[^\]]*\]$`)

// normName removes detail lsof adds that sosv does not record.
func normName(typ, name string) string {
	switch typ {
	case "a_inode":
		return aInodeRe.ReplaceAllString(name, "[$1]") // [eventpoll:5,6] -> [eventpoll]
	case "sock":
		return ""
	}
	return name
}

func parseLsof(out string, res *Result, ignore map[int]bool) map[string]lsofLine {
	m := map[string]lsofLine{}
	lines := strings.Split(out, "\n")
	if len(lines) == 0 {
		return m
	}
	hdr := lines[0]
	nameAt := strings.Index(hdr, "NAME")
	tidFrom, tidTo := strings.Index(hdr, "PID")+3, strings.Index(hdr, "TID")+3
	if nameAt < 0 {
		return m
	}
	for _, l := range lines[1:] {
		if strings.TrimSpace(l) == "" {
			continue
		}
		name := ""
		if len(l) > nameAt {
			name = strings.TrimSpace(l[nameAt:])
		}
		if tidTo > tidFrom && len(l) >= tidTo && strings.TrimSpace(l[tidFrom:tidTo]) != "" {
			res.Ignored["thread (TID) rows"]++
			continue
		}
		f := strings.Fields(l[:min(nameAt, len(l))])
		if len(f) < 5 {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		fd, mode := splitFD(f[3])
		typ := f[4]
		switch {
		case ignore[pid] || f[0] == "lsof":
			res.Ignored["recorder/tool processes"]++
			continue
		case strings.HasPrefix(fd, "mem") || strings.HasPrefix(fd, "DEL") || strings.HasPrefix(fd, "mmap") || fd == "NOFD":
			res.Ignored["mem/DEL rows"]++
			continue
		case typ == "unknown" && strings.HasPrefix(name, "/proc/"):
			res.Ignored["kernel-thread txt placeholders"]++
			continue
		}
		m[strconv.Itoa(pid)+" "+fd] = lsofLine{command: f[0], mode: mode, typ: typ, name: normName(typ, name)}
	}
	return m
}

func fdChurn(db *store.DB, pid int, fd string, s, next, nextAny int64) bool {
	if procChurn(db, pid, s, nextAny) {
		return true
	}
	num := map[string]int{"cwd": -1, "rtd": -2, "txt": -3}[fd]
	if n, err := strconv.Atoi(fd); err == nil {
		num = n
	} else if num == 0 {
		return false
	}
	changed := `((x.first_seen > ?3 AND x.first_seen <= ?4) OR
		(?4 < ?5 AND x.last_seen IS NOT NULL AND x.last_seen >= ?3 AND x.last_seen < ?4))`
	return exists(db, `SELECT 1 FROM open_files x JOIN processes p ON p.id = x.proc_id
		WHERE p.pid = ?1 AND x.fd = ?2 AND `+changed, pid, num, s, next, noNext) ||
		exists(db, `SELECT 1 FROM sock_owners x JOIN processes p ON p.id = x.proc_id
		WHERE p.pid = ?1 AND x.fd = ?2 AND `+changed, pid, num, s, nextAny, noNext)
}

func compareLsof(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	recon, s, sfd, err := query.LsofAt(db, snap.ts, query.LsofOptions{})
	if err != nil {
		return res, err
	}
	next, nextAny := nextSample(db, sfd, true), nextSample(db, s, false)
	real := parseLsof(snap.output, &res, snap.ignore)
	rec := map[string]lsofLine{}
	for _, r := range recon {
		if snap.ignore[r.PID] {
			continue
		}
		fd, mode := splitFD(r.FD)
		rec[strconv.Itoa(r.PID)+" "+fd] = lsofLine{command: r.Command, mode: mode, typ: r.Type, name: normName(r.Type, r.Name)}
	}
	res.Real, res.Recon = len(real), len(rec)
	keyParts := func(k string) (int, string) {
		p, fd, _ := strings.Cut(k, " ")
		n, _ := strconv.Atoi(p)
		return n, fd
	}
	for key, r := range real {
		x, ok := rec[key]
		if !ok {
			pid, fd := keyParts(key)
			if fdChurn(db, pid, fd, sfd, next, nextAny) {
				res.ChurnMissing++
			} else {
				res.Missing++
				res.example("lsof missing pid/fd %s: %s %s %s", key, r.command, r.typ, r.name)
			}
			continue
		}
		res.Matched++
		diff := false
		check := func(field, a, b string) {
			if a != b {
				res.FieldDiffs[field]++
				diff = true
				if res.FieldDiffs[field] <= 3 {
					res.example("lsof %s %s: real %q, sosv %q", key, field, a, b)
				}
			}
		}
		check("FD mode", r.mode, x.mode)
		check("TYPE", r.typ, x.typ)
		check("NAME", r.name, x.name)
		if !diff {
			res.Exact++
		}
	}
	for key, x := range rec {
		if _, ok := real[key]; ok {
			continue
		}
		pid, fd := keyParts(key)
		if fdChurn(db, pid, fd, sfd, next, nextAny) {
			res.ChurnExtra++
		} else {
			res.Extra++
			res.example("lsof extra pid/fd %s: %s %s %s", key, x.command, x.typ, x.name)
		}
	}
	return res, nil
}

// ---- output ----

func pct(a, b int) string {
	if b == 0 {
		return "-"
	}
	return fmt.Sprintf("%.2f%%", 100*float64(a)/float64(b))
}

func printResult(w io.Writer, r Result, examples bool) {
	fmt.Fprintf(w, "  %-11s real %6d  sosv %6d  matched %6d (%s, exact %s)  missing %4d  extra %4d  churn: missing %4d extra %4d  gap %dms\n",
		r.Cmd, r.Real, r.Recon, r.Matched, pct(r.Matched, r.Real), pct(r.Exact, r.Matched), r.Missing, r.Extra, r.ChurnMissing, r.ChurnExtra, r.GapMS)
	if len(r.FieldDiffs) > 0 {
		keys := make([]string, 0, len(r.FieldDiffs))
		for k := range r.FieldDiffs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %d", k, r.FieldDiffs[k]))
		}
		fmt.Fprintf(w, "              field mismatches: %s\n", strings.Join(parts, ", "))
	}
	if len(r.Ignored) > 0 {
		var parts []string
		for k, v := range r.Ignored {
			parts = append(parts, fmt.Sprintf("%s %d", k, v))
		}
		sort.Strings(parts)
		fmt.Fprintf(w, "              ignored rows: %s\n", strings.Join(parts, ", "))
	}
	if examples {
		for _, e := range r.Examples {
			fmt.Fprintf(w, "              e.g. %s\n", e)
		}
	}
}

func Print(w io.Writer, rep *Report, verbose bool) {
	if len(rep.Checkpoints) == 0 {
		fmt.Fprintln(w, "no verify checkpoints in this database (record with --verify-every)")
		return
	}
	for _, cp := range rep.Checkpoints {
		fmt.Fprintf(w, "checkpoint %s\n", query.FormatMS(cp.SampleTS))
		for _, r := range cp.Results {
			printResult(w, r, verbose)
		}
	}
	fmt.Fprintf(w, "\nTOTAL over %d checkpoints\n", len(rep.Checkpoints))
	for _, c := range []string{"ps aux", "ss -tanp", "lsof -n -P"} {
		if r, ok := rep.Totals[c]; ok {
			printResult(w, r, true)
		}
	}
	fmt.Fprintln(w, "\nNot compared:")
	for _, c := range []string{"ps aux", "ss -tanp", "lsof -n -P"} {
		fmt.Fprintf(w, "  %-11s %s\n", c, rep.IgnoredFields[c])
	}
	fmt.Fprintln(w, "churn = present on one side only, and the database shows it starting or ending between the\n"+
		"checkpoint sample and the sample taken right after the real commands finished. gap = how long after\n"+
		"the sample the real command finished; field mismatches include changes during that gap.")
}
