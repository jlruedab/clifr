// Package verify compares the real ps/ss/lsof output saved by
// `clifrd --verify-every` with clifr's reconstruction of the same moment.
//
// A row present on only one side counts as churn rather than missing/extra
// when the database shows the entity appearing or disappearing between the
// checkpoint sample and the next sample that could have seen it: the real
// command simply ran a moment after the sample. Likewise a matched row whose
// fields differ counts as churn-changed, not as a mismatch, when the entity
// changed in that window.
package verify

import (
	"database/sql"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/query"
	"clifr/internal/store"
)

// Result is the comparison of one command at one checkpoint.
type Result struct {
	Cmd          string `json:"cmd"`
	Real         int    `json:"real_rows"`
	Recon        int    `json:"reconstructed_rows"`
	Matched      int    `json:"matched"`
	Exact        int    `json:"exact"` // matched with no compared field different
	Missing      int    `json:"missing"`
	Extra        int    `json:"extra"`
	ChurnMissing int    `json:"churn_missing"`
	ChurnExtra   int    `json:"churn_extra"`
	// ChurnChanged: matched rows whose fields differ because the entity
	// changed between the sample and the next one (not in FieldDiffs).
	ChurnChanged int            `json:"churn_changed"`
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
	"ss -tanp": "none",
	"lsof -n -P": "DEVICE and SIZE/OFF (not recorded); mem/DEL/mmap rows (mapped files are not recorded); thread (TID) rows (captured with -K i: none); kernel-thread txt placeholders; " +
		"TYPE and NAME of sockets lsof could not resolve (TYPE sock: newer than lsof's own /proc/net read), which are matched by inode instead",
}

const maxExamples = 15

type snapshot struct {
	ts, endTS, sampleTS int64
	cmd, output         string
	ignore              map[int]bool
}

// Run compares every saved checkpoint.
func Run(db *store.DB) (*Report, error) {
	queryErr = nil
	complete := query.CompleteFrom(db) // read before the rows: one connection
	rows, err := db.Query(`SELECT ts, COALESCE(end_ts, ts), cmd, sample_ts, COALESCE(ignore_pids,''), output
		FROM verify_snapshots WHERE sample_ts >= ? ORDER BY sample_ts, id`, complete)
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
	events := query.TCPFromEvents(db)
	var prevLsof map[string]lsofLine // the previous checkpoint's real lsof (held mode)
	for _, s := range snaps {
		var res Result
		var err error
		if s.cmd == "lsof -n -P -K i" {
			s.cmd = "lsof -n -P" // the same rows without the per-thread ones, which were never compared
		}
		switch s.cmd {
		case "ps aux":
			res, err = comparePS(db, s)
		case "ss -tanp":
			if events {
				res, err = compareSSEvents(db, s)
			} else {
				res, err = compareSS(db, s)
			}
		case "lsof -n -P":
			var cur map[string]lsofLine
			res, cur, err = compareLsof(db, s, prevLsof)
			prevLsof = cur
		case "uptime", "vmstat", "mpstat -P ALL", "iostat -dx":
			res, err = compareSystem(db, s)
		case "free":
			res, err = compareFree(db, s)
		case "df", "df -al -x autofs":
			res, err = compareDF(db, s)
		case "mount", "mount -l":
			res, err = compareMount(db, s)
		case "ps -ef":
			res, err = comparePSEF(db, s)
		case "ps alxwww":
			res, err = comparePSFormat(db, s, query.PSLong, parsePSLong,
				[]string{"F", "UID", "PPID", "PRI", "NI", "VSZ", "RSS", "WCHAN", "STAT", "TTY", "TIME", "COMMAND"})
		case "pidstat -h -u -r -d -w -p ALL":
			res, err = comparePidstat(db, s)
		case "systemd-cgls --no-pager", "systemd-cgls --no-pager -l":
			res, err = compareCgls(db, s)
		case "ps auxZww":
			res, err = comparePSFormat(db, s, query.PSAuxLabel, parsePSLabel, []string{"LABEL"})
		case "top -b -n 1 -w 512":
			res, err = compareTop(db, s)
		case "findmnt":
			res, err = compareFindmnt(db, s)
		case "ip -s -d link", "ip -d address":
			res, err = compareIPLink(db, s)
		case "systemctl list-units --no-pager", "systemctl list-units --all --no-pager", "systemctl list-units --failed --no-pager":
			res, err = compareListUnits(db, s)
		case "dmesg", "dmesg -T":
			res, err = compareDmesg(db, s)
		case "ip route show table all", "ip -6 route show table all", "ip -4 rule list", "ip -6 rule list":
			res, err = compareIPRouting(db, s)
		case "ip -o addr":
			res, err = compareIPAddrOneLine(db, s)
		case "netstat -s", "netstat -s -6":
			res, err = compareNetstatStats(db, s)
		case "nstat -zas":
			res, err = compareNstat(db, s)
		case "uname -a":
			res, err = compareUname(db, s)
		case "swapon --show", "swapon --summary", "lsmod":
			res, err = compareSnapshotTool(db, s)
		case "lsblk", "lsblk -f":
			res, err = compareLsblk(db, s)
		case "ip neigh", "ip -s -s neigh", "ip netns":
			res, err = compareIPNeigh(db, s)
		case "lslocks", "ipcs", "ipcs -u":
			res, err = compareLocksIPC(db, s)
		case "sysctl -a":
			res, err = compareSysctl(db, s)
		case "nfsstat", "mountstats", "mountstats -x":
			res, err = compareNFS(db, s)
		case "slabtop -o", "numastat", "numastat -m", "conntrack -S":
			res, err = compareNumbers(db, s)
		case "ss -s":
			res, err = compareSSSummary(db, s)
		case "pstree -lpT", "ps auxfwww":
			res, err = compareTree(db, s)
		case "netstat -tanp":
			if !events {
				continue // compared only with TCP from events
			}
			res, err = compareNetstat(db, s)
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
	if queryErr != nil {
		return nil, fmt.Errorf("churn query: %w", queryErr)
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
	a.ChurnChanged += b.ChurnChanged
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

type fieldPair struct{ name, real, clifr string }

// compare counts a matched row as exact, churn-changed (fields differ and
// changed() shows the entity changing between the sample and the next one)
// or as field mismatches.
func (r *Result) compare(label string, fields []fieldPair, changed func() bool) {
	var diff []fieldPair
	for _, f := range fields {
		if f.real != f.clifr {
			diff = append(diff, f)
		}
	}
	switch {
	case len(diff) == 0:
		r.Exact++
	case changed():
		r.ChurnChanged++
	default:
		for _, f := range diff {
			r.FieldDiffs[f.name]++
			if r.FieldDiffs[f.name] <= 3 {
				r.example("%s %s: real %q, clifr %q", label, f.name, f.real, f.clifr)
			}
		}
	}
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

// queryErr keeps the first error from exists, which Run returns: a failing
// churn query must not silently count as "no churn".
var queryErr error

// exists runs SELECT EXISTS(q).
func exists(db *store.DB, q string, args ...any) bool {
	var ok bool
	if err := db.QueryRow(`SELECT EXISTS(`+q+`)`, args...).Scan(&ok); err != nil && queryErr == nil {
		queryErr = err
	}
	return ok
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
					res.example("ps pid %d %s: real %q, clifr %q", pid, field, a, b)
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

// sockChanged: sockChurn, or the connection's state, queues or owners
// changed between the sample and the next one.
func sockChanged(db *store.DB, key string, s, next int64) bool {
	if sockChurn(db, key, s, next) {
		return true
	}
	f := strings.Fields(key)
	la, lp := splitSSAddr(f[0])
	ra, rp := splitSSAddr(f[1])
	return exists(db, `SELECT 1 FROM sockets k WHERE k.proto = 'tcp' AND k.laddr = ?1 AND k.lport = ?2 AND k.raddr = ?3 AND k.rport = ?4
		AND (EXISTS(SELECT 1 FROM sock_samples x WHERE x.sock_id = k.id AND x.ts > ?5 AND x.ts <= ?6)
		  OR EXISTS(SELECT 1 FROM sock_owners x WHERE x.sock_id = k.id AND ((x.first_seen > ?5 AND x.first_seen <= ?6)
		     OR (?6 < ?7 AND x.last_seen IS NOT NULL AND x.last_seen >= ?5 AND x.last_seen < ?6))))`,
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
		res.compare("ss "+key, []fieldPair{
			{"State", r.state, x.State},
			{"Recv-Q", r.recvQ, strconv.FormatInt(x.RecvQ, 10)},
			{"Send-Q", r.sendQ, strconv.FormatInt(x.SendQ, 10)},
			{"Process", r.users, strings.Join(us, ",")},
		}, func() bool { return sockChanged(db, key, s, next) })
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
	node                     string // real lsof NODE column
	inode                    int64  // clifr: inode of an inet socket
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

// normName removes detail lsof adds that clifr does not record.
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
		m[strconv.Itoa(pid)+" "+fd] = lsofLine{command: f[0], mode: mode, typ: typ, name: normName(typ, name), node: f[len(f)-1]}
	}
	return m
}

// fdChurn: the process or this fd changed between the sample and the next
// one. With TCP events (window set), a TCP socket on this fd changed while
// the real command ran.
func fdChurn(db *store.DB, pid int, fd string, s, next, nextAny int64, window [2]int64) bool {
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
	if window[1] != 0 && exists(db, `SELECT 1 FROM tcp_conns c WHERE c.pid = ?1 AND c.fd = ?2 AND
		((c.open_ts > ?3 AND c.open_ts <= ?4) OR (c.close_ts > ?3 AND c.close_ts <= ?4) OR
		 (c.owner_until > ?3 AND c.owner_until <= ?4))`, pid, num, window[0], window[1]) {
		return true
	}
	// Held storage: first_seen is the first walk that saw the fd, so a row
	// starting at the next walk opened in the gap.
	if query.FDsHeld(db) && exists(db, `SELECT 1 FROM fds_held x WHERE x.pid = ?1 AND x.fd = ?2 AND `+changed,
		pid, num, s, next, noNext) {
		return true
	}
	return exists(db, `SELECT 1 FROM open_files x JOIN processes p ON p.id = x.proc_id
		WHERE p.pid = ?1 AND x.fd = ?2 AND `+changed, pid, num, s, next, noNext) ||
		window[1] == 0 && exists(db, `SELECT 1 FROM sock_owners x JOIN processes p ON p.id = x.proc_id
		WHERE p.pid = ?1 AND x.fd = ?2 AND `+changed, pid, num, s, nextAny, noNext)
}

// compareLsof also returns the parsed real output, which the next
// checkpoint uses in held mode.
func compareLsof(db *store.DB, snap snapshot, prev map[string]lsofLine) (Result, map[string]lsofLine, error) {
	res := newResult(snap.cmd)
	recon, s, sfd, err := query.LsofAt(db, snap.ts, query.LsofOptions{})
	if err != nil {
		return res, nil, err
	}
	next, nextAny := nextSample(db, sfd, true), nextSample(db, s, false)
	var window [2]int64
	if query.TCPFromEvents(db) {
		window = [2]int64{snap.ts, snap.endTS}
	}
	real := parseLsof(snap.output, &res, snap.ignore)
	all := real
	rec := map[string]lsofLine{}
	for _, r := range recon {
		if snap.ignore[r.PID] {
			continue
		}
		fd, mode := splitFD(r.FD)
		rec[strconv.Itoa(r.PID)+" "+fd] = lsofLine{command: r.Command, mode: mode, typ: r.Type, name: normName(r.Type, query.LsofSafe(r.Name)), inode: r.SockInode}
	}
	if query.FDsHeld(db) {
		// Held storage records an fd at the second walk that sees it. An fd
		// the previous checkpoint's real lsof (one walk earlier) did not
		// have is not expected yet.
		real = map[string]lsofLine{}
		for k, r := range all {
			// The same fd number with another inode is another open file
			// (a pidfd has its own inode per process since Linux 6.9).
			if p, ok := prev[k]; ok && p.name == r.name && p.typ == r.typ && p.node == r.node {
				real[k] = r
				continue
			}
			if _, inRecon := rec[k]; inRecon {
				real[k] = r
				continue
			}
			if prev == nil {
				res.Ignored["not judged: first checkpoint (held fds need two walks)"]++
			} else {
				res.Ignored["fds new since the previous walk (held storage starts at the second)"]++
			}
		}
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
			if fdChurn(db, pid, fd, sfd, next, nextAny, window) {
				res.ChurnMissing++
			} else {
				res.Missing++
				res.example("lsof missing pid/fd %s: %s %s %s", key, r.command, r.typ, r.name)
			}
			continue
		}
		res.Matched++
		if r.typ == "sock" && x.inode != 0 && r.node == strconv.FormatInt(x.inode, 10) {
			// lsof found the fd but not the socket in its /proc/net read: the
			// inode is the only thing it shows, and it agrees.
			r.typ, r.name = x.typ, x.name
			res.Ignored["sockets lsof could not resolve (matched by inode)"]++
		}
		pid, fd := keyParts(key)
		res.compare("lsof "+key, []fieldPair{
			{"FD mode", r.mode, x.mode},
			{"TYPE", r.typ, x.typ},
			{"NAME", r.name, x.name},
		}, func() bool { return fdChurn(db, pid, fd, sfd, next, nextAny, window) })
	}
	for key, x := range rec {
		if _, ok := real[key]; ok {
			continue
		}
		pid, fd := keyParts(key)
		if fdChurn(db, pid, fd, sfd, next, nextAny, window) {
			res.ChurnExtra++
		} else {
			res.Extra++
			res.example("lsof extra pid/fd %s: %s %s %s", key, x.command, x.typ, x.name)
		}
	}
	return res, all, nil
}

// ---- output ----

func pct(a, b int) string {
	if b == 0 {
		return "-"
	}
	return fmt.Sprintf("%.2f%%", 100*float64(a)/float64(b))
}

func printResult(w io.Writer, r Result, examples bool) {
	fmt.Fprintf(w, "  %-13s real %6d  clifr %6d  matched %6d (%s, exact %s)  missing %4d  extra %4d  churn: missing %4d extra %4d  gap %dms\n",
		r.Cmd, r.Real, r.Recon, r.Matched, pct(r.Matched, r.Real), pct(r.Exact, r.Matched-r.ChurnChanged), r.Missing, r.Extra, r.ChurnMissing, r.ChurnExtra, r.GapMS)
	if r.ChurnChanged > 0 {
		fmt.Fprintf(w, "                churn-changed (matched, fields changed during the gap): %d\n", r.ChurnChanged)
	}
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
		fmt.Fprintf(w, "                field mismatches: %s\n", strings.Join(parts, ", "))
	}
	if len(r.Ignored) > 0 {
		var parts []string
		for k, v := range r.Ignored {
			parts = append(parts, fmt.Sprintf("%s %d", k, v))
		}
		sort.Strings(parts)
		fmt.Fprintf(w, "                ignored rows: %s\n", strings.Join(parts, ", "))
	}
	if examples {
		for _, e := range r.Examples {
			fmt.Fprintf(w, "                e.g. %s\n", e)
		}
	}
}

// compared lists the commands in report order; laterCommands are those added
// after older recordings were made, listed only when present.
var (
	laterCommands = []string{"free", "ps -ef", "netstat -tanp", "df", "mount", "top -b -n 1 -w 512", "pstree -lpT", "ps auxfwww", "df -al -x autofs", "findmnt", "uname -a", "ss -s", "nstat -zas", "netstat -s", "netstat -s -6", "ip -s -d link", "ip -o addr", "ip -d address", "ip route show table all", "ip -6 route show table all", "ip -4 rule list", "ip -6 rule list", "dmesg", "dmesg -T", "systemctl list-units --no-pager", "systemctl list-units --all --no-pager", "systemctl list-units --failed --no-pager", "ps alxwww", "ps auxZww", "pidstat -h -u -r -d -w -p ALL", "systemd-cgls --no-pager", "systemd-cgls --no-pager -l", "swapon --show", "swapon --summary", "lsmod", "lsblk", "lsblk -f", "mount -l", "ip neigh", "ip -s -s neigh", "ip netns", "lslocks", "ipcs", "ipcs -u", "sysctl -a", "slabtop -o", "numastat", "numastat -m", "conntrack -S", "nfsstat", "mountstats", "mountstats -x"}
	compared      = append(append([]string{"ps aux", "ps -ef", "ss -tanp", "netstat -tanp", "lsof -n -P"}, systemCommands...), "free", "df", "mount", "top -b -n 1 -w 512", "pstree -lpT", "ps auxfwww", "df -al -x autofs", "findmnt", "uname -a", "ss -s", "nstat -zas", "netstat -s", "netstat -s -6", "ip -s -d link", "ip -o addr", "ip -d address", "ip route show table all", "ip -6 route show table all", "ip -4 rule list", "ip -6 rule list", "dmesg", "dmesg -T", "systemctl list-units --no-pager", "systemctl list-units --all --no-pager", "systemctl list-units --failed --no-pager", "ps alxwww", "ps auxZww", "pidstat -h -u -r -d -w -p ALL", "systemd-cgls --no-pager", "systemd-cgls --no-pager -l", "swapon --show", "swapon --summary", "lsmod", "lsblk", "lsblk -f", "mount -l", "ip neigh", "ip -s -s neigh", "ip netns", "lslocks", "ipcs", "ipcs -u", "sysctl -a", "slabtop -o", "numastat", "numastat -m", "conntrack -S", "nfsstat", "mountstats", "mountstats -x")
)

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
	for _, c := range compared {
		if r, ok := rep.Totals[c]; ok {
			printResult(w, r, true)
		}
	}
	fmt.Fprintln(w, "\nNot compared:")
	for _, c := range compared {
		if _, ok := rep.Totals[c]; ok || !slices.Contains(systemCommands, c) && !slices.Contains(laterCommands, c) {
			fmt.Fprintf(w, "  %-13s %s\n", c, rep.IgnoredFields[c])
		}
	}
	fmt.Fprintln(w, "churn = present on one side only, and the database shows it starting or ending between the\n"+
		"checkpoint sample and the sample taken right after the real commands finished. gap = how long after\n"+
		"the sample the real command finished. churn-changed = matched, but the fields differ and the database\n"+
		"shows the entity changing in that window; exact % is of the matched rows that did not change.")
}

// ---- TCP from events (v2) ----

// connChanged: a TCP connection with these addresses opened, closed, ended
// its time-wait (up to lingerSlackMS after the estimate), lost its owner or
// changed state in (from, to].
func connChanged(db *store.DB, key string, from, to int64) bool {
	f := strings.Fields(key)
	la, lp := splitSSAddr(f[0])
	ra, rp := splitSSAddr(f[1])
	return connChangedAddrs(db, la, lp, ra, rp, from, to)
}

func connChangedAddrs(db *store.DB, la string, lp int, ra string, rp int, from, to int64) bool {
	return exists(db, `SELECT 1 FROM tcp_conns c WHERE c.laddr = ?1 AND c.lport = ?2 AND c.raddr = ?3 AND c.rport = ?4
		AND ((c.open_ts > ?5 AND c.open_ts <= ?6) OR (c.close_ts > ?5 AND c.close_ts <= ?6)
		  OR (c.linger_until > ?5 - ?7 AND c.linger_until <= ?6) OR (c.owner_until > ?5 AND c.owner_until <= ?6)
		  OR EXISTS(SELECT 1 FROM tcp_transitions x WHERE x.conn_id = c.id AND x.ts > ?5 AND x.ts <= ?6))`,
		la, lp, ra, rp, from, to, lingerSlackMS)
}

// lingerSlackMS: the end of a time-wait socket is estimated as 60 s after
// the close, a lower bound: the kernel's timer wheel rounds a 60 s timer up
// to its granularity there, 4.1 s at HZ=1000 (2 s at 250, 5.1 s at 100).
const lingerSlackMS = 5500

// compareSSEvents compares the real ss with the reconstruction at the moment
// it started. Churn is what the events show changing while it ran.
func compareSSEvents(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	recon, _, err := query.ConnsAt(db, snap.ts, "tcp", query.SockFilter{})
	if err != nil {
		return res, err
	}
	real := parseSS(snap.output, snap.ignore)
	rec := map[string]query.SSRow{}
	for _, r := range recon {
		rec[r.Local+":"+portStr(r.LPort)+" "+r.Peer+":"+portStr(r.RPort)] = r
	}
	res.Real, res.Recon = len(real), len(rec)
	from, to := snap.ts, snap.endTS
	for key, r := range real {
		x, ok := rec[key]
		if !ok {
			if connChanged(db, key, from, to) {
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
		res.compare("ss "+key, []fieldPair{
			{"State", r.state, x.State},
			{"Recv-Q", r.recvQ, strconv.FormatInt(x.RecvQ, 10)},
			{"Send-Q", r.sendQ, strconv.FormatInt(x.SendQ, 10)},
			{"Process", r.users, strings.Join(us, ",")},
		}, func() bool { return connChanged(db, key, from, to) })
	}
	for key, x := range rec {
		if _, ok := real[key]; ok {
			continue
		}
		if connChanged(db, key, from, to) {
			res.ChurnExtra++
		} else {
			res.Extra++
			res.example("ss extra %s %s", x.State, key)
		}
	}
	return res, nil
}
