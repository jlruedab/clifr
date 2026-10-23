package verify

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/query"
	"clifr/internal/store"
)

// free, ps -ef and netstat -tanp: the reconstruction is printed with the
// same code as clifr's output and both sides are parsed by the same parser.

func init() {
	ignoredFields["free"] = "none; numbers match within 2% (total exactly)"
	ignoredFields["ps -ef"] = "C (derived from TIME, which is compared); the work-item suffix of kernel worker names"
	ignoredFields["netstat -tanp"] = "none"
	ignoredFields["df"] = "none; sizes match within 1% or 1 MiB, Use% within 1"
	ignoredFields["df -al -x autofs"] = ignoredFields["df"]
	ignoredFields["findmnt"] = "none; the whole line (tree, source, type, options)"
	ignoredFields["uname -a"] = "none"
	ignoredFields["ip -s -d link"] = "each interface type's own parameters (bridge, bond, vlan, ...: not reconstructed); counters that moved within 1% or 100 count as churn-changed"
	ignoredFields["ip -d address"] = "each interface type's own parameters; numbers that moved within 1% or 100 count as churn-changed"
	ignoredFields["ip -o addr"] = "none; lifetimes that counted down by up to 5 s count as churn-changed"
	ignoredFields["ip route show table all"] = "none; an expiring route's time left within 5 s"
	ignoredFields["ip -6 route show table all"] = ignoredFields["ip route show table all"]
	ignoredFields["systemctl list-units --no-pager"] = "none"
	ignoredFields["systemctl list-units --all --no-pager"] = "none"
	ignoredFields["systemctl list-units --failed --no-pager"] = "none"
	ignoredFields["dmesg"] = "none"
	ignoredFields["dmesg -T"] = "none"
	ignoredFields["ip -4 rule list"] = "none"
	ignoredFields["ip -6 rule list"] = "none"
	ignoredFields["netstat -s"] = "none; counters that moved within 1% or 10 count as churn-changed"
	ignoredFields["netstat -s -6"] = ignoredFields["netstat -s"]
	ignoredFields["nstat -zas"] = "the rate column (nstat's own history); values that moved within 1% or 10 count as churn-changed"
	ignoredFields["ss -s"] = "none; counts within 5% or 3 (sockets come and go between the sample and the run)"
	ignoredFields["mount"] = "none"
	ignoredFields["pstree -lpT"] = "none; compared: each process's parent and name (which set its place)"
	ignoredFields["ps auxfwww"] = "everything but the tree prefix of COMMAND (the rest is compared by ps aux)"
	ignoredFields["ps alxwww"] = "the work-item suffix of kernel worker names"
	ignoredFields["systemd-cgls --no-pager"] = "none; compared: each process's cgroup and command line, each cgroup's delegation mark and place among the siblings both have"
	ignoredFields["systemd-cgls --no-pager -l"] = ignoredFields["systemd-cgls --no-pager"]
	ignoredFields["ps auxZww"] = "everything but LABEL (the rest is compared by ps aux)"
	ignoredFields["pidstat -h -u -r -d -w -p ALL"] = "CPU (the one the process last ran on changes all the time); the work-item suffix of kernel worker names; averages match within 0.01 or 1%, VSZ and RSS exactly"
	ignoredFields["top -b -n 1 -w 512"] = "%CPU (top measures a fraction of a second, clifr the sample interval), %MEM (derived from RES), " +
		"the %Cpu(s) line (the same reason as %CPU), the first line (compared by uptime); " +
		"the work-item suffix of kernel worker names; task counts within 3, memory within 2%"
}

// ---- free ----

// parseFree reads free's Mem: and Swap: lines as "Mem: used" -> value.
func parseFree(out string) sysTable {
	t := sysTable{}
	var head []string
	for _, line := range strings.Split(out, "\n") {
		fs := strings.Fields(line)
		switch {
		case len(fs) > 0 && fs[0] == "total":
			head = fs
		case len(fs) > 1 && strings.HasSuffix(fs[0], ":") && head != nil:
			row := map[string]string{}
			for i, v := range fs[1:] {
				if i < len(head) {
					row[head[i]] = v
				}
			}
			t[fs[0]] = row
		}
	}
	return t
}

func compareFree(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	spans, err := query.SysSpans(db, query.Window{At: snap.sampleTS}, 0)
	if err != nil || spans[0].To != snap.sampleTS {
		res.example("no system counters at the checkpoint sample")
		return res, nil
	}
	rows, err := query.Free(db, spans)
	if err != nil {
		return res, err
	}
	real := parseFree(snap.output)
	recon := parseFree(render(func(sb *strings.Builder) { query.PrintFree(sb, rows, query.FreeFormat{Unit: "k"}) }))
	res.Real, res.Recon = len(real), len(recon)
	for key, rr := range real {
		sr, ok := recon[key]
		if !ok {
			res.Missing++
			res.example("free %s: not reconstructed", key)
			continue
		}
		res.Matched++
		exact := true
		for col, rv := range rr {
			rel := 0.02
			if col == "total" {
				rel = 0
			}
			if !near(rv, sr[col], rel, 0) {
				exact = false
				res.FieldDiffs[col]++
				if res.FieldDiffs[col] <= 3 {
					res.example("free %s %s: real %q, clifr %q", key, col, rv, sr[col])
				}
			}
		}
		if exact {
			res.Exact++
		}
	}
	for key := range recon {
		if _, ok := real[key]; !ok {
			res.Extra++
		}
	}
	return res, nil
}

// ---- ps -ef ----

type psefLine struct{ uid, ppid, stime, tty, time, cmd string }

// parsePSEF reads UID PID PPID C STIME TTY TIME CMD; CMD is the rest of the
// line, spaces and all.
func parsePSEF(out string) map[int]psefLine {
	m := map[int]psefLine{}
	lines := strings.Split(out, "\n")
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) < 8 {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		cmd := l
		for i := 0; i < 7; i++ {
			cmd = strings.TrimLeft(cmd, " ")
			cmd = cmd[strings.IndexByte(cmd, ' ')+1:]
		}
		m[pid] = psefLine{uid: f[0], ppid: f[2], stime: f[4], tty: f[5], time: f[6], cmd: strings.TrimLeft(cmd, " ")}
	}
	return m
}

func comparePSEF(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	rows, s, err := query.PSAt(db, snap.ts)
	if err != nil {
		return res, err
	}
	next := nextSample(db, s, false)
	real := parsePSEF(snap.output)
	rec := parsePSEF(render(func(sb *strings.Builder) { query.PrintPSFormat(sb, rows, query.PSFull) }))
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
				res.example("ps -ef missing pid %d: %s", pid, r.cmd)
			}
			continue
		}
		res.Matched++
		res.compare("ps -ef pid "+strconv.Itoa(pid), []fieldPair{
			{"UID", r.uid, x.uid}, {"PPID", r.ppid, x.ppid}, {"STIME", r.stime, x.stime},
			{"TTY", r.tty, x.tty}, {"TIME", r.time, x.time}, {"CMD", kworkerBase(r.cmd), kworkerBase(x.cmd)},
		}, func() bool { return false })
	}
	for pid, x := range rec {
		if _, ok := real[pid]; ok {
			continue
		}
		if procChurn(db, pid, s, next) {
			res.ChurnExtra++
		} else {
			res.Extra++
			res.example("ps -ef extra pid %d: %s", pid, x.cmd)
		}
	}
	return res, nil
}

// ---- ps alxwww and ps auxZww ----

// parsePSLong reads F UID PID PPID PRI NI VSZ RSS WCHAN STAT TTY TIME
// COMMAND into the fields by name (COMMAND: the rest of the line).
func parsePSLong(out string) map[int]map[string]string {
	heads := []string{"F", "UID", "PID", "PPID", "PRI", "NI", "VSZ", "RSS", "WCHAN", "STAT", "TTY", "TIME"}
	m := map[int]map[string]string{}
	for _, l := range strings.Split(out, "\n")[1:] {
		f := strings.Fields(l)
		if len(f) <= len(heads) {
			continue
		}
		pid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		row := map[string]string{}
		cmd := l
		for i, h := range heads {
			row[h] = f[i]
			cmd = strings.TrimLeft(cmd, " ")
			cmd = cmd[strings.IndexByte(cmd, ' ')+1:]
		}
		row["COMMAND"] = kworkerBase(strings.TrimLeft(cmd, " "))
		m[pid] = row
	}
	return m
}

// psLabelLine: a label (which may hold spaces: AppArmor's "name (enforce)"),
// then USER, PID, %CPU and %MEM.
var psLabelLine = regexp.MustCompile(`^(.*?)\s+\S+\s+(\d+)\s+[\d.-]+\s+[\d.-]+\s`)

func parsePSLabel(out string) map[int]map[string]string {
	m := map[int]map[string]string{}
	for _, l := range strings.Split(out, "\n")[1:] {
		if g := psLabelLine.FindStringSubmatch(l); g != nil {
			pid, _ := strconv.Atoi(g[2])
			m[pid] = map[string]string{"LABEL": g[1]}
		}
	}
	return m
}

// comparePSFormat compares ps alxwww or ps auxZww with the reconstruction
// in format f, field by field (the fields parse returns).
func comparePSFormat(db *store.DB, snap snapshot, f query.PSFormat, parse func(string) map[int]map[string]string, fields []string) (Result, error) {
	res := newResult(snap.cmd)
	rows, s, err := query.PSAt(db, snap.ts)
	if err != nil {
		return res, err
	}
	next := nextSample(db, s, false)
	real := parse(snap.output)
	rec := parse(render(func(sb *strings.Builder) { query.PrintPSFormat(sb, rows, f) }))
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
				res.example("%s missing pid %d: %v", snap.cmd, pid, r)
			}
			continue
		}
		res.Matched++
		var pairs []fieldPair
		for _, k := range fields {
			pairs = append(pairs, fieldPair{k, r[k], x[k]})
		}
		res.compare(snap.cmd+" pid "+strconv.Itoa(pid), pairs, func() bool { return false })
	}
	for pid, x := range rec {
		if _, ok := real[pid]; ok {
			continue
		}
		if procChurn(db, pid, s, next) {
			res.ChurnExtra++
		} else {
			res.Extra++
			res.example("%s extra pid %d: %v", snap.cmd, pid, x)
		}
	}
	return res, nil
}

// ---- pidstat ----

var pidstatHeads = []string{"UID", "PID", "%usr", "%system", "%guest", "%wait", "%CPU", "CPU", "minflt/s", "majflt/s",
	"VSZ", "RSS", "%MEM", "kB_rd/s", "kB_wr/s", "kB_ccwr/s", "iodelay", "cswch/s", "nvcswch/s"}

// parsePidstat reads pidstat -h -u -r -d -w lines: the time, the columns
// of pidstatHeads, then Command.
func parsePidstat(out string) map[int]map[string]string {
	m := map[int]map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < len(pidstatHeads)+2 || f[0] == "#" || f[0] == "Linux" {
			continue
		}
		pid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		row := map[string]string{"Command": topComm(strings.Join(f[len(pidstatHeads)+1:], " "))}
		for i, h := range pidstatHeads {
			row[h] = f[i+1]
		}
		m[pid] = row
	}
	return m
}

func comparePidstat(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	acts := []int{query.PidCPU, query.PidMem, query.PidIO, query.PidCtx}
	spans, err := query.ProcSpans(db, query.Window{At: snap.ts}, 0)
	if err != nil {
		return res, err
	}
	rows, err := query.Pidstat(db, spans, acts, query.PidstatSelect{All: true})
	if err != nil {
		return res, err
	}
	s := spans[0].To
	next := nextSample(db, s, false)
	real := parsePidstat(snap.output)
	rec := parsePidstat(render(func(sb *strings.Builder) { query.PrintPidstat(sb, rows, acts, true) }))
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
				res.example("pidstat missing pid %d: %v", pid, r["Command"])
			}
			continue
		}
		res.Matched++
		var pairs []fieldPair
		for _, h := range append(pidstatHeads, "Command") {
			a, b := r[h], x[h]
			if h == "CPU" {
				continue
			}
			if strings.Contains(a, ".") { // an average: within 0.01
				fa, ea := strconv.ParseFloat(a, 64)
				fb, eb := strconv.ParseFloat(b, 64)
				// The averages are since boot: on a young system they still
				// move during the gap.
				if tol := max(0.0101, fa/100); ea == nil && eb == nil && fa-fb <= tol && fb-fa <= tol {
					b = a
				}
			}
			pairs = append(pairs, fieldPair{h, a, b})
		}
		res.compare("pidstat pid "+strconv.Itoa(pid), pairs, func() bool { return false })
	}
	for pid, x := range rec {
		if _, ok := real[pid]; ok {
			continue
		}
		if procChurn(db, pid, s, next) {
			res.ChurnExtra++
		} else {
			res.Extra++
			res.example("pidstat extra pid %d: %v", pid, x["Command"])
		}
	}
	return res, nil
}

// ---- systemd-cgls ----

type cglsTree struct {
	procs  map[int][2]string   // pid -> cgroup, command
	groups map[string]string   // path -> "delegated" or ""
	ids    map[string]string   // path -> its "(#ID)" (systemd 252)
	attrs  map[string]string   // path -> its "-> name: value" lines (252)
	kids   map[string][]string // path -> children in printed order
}

var cglsID = regexp.MustCompile(` \(#\d+\)$`)

// parseCgls reads systemd-cgls's tree (ASCII glyphs: "|-", "`-", "| ",
// "  "): each line's depth is its prefix length / 2; a cgroup line holds a
// name (" ..." when delegated), a process line a PID and its command.
func parseCgls(out string) cglsTree {
	t := cglsTree{procs: map[int][2]string{}, groups: map[string]string{"/": ""}, ids: map[string]string{},
		attrs: map[string]string{}, kids: map[string][]string{}}
	stack := []string{"/"} // stack[d]: the cgroup at depth d
	last := ""
	for _, l := range strings.Split(out, "\n") {
		if _, attr, ok := strings.Cut(l, "-> "); ok && !strings.Contains(l, "|-") && !strings.Contains(l, "`-") {
			t.attrs[last] += attr + "\n"
			continue
		}
		i := strings.Index(l, "|-")
		if j := strings.Index(l, "`-"); j >= 0 && (i < 0 || j < i) {
			i = j
		}
		if i < 0 || i%2 != 0 {
			continue
		}
		depth, rest := i/2, l[i+2:]
		if depth+1 > len(stack) {
			continue
		}
		parent := stack[depth]
		if f := strings.Fields(rest); len(f) > 0 {
			if pid, err := strconv.Atoi(f[0]); err == nil && strings.HasPrefix(strings.TrimLeft(rest, " "), f[0]+" ") {
				t.procs[pid] = [2]string{parent, strings.TrimPrefix(strings.TrimLeft(rest, " "), f[0]+" ")}
				continue
			}
		}
		name, mark, id := rest, "", ""
		if m := cglsID.FindString(name); m != "" {
			name, id = strings.TrimSuffix(name, m), m
		}
		if n, ok := strings.CutSuffix(name, " ..."); ok {
			name, mark = n, "delegated"
		}
		name = strings.TrimRight(name, " ") // systemd 249: a space after each name
		p := strings.TrimSuffix(parent, "/") + "/" + name
		t.groups[p], t.ids[p], last = mark, id, p
		t.kids[parent] = append(t.kids[parent], p)
		stack = append(stack[:depth+1], p)
	}
	return t
}

func compareCgls(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	procs, info, s, err := query.CglsAt(db, snap.ts)
	if err != nil {
		return res, err
	}
	full := strings.HasSuffix(snap.cmd, " -l")
	next := nextSample(db, s, false)
	real := parseCgls(snap.output)
	rec := parseCgls(render(func(sb *strings.Builder) {
		query.PrintCgls(sb, procs, info, query.CglsOptions{Full: full, ASCII: true, Columns: 80, Style: query.StyleAt(db, s).SystemdCgls})
	}))
	for pid := range snap.ignore {
		if _, ok := real.procs[pid]; ok {
			res.Ignored["recorder/tool processes"]++
		}
		delete(real.procs, pid)
		delete(rec.procs, pid)
	}
	res.Real, res.Recon = len(real.procs)+len(real.groups), len(rec.procs)+len(rec.groups)
	for pid, r := range real.procs {
		x, ok := rec.procs[pid]
		switch {
		case ok:
			res.Matched++
			res.compare("systemd-cgls pid "+strconv.Itoa(pid), []fieldPair{{"cgroup", r[0], x[0]}, {"command", r[1], x[1]}},
				func() bool { return false })
		case procChurn(db, pid, s, next):
			res.ChurnMissing++
		default:
			res.Missing++
			res.example("systemd-cgls missing pid %d in %s: %s", pid, r[0], r[1])
		}
	}
	for pid, x := range rec.procs {
		if _, ok := real.procs[pid]; !ok {
			if procChurn(db, pid, s, next) {
				res.ChurnExtra++
			} else {
				res.Extra++
				res.example("systemd-cgls extra pid %d in %s: %s", pid, x[0], x[1])
			}
		}
	}
	// Cgroups: the delegation mark, and the place among the siblings both
	// sides list (a cgroup on one side only is churn: its processes came or
	// went, which the process rows count).
	for p, mark := range real.groups {
		x, ok := rec.groups[p]
		if !ok {
			res.ChurnMissing++
			continue
		}
		res.Matched++
		res.compare("systemd-cgls cgroup "+p, []fieldPair{{"delegated", mark, x},
			{"place", placeIn(real, rec, p), placeIn(rec, real, p)},
			{"id", real.ids[p], rec.ids[p]}, {"attributes", real.attrs[p], rec.attrs[p]}}, func() bool { return false })
	}
	for p := range rec.groups {
		if _, ok := real.groups[p]; !ok {
			res.ChurnExtra++
		}
	}
	return res, nil
}

// placeIn is p's place among its siblings in t that other lists too.
func placeIn(t, other cglsTree, p string) string {
	parent := p[:strings.LastIndex(p, "/")]
	if parent == "" {
		parent = "/"
	}
	n := 0
	for _, k := range t.kids[parent] {
		if k == p {
			return strconv.Itoa(n)
		}
		if _, ok := other.groups[k]; ok {
			n++
		}
	}
	return "?"
}

// ---- netstat -tanp ----

type netstatLine struct {
	state, recvQ, sendQ, prog string
	la, ra                    string // ADDR:PORT as printed
}

// parseNetstat reads tcp and tcp6 lines, keyed by "proto local foreign".
// Program names of ignored processes count as "-".
func parseNetstat(out string, ignore map[int]bool) map[string]netstatLine {
	m := map[string]netstatLine{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 6 || (f[0] != "tcp" && f[0] != "tcp6") {
			continue
		}
		x := netstatLine{recvQ: f[1], sendQ: f[2], la: f[3], ra: f[4], state: f[5], prog: "-"}
		if len(f) > 6 {
			x.prog = strings.Join(f[6:], " ")
			if pid, err := strconv.Atoi(strings.SplitN(x.prog, "/", 2)[0]); err == nil && ignore[pid] {
				x.prog = "-"
			}
		}
		m[f[0]+" "+f[3]+" "+f[4]] = x
	}
	return m
}

// netstatChanged: connChanged for netstat's addresses, which show IPv4-mapped
// addresses as IPv4.
func netstatChanged(db *store.DB, x netstatLine, from, to int64) bool {
	la, lp := splitSSAddr(x.la)
	ra, rp := splitSSAddr(x.ra)
	if connChangedAddrs(db, la, lp, ra, rp, from, to) {
		return true
	}
	return !strings.Contains(la, ":") && connChangedAddrs(db, "::ffff:"+la, lp, "::ffff:"+ra, rp, from, to)
}

func compareNetstat(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	rows, _, err := query.ConnsAt(db, snap.ts, "tcp", query.SockFilter{})
	if err != nil {
		return res, err
	}
	progs, err := query.ProgramNames(db, snap.ts)
	if err != nil {
		return res, err
	}
	v := query.NetstatView{All: true, Program: true}
	real := parseNetstat(snap.output, snap.ignore)
	rec := parseNetstat(render(func(sb *strings.Builder) { query.PrintNetstat(sb, rows, v, progs) }), snap.ignore)
	res.Real, res.Recon = len(real), len(rec)
	from, to := snap.ts, snap.endTS
	for key, r := range real {
		x, ok := rec[key]
		if !ok {
			if netstatChanged(db, r, from, to) {
				res.ChurnMissing++
			} else {
				res.Missing++
				res.example("netstat missing %s %s %s", r.state, key, r.prog)
			}
			continue
		}
		res.Matched++
		res.compare("netstat "+key, []fieldPair{
			{"State", r.state, x.state}, {"Recv-Q", r.recvQ, x.recvQ}, {"Send-Q", r.sendQ, x.sendQ},
			{"PID/Program", r.prog, x.prog},
		}, func() bool { return netstatChanged(db, r, from, to) })
	}
	for key, x := range rec {
		if _, ok := real[key]; ok {
			continue
		}
		if netstatChanged(db, x, from, to) {
			res.ChurnExtra++
		} else {
			res.Extra++
			res.example("netstat extra %s %s", x.state, key)
		}
	}
	return res, nil
}

// ---- df ----

type dfLine struct {
	fs, size, used, avail, pct string
	pos                        int
}

// parseDF reads df's default output, keyed by mount point (the rest of the
// line after Use%) and, for df -a, which lists a mount point twice when a
// file system is mounted over another, the file system.
func parseDF(out string, all bool) map[string]dfLine {
	m := map[string]dfLine{}
	for i, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 6 {
			continue
		}
		point := strings.Join(f[5:], " ")
		if all {
			point = f[0] + " " + point
		}
		m[point] = dfLine{fs: f[0], size: f[1], used: f[2], avail: f[3], pct: strings.TrimSuffix(f[4], "%"), pos: len(m)}
	}
	return m
}

func compareDF(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	sel := query.DFSelect{}
	if snap.cmd == "df -al -x autofs" {
		sel = query.DFSelect{All: true, Local: true, Exclude: []string{"autofs"}}
	}
	rows, err := query.DF(db, snap.ts, sel)
	if err != nil {
		return res, err
	}
	real := parseDF(snap.output, sel.All)
	rec := parseDF(render(func(sb *strings.Builder) { query.PrintDF(sb, rows, query.DFFormat{}) }), sel.All)
	res.Real, res.Recon = len(real), len(rec)
	for point, r := range real {
		x, ok := rec[point]
		if !ok {
			res.Missing++
			res.example("df missing %s (%s)", point, r.fs)
			continue
		}
		res.Matched++
		exact := true
		check := func(field, a, b string, ok bool) {
			if !ok {
				exact = false
				res.FieldDiffs[field]++
				if res.FieldDiffs[field] <= 3 {
					res.example("df %s %s: real %q, clifr %q", point, field, a, b)
				}
			}
		}
		check("Filesystem", r.fs, x.fs, r.fs == x.fs)
		for _, f := range []struct{ name, a, b string }{{"1K-blocks", r.size, x.size}, {"Used", r.used, x.used}, {"Available", r.avail, x.avail}} {
			check(f.name, f.a, f.b, near(f.a, f.b, 0.01, 1024))
		}
		check("Use%", r.pct, x.pct, near(r.pct, x.pct, 0, 1))
		if exact {
			res.Exact++
		}
	}
	for point := range rec {
		if _, ok := real[point]; !ok {
			res.Extra++
			res.example("df extra %s", point)
		}
	}
	res.compareOrder("df", rankOf(real), rankOf(rec))
	return res, nil
}

func rankOf[T interface{ position() int }](m map[string]T) map[string]int {
	r := make(map[string]int, len(m))
	for k, v := range m {
		r[k] = v.position()
	}
	return r
}

func (l dfLine) position() int    { return l.pos }
func (l mountLine) position() int { return l.pos }

// compareOrder counts the rows on both sides that are not in the same order:
// among the keys present on both, those whose rank differs.
func (r *Result) compareOrder(cmd string, real, rec map[string]int) {
	var keys []string
	for k := range real {
		if _, ok := rec[k]; ok {
			keys = append(keys, k)
		}
	}
	rank := func(m map[string]int) map[string]int {
		sorted := append([]string(nil), keys...)
		sort.Slice(sorted, func(i, j int) bool { return m[sorted[i]] < m[sorted[j]] })
		out := make(map[string]int, len(sorted))
		for i, k := range sorted {
			out[k] = i
		}
		return out
	}
	a, b := rank(real), rank(rec)
	for _, k := range keys {
		if a[k] != b[k] {
			r.FieldDiffs["order"]++
			if r.FieldDiffs["order"] <= 3 {
				r.example("%s %s: line %d, clifr line %d", cmd, k, a[k]+1, b[k]+1)
			}
		}
	}
}

// ---- mount ----

type mountLine struct {
	fstype, opts, label string
	pos                 int
}

var mountRe = regexp.MustCompile(`^(.*) on (.*) type (\S+) \((.*)\)(?: \[(.*)\])?$`)

// parseMount reads mount's lines, keyed by source and mount point (and the
// occurrence, for the same pair mounted twice).
func parseMount(out string) map[string]mountLine {
	m := map[string]mountLine{}
	for _, l := range strings.Split(out, "\n") {
		g := mountRe.FindStringSubmatch(l)
		if g == nil {
			continue
		}
		key := g[1] + " on " + g[2]
		for n := 2; ; n++ {
			if _, dup := m[key]; !dup {
				break
			}
			key = g[1] + " on " + g[2] + " #" + strconv.Itoa(n)
		}
		m[key] = mountLine{fstype: g[3], opts: g[4], label: g[5], pos: len(m)}
	}
	return m
}

func compareMount(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	rows, err := query.MountsAt(db, snap.ts)
	if err != nil {
		return res, err
	}
	if snap.cmd == "mount -l" {
		if err := query.AddMountLabels(db, snap.ts, rows); err != nil {
			res.example("%s: %v", snap.cmd, err)
			return res, nil
		}
	}
	real := parseMount(snap.output)
	rec := parseMount(render(func(sb *strings.Builder) { query.PrintMount(sb, rows) }))
	res.Real, res.Recon = len(real), len(rec)
	for key, r := range real {
		x, ok := rec[key]
		if !ok {
			res.Missing++
			res.example("mount missing %s", key)
			continue
		}
		res.Matched++
		res.compare("mount "+key, []fieldPair{{"type", r.fstype, x.fstype}, {"options", r.opts, x.opts}, {"label", r.label, x.label}},
			func() bool { return false })
	}
	for key := range rec {
		if _, ok := real[key]; !ok {
			res.Extra++
			res.example("mount extra %s", key)
		}
	}
	res.compareOrder("mount", rankOf(real), rankOf(rec))
	return res, nil
}

// ---- top -b -n 1 ----

type topLine struct{ user, pr, ni, virt, res, shr, s, time, cmd string }

// parseTop reads top's summary (Tasks, MiB Mem, MiB Swap as "Tasks: total"
// -> value) and its process lines by PID. COMMAND is the rest of the line.
func parseTop(out string) (sysTable, map[int]topLine) {
	sum, procs := sysTable{}, map[int]topLine{}
	numRe := regexp.MustCompile(`([\d.]+) ([a-z/]+(?: Mem)?)`)
	inProcs := false
	for _, l := range strings.Split(out, "\n") {
		for _, head := range []string{"Tasks:", "MiB Mem :", "MiB Swap:"} {
			if rest, ok := strings.CutPrefix(l, head); ok {
				row := map[string]string{}
				for _, m := range numRe.FindAllStringSubmatch(rest, -1) {
					row[m[2]] = m[1]
				}
				sum[head] = row
			}
		}
		f := strings.Fields(l)
		if len(f) > 0 && f[0] == "PID" {
			inProcs = true
			continue
		}
		if !inProcs || len(f) < 12 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		cmd := l
		for i := 0; i < 11; i++ {
			cmd = strings.TrimLeft(cmd, " ")
			cmd = cmd[strings.IndexByte(cmd, ' ')+1:]
		}
		procs[pid] = topLine{user: f[1], pr: f[2], ni: f[3], virt: f[4], res: f[5], shr: f[6], s: f[7], time: f[10],
			cmd: strings.TrimLeft(cmd, " ")}
	}
	return sum, procs
}

// topComm drops a kernel worker's work item, as kworkerBase does for ps:
// "kworker/u88:1-i915" -> "kworker/u88:1".
func topComm(c string) string {
	if strings.HasPrefix(c, "kworker/") {
		if i := strings.IndexAny(c, "-+"); i > 0 {
			return c[:i]
		}
	}
	return c
}

func compareTop(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	rep, err := query.TopAt(db, snap.ts)
	if err != nil {
		return res, err
	}
	next := nextSample(db, rep.SampleTS, false)
	realSum, real := parseTop(snap.output)
	recSum, rec := parseTop(render(func(sb *strings.Builder) { query.PrintTop(sb, rep, query.TopFormat{Width: 512}) }))
	for pid := range snap.ignore {
		if _, ok := real[pid]; ok {
			res.Ignored["recorder/tool processes"]++
		}
		delete(real, pid)
		delete(rec, pid)
	}
	// The summary: memory within 2% (totals exactly); the task counts within
	// 2% or 3 (processes start and end between the sample and the run).
	for head, rr := range realSum {
		for col, rv := range rr {
			rel, abs := 0.02, 0.0
			switch {
			case col == "total" && head != "Tasks:":
				rel = 0
			case head == "Tasks:":
				abs = 3
			}
			if !near(rv, recSum[head][col], rel, abs) {
				res.FieldDiffs[head+" "+col]++
				res.example("top %s %s: real %q, clifr %q", head, col, rv, recSum[head][col])
			}
		}
	}
	res.Real, res.Recon = len(real), len(rec)
	for pid, r := range real {
		x, ok := rec[pid]
		if !ok {
			if procChurn(db, pid, rep.SampleTS, next) {
				res.ChurnMissing++
			} else {
				res.Missing++
				res.example("top missing pid %d: %s", pid, r.cmd)
			}
			continue
		}
		res.Matched++
		fields := []fieldPair{
			{"USER", r.user, x.user}, {"PR", r.pr, x.pr}, {"NI", r.ni, x.ni}, {"VIRT", r.virt, x.virt},
			{"RES", r.res, x.res}, {"S", r.s, x.s}, {"TIME+", r.time, x.time}, {"COMMAND", topComm(r.cmd), topComm(x.cmd)},
		}
		if x.shr != "-" { // recorded since schema 8
			fields = append(fields, fieldPair{"SHR", r.shr, x.shr})
		}
		res.compare("top pid "+strconv.Itoa(pid), fields, func() bool { return false })
	}
	for pid, x := range rec {
		if _, ok := real[pid]; ok {
			continue
		}
		if procChurn(db, pid, rep.SampleTS, next) {
			res.ChurnExtra++
		} else {
			res.Extra++
			res.example("top extra pid %d: %s", pid, x.cmd)
		}
	}
	return res, nil
}

// ---- pstree -lpT and ps auxfwww: the tree ----

var pstreeTok = regexp.MustCompile(`([^\s(]|\([^\d])*\((\d+)\)`)

// parsePstree reads each process's parent and name from pstree -p's layout:
// a child's name starts 3 columns ("---", "-+-", " |-", " `-") after its
// parent's ends, and the parent is the latest process ending in that column.
func parsePstree(out string) (parent map[int]int, name map[int]string) {
	parent, name = map[int]int{}, map[int]string{}
	endAt := map[int]int{} // column after a name -> its pid
	for _, l := range strings.Split(out, "\n") {
		for _, m := range pstreeTok.FindAllStringSubmatchIndex(l, -1) {
			start, end := m[0], m[1]
			for start < end && strings.ContainsRune("-+|` ", rune(l[start])) {
				start++
			}
			pid, _ := strconv.Atoi(l[m[4]:m[5]])
			if p, ok := endAt[start-3]; ok && start > 0 {
				parent[pid] = p
			} else {
				parent[pid] = 0
			}
			name[pid] = l[start : m[4]-1]
			endAt[end] = pid
		}
	}
	return parent, name
}

var forestPrefix = regexp.MustCompile(`^(?: \\_ | \|  |    )*`)

// parseForest reads ps auxf: each PID's tree prefix, kernel worker names
// cut to their base (the prefix is the part of COMMAND before the name).
func parseForest(out string) map[int]string {
	m := map[int]string{}
	for _, l := range strings.Split(out, "\n")[1:] {
		f := strings.Fields(l)
		if len(f) < 11 {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		cmd := l
		for i := 0; i < 10; i++ {
			cmd = strings.TrimLeft(cmd, " ")
			cmd = cmd[strings.IndexByte(cmd, ' ')+1:]
		}
		m[pid] = forestPrefix.FindString(cmd)
	}
	return m
}

// compareTree compares pstree -lpT (each process's parent and name) or ps
// auxfwww (each process's tree prefix).
func compareTree(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	rows, s, err := query.PSAt(db, snap.ts)
	if err != nil {
		return res, err
	}
	next := nextSample(db, s, false)
	real, rec := map[int]string{}, map[int]string{}
	if snap.cmd == "pstree -lpT" {
		lines, _ := query.Pstree(rows, query.PstreeFormat{Root: 1, Long: true})
		rp, rn := parsePstree(snap.output)
		cp, cn := parsePstree(strings.Join(lines, "\n"))
		// The parent and the name, which sets the order among siblings: a
		// process that renamed itself after the sample counts once, not
		// for every sibling it moved past.
		for pid, p := range rp {
			real[pid] = fmt.Sprintf("parent %d, name %s", p, rn[pid])
		}
		for pid, p := range cp {
			rec[pid] = fmt.Sprintf("parent %d, name %s", p, cn[pid])
		}
	} else {
		real = parseForest(snap.output)
		rec = parseForest(render(func(sb *strings.Builder) { query.PrintPS(sb, query.PSForest(rows)) }))
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
				res.example("%s missing pid %d", snap.cmd, pid)
			}
			continue
		}
		res.Matched++
		res.compare(snap.cmd+" pid "+strconv.Itoa(pid), []fieldPair{{"TREE", r, x}},
			func() bool { return false })
	}
	for pid := range rec {
		if _, ok := real[pid]; !ok {
			if procChurn(db, pid, s, next) {
				res.ChurnExtra++
			} else {
				res.Extra++
				res.example("%s extra pid %d", snap.cmd, pid)
			}
		}
	}
	return res, nil
}

// ---- findmnt ----

// parseFindmnt reads findmnt's lines keyed by TARGET and SOURCE (a point
// can hold a stack of mounts); the value is the whole line, tree included.
func parseFindmnt(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n")[1:] {
		f := strings.Fields(strings.TrimLeft(l, "|`- "))
		if len(f) < 3 {
			continue
		}
		m[f[0]+" "+f[1]] = strings.TrimRight(l, " ")
	}
	return m
}

func compareFindmnt(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	rows, err := query.Findmnt(db, snap.ts, false)
	if err != nil {
		return res, err
	}
	real := parseFindmnt(snap.output)
	rec := parseFindmnt(render(func(sb *strings.Builder) { query.PrintFindmnt(sb, rows) }))
	res.Real, res.Recon = len(real), len(rec)
	for k, r := range real {
		x, ok := rec[k]
		if !ok {
			res.Missing++
			res.example("findmnt missing %s", k)
			continue
		}
		res.Matched++
		res.compare("findmnt "+k, []fieldPair{{"LINE", r, x}}, func() bool { return false })
	}
	for k := range rec {
		if _, ok := real[k]; !ok {
			res.Extra++
			res.example("findmnt extra %s", k)
		}
	}
	return res, nil
}

// ---- uname -a, ss -s ----

// compareUname compares uname -a word by word (the kernel version holds
// spaces, so the line as a whole).
func compareUname(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	at := func(k string) string { return query.MetaAt(db, k, snap.ts) }
	m := at("uname_machine")
	rec := strings.Join([]string{at("uname_sysname"), query.HostnameAt(db, snap.ts), at("uname_release"), at("uname_version"), m, m, m, "GNU/Linux"}, " ")
	real := strings.TrimSpace(snap.output)
	res.Real, res.Recon, res.Matched = 1, 1, 1
	res.compare("uname -a", []fieldPair{{"LINE", real, rec}}, func() bool { return false })
	return res, nil
}

var ssCountRe = regexp.MustCompile(`([A-Za-z]+)[ :\t]+(\d+)`)

// parseSSSummary reads ss -s as "TCP: estab" -> value and "UDP\tIP" -> value.
func parseSSSummary(out string) sysTable {
	t := sysTable{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) == 2 && f[0] == "Total:":
			t["Total"] = map[string]string{"": f[1]}
		case len(f) > 2 && f[0] == "TCP:":
			row := map[string]string{"": f[1]}
			for _, m := range ssCountRe.FindAllStringSubmatch(strings.Join(f[2:], " "), -1) {
				row[m[1]] = m[2]
			}
			t["TCP:"] = row
		case len(f) == 4 && f[0] != "Transport":
			t[f[0]] = map[string]string{"Total": f[1], "IP": f[2], "IPv6": f[3]}
		}
	}
	return t
}

func compareSSSummary(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	s, err := query.SSSummaryAt(db, snap.ts)
	if err != nil {
		res.example("ss -s: %v", err)
		return res, nil
	}
	real := parseSSSummary(snap.output)
	rec := parseSSSummary(render(func(sb *strings.Builder) { query.PrintSSSummary(sb, s) }))
	res.Real, res.Recon = len(real), len(rec)
	for key, rr := range real {
		sr, ok := rec[key]
		if !ok {
			res.Missing++
			continue
		}
		res.Matched++
		exact := true
		for col, rv := range rr {
			if !near(rv, sr[col], 0.05, 3) {
				exact = false
				res.FieldDiffs[key+" "+col]++
				res.example("ss -s %s %s: real %q, clifr %q", key, col, rv, sr[col])
			}
		}
		if exact {
			res.Exact++
		}
	}
	return res, nil
}

// ---- nstat -zas ----

// parseNstat reads nstat's counters by name, with their place.
func parseNstat(out string) map[string]dfLine {
	m := map[string]dfLine{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 3 && !strings.HasPrefix(f[0], "#") {
			m[f[0]] = dfLine{size: f[1], pos: len(m)}
		}
	}
	return m
}

func compareNstat(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	rows, _, _, err := query.Nstat(db, query.Window{At: snap.ts}, true)
	if err != nil {
		res.example("nstat: %v", err)
		return res, nil
	}
	real := parseNstat(snap.output)
	rec := parseNstat(render(func(sb *strings.Builder) { query.PrintNstat(sb, rows) }))
	res.Real, res.Recon = len(real), len(rec)
	for name, r := range real {
		x, ok := rec[name]
		if !ok {
			res.Missing++
			res.example("nstat missing %s", name)
			continue
		}
		res.Matched++
		// Counters keep moving between the sample and the run.
		res.compare("nstat "+name, []fieldPair{{"value", r.size, x.size}}, func() bool { return near(r.size, x.size, 0.01, 10) })
	}
	for name := range rec {
		if _, ok := real[name]; !ok {
			res.Extra++
			res.example("nstat extra %s", name)
		}
	}
	res.compareOrder("nstat", rankOf(real), rankOf(rec))
	return res, nil
}

// ---- netstat -s ----

var numRe = regexp.MustCompile(`\d+`)

// compareNetstatStats compares netstat -s line by line: the same sentence,
// and its numbers within 1% or 10 (counters keep moving between the sample
// and the run).
func compareNetstatStats(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	text, _, err := query.NetstatStats(db, snap.ts, query.NetstatStatsOptions{V6: strings.HasSuffix(snap.cmd, "-6")})
	if err != nil {
		res.example("%s: %v", snap.cmd, err)
		return res, nil
	}
	lines := func(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") }
	real, rec := lines(snap.output), lines(text)
	res.Real, res.Recon = len(real), len(rec)
	key := func(l string) string { return numRe.ReplaceAllString(l, "N") }
	recAt := map[string][]string{} // sentence -> lines, in order
	for _, l := range rec {
		recAt[key(l)] = append(recAt[key(l)], l)
	}
	for _, r := range real {
		k := key(r)
		xs := recAt[k]
		if len(xs) == 0 {
			res.Missing++
			res.example("%s missing %q", snap.cmd, strings.TrimSpace(r))
			continue
		}
		x := xs[0]
		recAt[k] = xs[1:]
		res.Matched++
		rn, xn := numRe.FindAllString(r, -1), numRe.FindAllString(x, -1)
		close := true
		for i := range rn {
			if i < len(xn) && !near(rn[i], xn[i], 0.01, 10) {
				close = false
			}
		}
		res.compare(snap.cmd+" "+strings.TrimSpace(k), []fieldPair{{"value", r, x}}, func() bool { return close })
	}
	for _, xs := range recAt {
		for _, x := range xs {
			res.Extra++
			res.example("%s extra %q", snap.cmd, strings.TrimSpace(x))
		}
	}
	return res, nil
}

// ---- ip -s -d link ----

var linkHead = regexp.MustCompile(`^\d+: ([^:@ ]+)`)

// parseIPLink splits ip link's output into one block of lines per interface.
func parseIPLink(out string) map[string][]string {
	m := map[string][]string{}
	var cur string
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if h := linkHead.FindStringSubmatch(l); h != nil {
			cur = h[1]
		}
		if cur != "" {
			m[cur] = append(m[cur], strings.TrimRight(l, " "))
		}
	}
	return m
}

// kindLine drops an interface type's own parameters, which clifr does not
// reconstruct: "    bridge forward_delay 1500 ... addrgenmode eui64 ..." ->
// "    bridge addrgenmode eui64 ...".
func kindLine(l string) string {
	f := strings.Fields(l)
	if !strings.HasPrefix(l, "    ") || len(f) < 2 || strings.HasPrefix(f[0], "link/") || f[0] == "RX:" || f[0] == "TX:" ||
		f[0] == "altname" || f[0] == "alias" || strings.Contains(f[0], "errors") {
		return l
	}
	for _, k := range []string{" addrgenmode ", " numtxqueues "} {
		if i := strings.Index(l, k); i > 0 {
			return "    " + f[0] + l[i:]
		}
	}
	return "    " + f[0]
}

// compareIPLink compares ip -s -d link or ip -d address interface by
// interface.
func compareIPLink(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	links, _, err := query.LinksAt(db, snap.ts)
	if err != nil {
		res.example("%s: %v", snap.cmd, err)
		return res, nil
	}
	var addrs []store.AddrRow
	if snap.cmd == "ip -d address" {
		if addrs, err = query.AddrsAt(db, snap.ts); err != nil {
			res.example("%s: %v", snap.cmd, err)
			return res, nil
		}
	}
	real := parseIPLink(snap.output)
	rec := parseIPLink(render(func(sb *strings.Builder) {
		if snap.cmd == "ip -d address" {
			query.PrintIPAddr(sb, links, addrs, query.IPAddrOptions{Details: true})
		} else {
			query.PrintIPLink(sb, links, query.IPLinkOptions{Stats: 1, Details: true})
		}
	}))
	res.Real, res.Recon = len(real), len(rec)
	for name, rl := range real {
		xl, ok := rec[name]
		if !ok {
			res.Missing++
			res.example("ip link missing %s", name)
			continue
		}
		res.Matched++
		var fields []fieldPair
		close := true
		for i := 0; i < len(rl) || i < len(xl); i++ {
			var r, x string
			if i < len(rl) {
				r = kindLine(rl[i])
			}
			if i < len(xl) {
				x = kindLine(xl[i])
			}
			fields = append(fields, fieldPair{fmt.Sprintf("line %d", i+1), r, x})
			if numRe.ReplaceAllString(r, "N") != numRe.ReplaceAllString(x, "N") {
				close = false
				continue
			}
			rn, xn := numRe.FindAllString(r, -1), numRe.FindAllString(x, -1)
			for j := range rn {
				if !near(rn[j], xn[j], 0.01, 100) {
					close = false
				}
			}
		}
		res.compare(snap.cmd+" "+name, fields, func() bool { return close })
	}
	for name := range rec {
		if _, ok := real[name]; !ok {
			res.Extra++
			res.example("ip link extra %s", name)
		}
	}
	return res, nil
}

// compareIPAddrOneLine compares ip -o addr line by line, keyed by interface,
// family and address; lifetimes may have counted down a little.
func compareIPAddrOneLine(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	links, _, err := query.LinksAt(db, snap.ts)
	if err != nil {
		res.example("%s: %v", snap.cmd, err)
		return res, nil
	}
	addrs, err := query.AddrsAt(db, snap.ts)
	if err != nil {
		res.example("%s: %v", snap.cmd, err)
		return res, nil
	}
	parse := func(out string) map[string]string {
		m := map[string]string{}
		for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
			if f := strings.Fields(l); len(f) >= 4 {
				m[f[1]+" "+f[2]+" "+f[3]] = strings.TrimRight(l, " ")
			}
		}
		return m
	}
	real := parse(snap.output)
	rec := parse(render(func(sb *strings.Builder) { query.PrintIPAddr(sb, links, addrs, query.IPAddrOptions{OneLine: true}) }))
	res.Real, res.Recon = len(real), len(rec)
	for k, r := range real {
		x, ok := rec[k]
		if !ok {
			res.Missing++
			res.example("%s missing %s", snap.cmd, k)
			continue
		}
		res.Matched++
		close := numRe.ReplaceAllString(r, "N") == numRe.ReplaceAllString(x, "N")
		rn, xn := numRe.FindAllString(r, -1), numRe.FindAllString(x, -1)
		for i := range rn {
			if close && !near(rn[i], xn[i], 0, 5) {
				close = false
			}
		}
		res.compare(snap.cmd+" "+k, []fieldPair{{"line", r, x}}, func() bool { return close })
	}
	for k := range rec {
		if _, ok := real[k]; !ok {
			res.Extra++
			res.example("%s extra %s", snap.cmd, k)
		}
	}
	return res, nil
}

// ---- ip route show table all, ip rule list ----

var expiresRe = regexp.MustCompile(`expires (\d+)sec`)

// compareIPRouting compares routes or rules line by line (an expiring
// route's time left within 5 s) and in order.
func compareIPRouting(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	kind, family := "route", 0
	if strings.Contains(snap.cmd, " rule") {
		kind, family = "rule", 2
	}
	if strings.Contains(snap.cmd, "-6") {
		family = 10
	}
	rows, err := query.RoutingAt(db, snap.ts, kind)
	if err != nil {
		res.example("%s: %v", snap.cmd, err)
		return res, nil
	}
	names := map[int]string{}
	if links, _, err := query.LinksAt(db, snap.ts); err == nil {
		for _, l := range links {
			names[l.Index] = l.Name
		}
	}
	text := render(func(sb *strings.Builder) {
		if kind == "route" {
			query.PrintIPRoute(sb, rows, query.IPRouteOptions{Family: family}, func(i int) string {
				if n, ok := names[i]; ok {
					return n
				}
				return fmt.Sprintf("if%d", i)
			}, snap.ts)
		} else {
			query.PrintIPRule(sb, rows, family, false)
		}
	})
	index := func(out string) (map[string]int, map[string]string) {
		at, line := map[string]int{}, map[string]string{}
		for i, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
			if l = strings.TrimRight(l, " "); l == "" {
				continue
			}
			k := expiresRe.ReplaceAllString(l, "expires N")
			for n := 2; ; n++ { // the same line twice: keep both
				if _, dup := at[k]; !dup {
					break
				}
				k = fmt.Sprintf("%s #%d", expiresRe.ReplaceAllString(l, "expires N"), n)
			}
			at[k], line[k] = i, l
		}
		return at, line
	}
	ra, rl := index(snap.output)
	xa, xl := index(text)
	res.Real, res.Recon = len(ra), len(xa)
	var common []string
	for k, r := range rl {
		x, ok := xl[k]
		if !ok {
			res.Missing++
			res.example("%s missing %q", snap.cmd, r)
			continue
		}
		res.Matched++
		common = append(common, k)
		rm, xm := expiresRe.FindStringSubmatch(r), expiresRe.FindStringSubmatch(x)
		close := rm == nil || near(rm[1], xm[1], 0, 5)
		res.compare(snap.cmd, []fieldPair{{"line", r, x}}, func() bool { return close })
	}
	for k, x := range xl {
		if _, ok := rl[k]; !ok {
			res.Extra++
			res.example("%s extra %q", snap.cmd, x)
		}
	}
	// The order of the lines both have.
	sortBy := func(pos map[string]int) []string {
		s := append([]string(nil), common...)
		sort.Slice(s, func(i, j int) bool { return pos[s[i]] < pos[s[j]] })
		return s
	}
	ro, xo := sortBy(ra), sortBy(xa)
	for i := range ro {
		if ro[i] != xo[i] {
			res.FieldDiffs["order"]++
			res.example("%s order: real %q, clifr %q at place %d", snap.cmd, rl[ro[i]], xl[xo[i]], i+1)
			break
		}
	}
	return res, nil
}

// ---- dmesg, dmesg -T ----

// compareDmesg compares the kernel log line by line and in order.
func compareDmesg(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	recs, err := query.KmsgAt(db, snap.ts)
	if err != nil {
		res.example("%s: %v", snap.cmd, err)
		return res, nil
	}
	st := query.StyleAt(db, snap.ts)
	text := render(func(sb *strings.Builder) {
		query.PrintDmesg(sb, recs, query.DmesgOptions{Ctime: strings.Contains(snap.cmd, "-T"), ASCII: true}, st) // LC_ALL=C
	})
	compareLines(&res, snap.cmd, snap.output, text)
	return res, nil
}

// compareLines matches the lines of two outputs (a line repeated counts
// each time) and checks the order of those both have.
func compareLines(res *Result, cmd, real, recon string) {
	index := func(out string) (map[string]int, []string) {
		at := map[string]int{}
		var keys []string
		for i, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
			if l == "" {
				continue
			}
			k := l
			for n := 2; ; n++ {
				if _, dup := at[k]; !dup {
					break
				}
				k = fmt.Sprintf("%s #%d", l, n)
			}
			at[k] = i
			keys = append(keys, k)
		}
		return at, keys
	}
	ra, rk := index(real)
	xa, xk := index(recon)
	res.Real, res.Recon = len(rk), len(xk)
	var common []string
	for _, k := range rk {
		if _, ok := xa[k]; ok {
			res.Matched++
			res.compare(cmd, []fieldPair{{"line", k, k}}, func() bool { return true })
			common = append(common, k)
		} else {
			res.Missing++
			res.example("%s missing %q", cmd, k)
		}
	}
	for _, k := range xk {
		if _, ok := ra[k]; !ok {
			res.Extra++
			res.example("%s extra %q", cmd, k)
		}
	}
	xo := append([]string(nil), common...)
	sort.Slice(xo, func(i, j int) bool { return xa[xo[i]] < xa[xo[j]] })
	for i := range common {
		if common[i] != xo[i] {
			res.FieldDiffs["order"]++
			res.example("%s order: real %q, clifr %q at place %d", cmd, common[i], xo[i], i+1)
			break
		}
	}
}

// ---- systemctl list-units ----

// compareListUnits compares systemctl list-units line by line and in order.
func compareListUnits(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	units, err := query.UnitsAt(db, snap.ts)
	if err != nil {
		res.example("%s: %v", snap.cmd, err)
		return res, nil
	}
	// The captures run with LC_ALL=C.
	o := query.ListUnitsOptions{All: strings.Contains(snap.cmd, "--all"), ASCII: true}
	if strings.Contains(snap.cmd, "--failed") {
		o.States = []string{"failed"}
	}
	text := render(func(sb *strings.Builder) { query.PrintListUnits(sb, units, o, query.StyleAt(db, snap.ts)) })
	compareLines(&res, snap.cmd, snap.output, text)
	return res, nil
}

// ---- swapon, lsmod (snapshots) ----

// compareSnapshotTool compares the commands printed from the snapshots
// table line by line.
func compareSnapshotTool(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	var text string
	var err error
	switch snap.cmd {
	case "lsmod":
		var mods []query.Module
		if mods, err = query.ModulesAt(db, snap.ts); err == nil {
			text = render(func(sb *strings.Builder) { query.PrintLsmod(sb, mods) })
		}
	default:
		var swaps []query.Swap
		var raw []string
		if swaps, raw, err = query.SwapsAt(db, snap.ts); err == nil {
			text = render(func(sb *strings.Builder) {
				if snap.cmd == "swapon --summary" {
					query.PrintSwapSummary(sb, swaps, raw, query.StyleAt(db, snap.ts).SwapSummaryOwn)
				} else {
					query.PrintSwapon(sb, swaps, query.SwapColumns, false, false, false)
				}
			})
		}
	}
	if err != nil {
		res.example("%s: %v", snap.cmd, err)
		return res, nil
	}
	compareLines(&res, snap.cmd, snap.output, text)
	return res, nil
}

// ---- lsblk ----

// compareLsblk compares lsblk [-f] line by line (the captures run with
// LC_ALL=C: ASCII tree glyphs).
func compareLsblk(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	roots, err := query.LsblkAt(db, snap.ts)
	if err != nil {
		res.example("%s: %v", snap.cmd, err)
		return res, nil
	}
	o := query.LsblkOptions{FS: snap.cmd == "lsblk -f", V232: query.StyleAt(db, snap.ts).LsblkV232, ASCII: true}
	text := render(func(sb *strings.Builder) { query.PrintLsblk(sb, roots, o) })
	compareLines(&res, snap.cmd, snap.output, text)
	return res, nil
}
