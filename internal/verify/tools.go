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
	ignoredFields["nstat -zas"] = "the rate column (nstat's own history); values that moved within 1% or 10 count as churn-changed"
	ignoredFields["ss -s"] = "none; counts within 5% or 3 (sockets come and go between the sample and the run)"
	ignoredFields["mount"] = "none"
	ignoredFields["pstree -lpT"] = "none; compared: each process's parent and name (which set its place)"
	ignoredFields["ps auxfwww"] = "everything but the tree prefix of COMMAND (the rest is compared by ps aux)"
	ignoredFields["top -b -n 1 -w 512"] = "%CPU (top measures a fraction of a second, clifr the sample interval), %MEM (derived from RES), " +
		"SHR (not recorded), the %Cpu(s) line (the same reason as %CPU), the first line (compared by uptime); " +
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
	fstype, opts string
	pos          int
}

var mountRe = regexp.MustCompile(`^(.*) on (.*) type (\S+) \((.*)\)$`)

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
		m[key] = mountLine{fstype: g[3], opts: g[4], pos: len(m)}
	}
	return m
}

func compareMount(db *store.DB, snap snapshot) (Result, error) {
	res := newResult(snap.cmd)
	rows, err := query.MountsAt(db, snap.ts)
	if err != nil {
		return res, err
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
		res.compare("mount "+key, []fieldPair{{"type", r.fstype, x.fstype}, {"options", r.opts, x.opts}},
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

type topLine struct{ user, pr, ni, virt, res, s, time, cmd string }

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
		procs[pid] = topLine{user: f[1], pr: f[2], ni: f[3], virt: f[4], res: f[5], s: f[7], time: f[10],
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
		res.compare("top pid "+strconv.Itoa(pid), []fieldPair{
			{"USER", r.user, x.user}, {"PR", r.pr, x.pr}, {"NI", r.ni, x.ni}, {"VIRT", r.virt, x.virt},
			{"RES", r.res, x.res}, {"S", r.s, x.s}, {"TIME+", r.time, x.time}, {"COMMAND", topComm(r.cmd), topComm(x.cmd)},
		}, func() bool { return false })
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
	rec := strings.Join([]string{at("uname_sysname"), at("hostname"), at("uname_release"), at("uname_version"), m, m, m, "GNU/Linux"}, " ")
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
