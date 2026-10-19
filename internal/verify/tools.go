package verify

import (
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
