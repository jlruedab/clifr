//go:build truth

// Package truth runs clifrd against scripted activity whose details the
// test knows exactly, then counts how much of it the recording has: found /
// expected for every check. As root:
//
//	sudo env PATH=$PATH HOME=$HOME go test -tags truth -count=1 -timeout 30m -v ./test/truth -scale full
//
// Scenarios (full scale; -scale small, the default, is a tenth and takes about 5 minutes):
//   - 10,000 TCP connections living 5-200 ms: owner, peer and duration of both ends
//   - 5,000 processes shorter than 100 ms: full command lines and exit codes
//   - a server rejecting with RST, and connects to a closed port: resets counted
//   - an OOM kill in a memory.max cgroup: clifr oom shows it with the RSS before the kill
//   - a tmpfs mounted, remounted read-only, unmounted and mounted again
//   - a deleted file held open for 10 minutes: clifr lsof at moments inside and after
//
// The full scale records with the recorder's default settings. Results go to
// bench/results/truth-<scale>-<time>/ (truth.md, truth.json, the recorder log,
// clifr stats and the data directory).
package truth

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/duck"
)

var (
	scaleFlag = flag.String("scale", "small", "small (about 5 minutes) or full (about 14 minutes, default recorder settings)")
	outFlag   = flag.String("out", "", "results directory (default bench/results/truth-<scale>-<time>)")
)

type scale struct {
	conns, connWorkers int
	procs, procWorkers int
	resets             int
	hold, after        time.Duration // the deleted file: held this long; recording continues this long after
	recorder           []string      // extra clifrd flags
}

var scales = map[string]scale{
	"small": {conns: 1000, connWorkers: 50, procs: 500, procWorkers: 8, resets: 100,
		hold: 150 * time.Second, after: 45 * time.Second,
		recorder: []string{"--interval", "5s", "--fd-interval", "15s", "--keyframe-interval", "30s", "--flush-interval", "30s"}},
	"full": {conns: 10000, connWorkers: 100, procs: 5000, procWorkers: 8, resets: 500,
		hold: 10 * time.Minute, after: 150 * time.Second},
}

const (
	oomLimit    = 96 << 20 // memory.max of the OOM cgroup
	durTolMS    = 20       // a recorded duration this close to the measured one counts as right
	timeLayout  = "2006-01-02 15:04:05"
	longCmdline = 1024 // the eBPF exec event keeps this many bytes; longer ones are read from /proc
)

// check is one row of the result.
type check struct {
	Scenario string `json:"scenario"`
	Check    string `json:"check"`
	Found    int    `json:"found"`
	Expected int    `json:"expected"`
	Note     string `json:"note,omitempty"`
}

type results struct {
	Scale  string  `json:"scale"`
	Start  string  `json:"start"`
	End    string  `json:"end"`
	Kernel string  `json:"kernel"`
	CPUs   int     `json:"cpus"`
	Checks []check `json:"checks"`
}

func (r *results) add(scenario, name string, found, expected int, note string, args ...any) {
	r.Checks = append(r.Checks, check{scenario, name, found, expected, fmt.Sprintf(note, args...)})
}

// conn mirrors truthproc's Conn.
type conn struct {
	LPort   int   `json:"lport"`
	DialMS  int64 `json:"dial_ms"`
	OpenMS  int64 `json:"open_ms"`
	CloseMS int64 `json:"close_ms"`
	Reset   bool  `json:"reset"`
}

// shortProc is one short-lived process the test ran.
type shortProc struct {
	id, pid, code int
	command       string
	measuredMS    int64 // from before fork to after wait
}

type env struct {
	t                *testing.T
	dir, clifr, proc string
	data             string
	res              *results
	sc               scale
	cleanup          []func()
	recStart, recEnd time.Time
}

func TestGroundTruth(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: sudo env PATH=$PATH HOME=$HOME go test -tags truth ./test/truth")
	}
	sc, ok := scales[*scaleFlag]
	if !ok {
		t.Fatalf("unknown -scale %q", *scaleFlag)
	}
	dir := t.TempDir()
	root, _ := filepath.Abs("../..")
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	for _, b := range []struct{ out, pkg, cgo string }{
		{"clifrd", "./cmd/clifrd", "0"}, {"clifr", "./cmd/clifr", "1"}, {"truthproc", "./test/truth/truthproc", "0"},
	} {
		cmd := exec.Command(gobin, "build", "-o", filepath.Join(dir, b.out), b.pkg)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED="+b.cgo)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", b.pkg, err, out)
		}
	}
	var un unix.Utsname
	unix.Uname(&un)
	e := &env{t: t, dir: dir, clifr: filepath.Join(dir, "clifr"), proc: filepath.Join(dir, "truthproc"),
		data: filepath.Join(dir, "data"), sc: sc,
		res: &results{Scale: *scaleFlag, Kernel: unix.ByteSliceToString(un.Release[:]), CPUs: runtime.NumCPU()}}
	defer func() {
		for _, f := range e.cleanup {
			f()
		}
	}()

	rec := exec.Command(filepath.Join(dir, "clifrd"), append([]string{"--data-dir", e.data}, sc.recorder...)...)
	recLog, _ := os.Create(filepath.Join(dir, "recorder.log"))
	rec.Stdout, rec.Stderr = recLog, recLog
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	e.recStart = time.Now()
	e.cleanup = append(e.cleanup, func() { rec.Process.Kill() })
	t.Logf("recording (%s scale); the scenarios start in 10 s", *scaleFlag)
	time.Sleep(10 * time.Second)

	// The deleted file is held while everything else happens.
	delPath := filepath.Join(dir, "evidence.log")
	del, _ := e.start("deleted", delPath)
	delStart := time.Now()
	t.Logf("deleted file held by pid %d for %s", del.Process.Pid, sc.hold)

	tcp := e.runTCP()
	procs, procsFrom, procsTo := e.runProcs()
	rst := e.runResets()
	oom := e.runOOM()
	mnt := e.runMounts()

	if d := time.Until(delStart.Add(sc.hold)); d > 0 {
		t.Logf("scenarios done; holding the deleted file for another %s", d.Round(time.Second))
		time.Sleep(d)
	}
	stop(del)
	delEnd := time.Now()
	time.Sleep(sc.after)
	rec.Process.Signal(syscall.SIGTERM)
	if err := rec.Wait(); err != nil {
		t.Fatalf("recorder: %v (log in %s)", err, recLog.Name())
	}
	e.recEnd = time.Now()
	e.res.Start, e.res.End = e.recStart.Format(timeLayout), e.recEnd.Format(timeLayout)

	e.checkTCP(tcp)
	e.checkProcs(procs, procsFrom, procsTo)
	e.checkResets(rst)
	e.checkOOM(oom)
	e.checkMounts(mnt)
	e.checkDeleted(del.Process.Pid, delPath, delStart, delEnd)
	e.checkDrops()
	e.report(root, recLog.Name())
}

// start runs truthproc and returns it with the first line it printed.
func (e *env) start(args ...string) (*exec.Cmd, string) {
	e.t.Helper()
	cmd := exec.Command(e.proc, args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		e.t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	e.cleanup = append(e.cleanup, func() { stop(cmd) })
	sc := bufio.NewScanner(out)
	if !sc.Scan() {
		e.t.Fatalf("truthproc %s printed nothing", args[0])
	}
	return cmd, strings.TrimSpace(sc.Text())
}

func stop(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil || cmd.ProcessState != nil {
		return
	}
	cmd.Process.Kill()
	cmd.Wait()
}

func readConns(t *testing.T, path string) []conn {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []conn
	dec := json.NewDecoder(f)
	for dec.More() {
		var c conn
		if err := dec.Decode(&c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// --- TCP: many short connections ---

type tcpTruth struct {
	port, serverPID, clientPID int
	conns                      []conn
	from                       int64 // ms: just after the server started
}

func (e *env) runTCP() tcpTruth {
	srv, port := e.start("server")
	out := filepath.Join(e.dir, "conns.jsonl")
	began := time.Now()
	cli, done := e.start("client", "127.0.0.1:"+port, strconv.Itoa(e.sc.conns), strconv.Itoa(e.sc.connWorkers), "5", "200", out)
	if done != "DONE" {
		e.t.Fatalf("client: %q", done)
	}
	tr := tcpTruth{serverPID: srv.Process.Pid, clientPID: cli.Process.Pid, conns: readConns(e.t, out), from: began.UnixMilli()}
	tr.port, _ = strconv.Atoi(port)
	cli.Wait()
	time.Sleep(time.Second) // the server closes its ends
	stop(srv)
	e.t.Logf("tcp: %d connections to port %s in %s (client pid %d, server pid %d)",
		len(tr.conns), port, time.Since(began).Round(time.Millisecond), tr.clientPID, tr.serverPID)
	return tr
}

// connRow is a tcp_conns row.
type connRow struct {
	pid, lport, rport    int
	laddr, raddr, dir    string
	open, close          int64 // close 0: not closed
	appClose             int64 // the application closed its fd (0: not seen)
	resetsSent, resetsRx int
	used                 bool
}

// connRows returns the recorded connections with the port on either side.
func (e *env) connRows(port int) []*connRow {
	e.t.Helper()
	db, err := duck.Open(e.data)
	if err != nil {
		e.t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`
		SELECT pid, laddr, lport, raddr, rport, direction, open_ts, COALESCE(close_ts, 0), COALESCE(owner_until, 0),
		       resets_sent, resets_received
		FROM tcp_conns WHERE lport = ?1 OR rport = ?1`, port)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []*connRow
	for rows.Next() {
		var r connRow
		if err := rows.Scan(&r.pid, &r.laddr, &r.lport, &r.raddr, &r.rport, &r.dir, &r.open, &r.close, &r.appClose, &r.resetsSent, &r.resetsRx); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, &r)
	}
	if err := rows.Err(); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// matcher finds the recorded row of a connection: the given ports, opened
// between the connect call and its return (a local port can be reused within
// the run). Each row is matched once.
type matcher struct{ by map[[2]int][]*connRow }

func newMatcher(rows []*connRow) *matcher {
	m := &matcher{map[[2]int][]*connRow{}}
	for _, r := range rows {
		k := [2]int{r.lport, r.rport}
		m.by[k] = append(m.by[k], r)
	}
	return m
}

func (m *matcher) find(lport, rport int, c conn) *connRow {
	var best *connRow
	for _, r := range m.by[[2]int{lport, rport}] {
		if r.used || r.open < c.DialMS-5 || r.open > c.OpenMS+5 {
			continue
		}
		if best == nil || r.open < best.open {
			best = r
		}
	}
	if best != nil {
		best.used = true
	}
	return best
}

func percentile(v []int64, p float64) int64 {
	if len(v) == 0 {
		return 0
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[min(len(v)-1, int(float64(len(v))*p))]
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func (e *env) checkTCP(tr tcpTruth) {
	const sc = "tcp short connections"
	m := newMatcher(e.connRows(tr.port))
	n := len(tr.conns)
	var cFound, cOwner, cPeer, cDur, sFound, sOwner, sPeer, sDur, unclosed, slowClose int
	var cErr, sErr []int64
	for _, c := range tr.conns {
		want := c.CloseMS - c.DialMS
		if r := m.find(c.LPort, tr.port, c); r != nil {
			cFound++
			if r.pid == tr.clientPID {
				cOwner++
			}
			if r.raddr == "127.0.0.1" && r.rport == tr.port && r.dir == "active" {
				cPeer++
			}
			if r.close == 0 {
				unclosed++
			} else {
				d := r.close - r.open - want
				cErr = append(cErr, abs(d))
				if abs(d) <= durTolMS {
					cDur++
				}
			}
		}
		if r := m.find(tr.port, c.LPort, c); r != nil {
			sFound++
			if r.pid == tr.serverPID {
				sOwner++
			}
			if r.raddr == "127.0.0.1" && r.rport == c.LPort && r.dir == "passive" {
				sPeer++
			}
			// The server's end lasts until its own close is acknowledged,
			// which the client cannot time: compare the server
			// application's close (it closes when the client does).
			if r.close == 0 || r.appClose == 0 {
				unclosed++
			} else {
				d := r.appClose - r.open - want
				sErr = append(sErr, abs(d))
				if abs(d) <= durTolMS {
					sDur++
				}
				if r.close-r.appClose > durTolMS {
					slowClose++
				}
			}
		}
	}
	durNote := func(v []int64) string {
		return fmt.Sprintf("within %d ms of the client's own measurement; error p50 %d ms, p99 %d ms, max %d ms",
			durTolMS, percentile(v, 0.5), percentile(v, 0.99), percentile(v, 1))
	}
	e.res.add(sc, "client end: found", cFound, n, "by local port, peer port and connect time")
	e.res.add(sc, "client end: owner", cOwner, n, "pid %d", tr.clientPID)
	e.res.add(sc, "client end: peer and direction", cPeer, n, "127.0.0.1:%d, active", tr.port)
	e.res.add(sc, "client end: duration", cDur, n, "%s", durNote(cErr))
	e.res.add(sc, "server end: found", sFound, n, "")
	e.res.add(sc, "server end: owner", sOwner, n, "pid %d, the accepting process", tr.serverPID)
	e.res.add(sc, "server end: peer and direction", sPeer, n, "the client's port, passive")
	e.res.add(sc, "server end: duration", sDur, n, "until the server application's close: %s; %d stayed in LAST-ACK longer than %d ms after it",
		durNote(sErr), slowClose, durTolMS)

	// Rows nothing asked for: the listening socket is the only one expected.
	extra := 0
	for _, rows := range m.by {
		for _, r := range rows {
			// Older than the server: a time-wait socket of an earlier owner
			// of the port, found by the first keyframe.
			if !r.used && r.dir != "listen" && r.open >= tr.from {
				extra++
			}
		}
	}
	e.res.add(sc, "recorded connections that never existed", extra, 0, "rows on port %d not matched to a connection; %d matched rows have no close time", tr.port, unclosed)

	// The same through the CLI: clifr ss over the range, grouped by process.
	var groups []struct {
		PID   int `json:"pid"`
		Conns int `json:"conns"`
	}
	e.query(&groups, "ss", "-tanp", "dport", "=", ":"+strconv.Itoa(tr.port), "--start_from", e.recStart.Format(timeLayout),
		"--end_at", e.recEnd.Format(timeLayout))
	got := 0
	for _, g := range groups {
		if g.PID == tr.clientPID {
			got = g.Conns
		}
	}
	e.res.add(sc, "clifr ss (range): connections of the client", got, n, "clifr ss -tanp dport = :%d --start_from .. --end_at ..", tr.port)
}

// --- short-lived processes ---

func (e *env) runProcs() (procs []shortProc, from, to time.Time) {
	n := e.sc.procs
	procs = make([]shortProc, n)
	rng := rand.New(rand.NewPCG(1, 2))
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./=:,"
	plans := make([][]string, n)
	for i := range plans {
		padLen := rng.IntN(400)
		if i%100 == 50 {
			padLen = 1500 + rng.IntN(1500) // longer than the exec event keeps
		}
		pad := make([]byte, padLen)
		for j := range pad {
			pad[j] = letters[rng.IntN(len(letters))]
		}
		code := i % 256
		procs[i].id, procs[i].code = i, code
		plans[i] = []string{fmt.Sprintf("--id=%06d", i), fmt.Sprintf("--sleep-ms=%d", rng.IntN(60)), fmt.Sprintf("--exit=%d", code)}
		if padLen > 0 {
			plans[i] = append(plans[i], "--pad="+string(pad))
		}
		procs[i].command = e.proc + " " + strings.Join(plans[i], " ")
	}
	from = time.Now()
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < e.sc.procWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				cmd := exec.Command(e.proc, plans[i]...)
				t0 := time.Now()
				if err := cmd.Start(); err != nil {
					e.t.Errorf("start process %d: %v", i, err)
					continue
				}
				procs[i].pid = cmd.Process.Pid
				cmd.Wait()
				procs[i].measuredMS = time.Since(t0).Milliseconds()
				if got := cmd.ProcessState.ExitCode(); got != procs[i].code {
					e.t.Errorf("process %d exited with %d, want %d", i, got, procs[i].code)
				}
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
	to = time.Now()
	e.t.Logf("processes: %d in %s", n, to.Sub(from).Round(time.Millisecond))
	return procs, from, to
}

func (e *env) checkProcs(procs []shortProc, from, to time.Time) {
	const sc = "short processes"
	var life []struct {
		Duration int64  `json:"duration_ms"`
		PID      int    `json:"pid"`
		Command  string `json:"command"`
		EndKind  string `json:"end_kind"`
		Source   string `json:"source"`
		ExitCode *int   `json:"exit_code"`
	}
	e.query(&life, "life", "--name", "^"+regexp.QuoteMeta(e.proc)+" --id=",
		"--start_from", from.Add(-2*time.Second).Format(timeLayout), "--end_at", to.Add(2*time.Second).Format(timeLayout))
	idRE := regexp.MustCompile(`--id=(\d+)`)
	byID := map[int]int{}
	dup := 0
	for i, l := range life {
		if m := idRE.FindStringSubmatch(l.Command); m != nil {
			id, _ := strconv.Atoi(m[1])
			if _, ok := byID[id]; ok {
				dup++
			}
			byID[id] = i
		}
	}
	var found, pid, cmd, code, exact, short, dur, nLong, long, nShortCmd, maxMeasured int
	var errs []int64
	for _, p := range procs {
		isLong := len(p.command) > longCmdline
		if isLong {
			nLong++
		} else {
			nShortCmd++
		}
		maxMeasured = max(maxMeasured, int(p.measuredMS))
		i, ok := byID[p.id]
		if !ok {
			continue
		}
		l := life[i]
		found++
		if l.PID == p.pid {
			pid++
		}
		if l.Command == p.command {
			if isLong {
				long++
			} else {
				cmd++
			}
		}
		if l.ExitCode != nil && *l.ExitCode == p.code {
			code++
		}
		if l.EndKind == "exact" {
			exact++
		}
		if l.Duration < 100 {
			short++
		}
		// The start time has the kernel's 10 ms resolution; the measured
		// time includes fork and exec.
		d := abs(l.Duration - p.measuredMS)
		errs = append(errs, d)
		if d <= durTolMS {
			dur++
		}
	}
	n := len(procs)
	e.res.add(sc, "found", found, n, "clifr life --name, by the --id argument; longest measured lifetime %d ms", maxMeasured)
	e.res.add(sc, "pid", pid, n, "")
	e.res.add(sc, "full command line", cmd, nShortCmd, "byte-identical, up to %d bytes", longCmdline)
	e.res.add(sc, "full command line, over 1024 bytes", long, nLong, "1.5-3 kB; the exec event keeps 1024 bytes, the rest must be read from /proc before the process exits")
	e.res.add(sc, "exit code", code, n, "codes 0-255")
	e.res.add(sc, "exact end (exit event)", exact, n, "")
	e.res.add(sc, "duration", dur, n, "within %d ms of the measured fork-to-wait time; error p50 %d ms, p99 %d ms, max %d ms; %d recorded as shorter than 100 ms",
		durTolMS, percentile(errs, 0.5), percentile(errs, 0.99), percentile(errs, 1), short)
	e.res.add(sc, "recorded more than once", dup, 0, "")
}

// --- resets ---

type rstTruth struct {
	rstPort, closedPort             int
	serverPID, clientPID, refusePID int
	conns                           []conn
	refused                         int
}

func (e *env) runResets() rstTruth {
	n := strconv.Itoa(e.sc.resets)
	srv, port := e.start("rstserver")
	out := filepath.Join(e.dir, "resets.jsonl")
	cli, done := e.start("rstclient", "127.0.0.1:"+port, n, out)
	if done != "DONE" {
		e.t.Fatalf("rstclient: %q", done)
	}
	cli.Wait()
	tr := rstTruth{serverPID: srv.Process.Pid, clientPID: cli.Process.Pid, conns: readConns(e.t, out)}
	tr.rstPort, _ = strconv.Atoi(port)
	stop(srv)

	// A port nothing listens on: a server that just stopped.
	gone, closed := e.start("server")
	stop(gone)
	tr.closedPort, _ = strconv.Atoi(closed)
	ref, got := e.start("refused", "127.0.0.1:"+closed, n)
	ref.Wait()
	tr.refusePID = ref.Process.Pid
	tr.refused, _ = strconv.Atoi(got)
	resets := 0
	for _, c := range tr.conns {
		if c.Reset {
			resets++
		}
	}
	e.t.Logf("resets: %d of %d connections to port %d saw ECONNRESET; %d of %s connects to closed port %d refused",
		resets, len(tr.conns), tr.rstPort, tr.refused, n, tr.closedPort)
	return tr
}

func (e *env) checkResets(tr rstTruth) {
	const sc = "resets"
	m := newMatcher(e.connRows(tr.rstPort))
	var want, cFound, cReset, sFound, sReset int
	for _, c := range tr.conns {
		if !c.Reset {
			continue // the client did not see a reset (it would be the test's fault)
		}
		want++
		if r := m.find(c.LPort, tr.rstPort, c); r != nil && r.pid == tr.clientPID {
			cFound++
			if r.resetsRx == 1 && r.resetsSent == 0 {
				cReset++
			}
		}
		if r := m.find(tr.rstPort, c.LPort, c); r != nil {
			sFound++
			if r.resetsSent == 1 && r.resetsRx == 0 {
				sReset++
			}
		}
	}
	e.res.add(sc, "aborted by the server: client end found", cFound, want, "accept, then close with SO_LINGER 0; the client read ECONNRESET")
	e.res.add(sc, "aborted by the server: client end, 1 reset received", cReset, want, "")
	e.res.add(sc, "aborted by the server: server end found", sFound, want, "")
	e.res.add(sc, "aborted by the server: server end, 1 reset sent", sReset, want, "")

	var refFound, refReset int
	for _, r := range e.connRows(tr.closedPort) {
		if r.rport == tr.closedPort && r.pid == tr.refusePID {
			refFound++
			if r.resetsRx == 1 {
				refReset++
			}
		}
	}
	e.res.add(sc, "refused connects: found", refFound, tr.refused, "connects to a closed port (ECONNREFUSED)")
	e.res.add(sc, "refused connects: 1 reset received", refReset, tr.refused, "")

	// The totals as clifr ss shows them.
	var groups []struct {
		PID    int `json:"pid"`
		Resets int `json:"resets"`
	}
	e.query(&groups, "ss", "-tanp", "--start_from", e.recStart.Format(timeLayout), "--end_at", e.recEnd.Format(timeLayout))
	byPID := map[int]int{}
	for _, g := range groups {
		byPID[g.PID] += g.Resets
	}
	e.res.add(sc, "clifr ss (range): resets of the reset client", byPID[tr.clientPID], want, "")
	e.res.add(sc, "clifr ss (range): resets of the rejecting server", byPID[tr.serverPID], want, "")
	e.res.add(sc, "clifr ss (range): resets of the refused client", byPID[tr.refusePID], tr.refused, "")
}

// --- OOM kill ---

type oomTruth struct {
	pid      int
	killed   bool // by SIGKILL, and the cgroup counted an oom_kill
	from, to time.Time
}

func (e *env) runOOM() oomTruth {
	cg := fmt.Sprintf("/sys/fs/cgroup/clifr-truth-%d", os.Getpid())
	if err := os.Mkdir(cg, 0o755); err != nil {
		e.t.Fatalf("cgroup: %v", err)
	}
	e.cleanup = append(e.cleanup, func() { os.Remove(cg) })
	if err := os.WriteFile(filepath.Join(cg, "memory.max"), []byte(strconv.Itoa(oomLimit)), 0o644); err != nil {
		e.t.Fatalf("memory.max: %v", err)
	}
	os.WriteFile(filepath.Join(cg, "memory.swap.max"), []byte("0"), 0o644) // absent without swap accounting
	tr := oomTruth{from: time.Now()}
	cmd, _ := e.start("oom", cg)
	tr.pid = cmd.Process.Pid
	err := cmd.Wait()
	tr.to = time.Now()
	ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
	events, _ := os.ReadFile(filepath.Join(cg, "memory.events"))
	tr.killed = ws.Signaled() && ws.Signal() == syscall.SIGKILL && strings.Contains(string(events), "oom_kill 1")
	e.t.Logf("oom: pid %d in a %d MiB cgroup: %v; memory.events: %s", tr.pid, oomLimit>>20, err,
		strings.Join(strings.Fields(string(events)), " "))
	if !tr.killed {
		e.t.Errorf("the OOM helper was not OOM-killed")
	}
	return tr
}

func (e *env) checkOOM(tr oomTruth) {
	const sc = "oom kill"
	var kills []struct {
		TS      int64  `json:"ts_ms"`
		PID     int    `json:"pid"`
		RSSKB   int64  `json:"rss_kb"`
		Command string `json:"command"`
	}
	e.query(&kills, "oom", "--start_from", e.recStart.Format(timeLayout), "--end_at", e.recEnd.Format(timeLayout))
	var found, rss, when, cmd int
	note := ""
	for _, k := range kills {
		if k.PID != tr.pid {
			continue
		}
		found++
		limitKB := int64(oomLimit >> 10)
		if k.RSSKB >= limitKB*85/100 && k.RSSKB <= limitKB*105/100 {
			rss++
		}
		if k.TS >= tr.from.UnixMilli() && k.TS <= tr.to.UnixMilli() {
			when++
		}
		if strings.HasPrefix(k.Command, e.proc+" oom ") {
			cmd++
		}
		note = fmt.Sprintf("RSS at the kill %d kB (%.1f%% of the %d MiB limit)", k.RSSKB, float64(k.RSSKB)/float64(limitKB)*100, oomLimit>>20)
	}
	e.res.add(sc, "clifr oom: the kill", found, 1, "pid %d; %d kills listed in the recording", tr.pid, len(kills))
	e.res.add(sc, "clifr oom: RSS before the kill", rss, 1, "85-105%% of memory.max (RSS includes file pages charged to other cgroups): %s", note)
	e.res.add(sc, "clifr oom: time and command", min(when, cmd), 1, "between the start and the wait of the process")

	var life []struct {
		PID       int  `json:"pid"`
		OOMKilled bool `json:"oom_killed"`
		Signal    *int `json:"signal"`
	}
	e.query(&life, "life", "--name", "^"+regexp.QuoteMeta(e.proc)+" oom ")
	marked := 0
	for _, l := range life {
		if l.PID == tr.pid && l.OOMKilled && l.Signal != nil && *l.Signal == int(syscall.SIGKILL) {
			marked++
		}
	}
	e.res.add(sc, "clifr life: ended by OOM, SIGKILL", marked, 1, "")
}

// --- mounts ---

type mountStep struct {
	action string
	at     time.Time
}

type mountTruth struct {
	point string
	steps []mountStep
}

func (e *env) runMounts() mountTruth {
	tr := mountTruth{point: filepath.Join(e.dir, "mnt")}
	if err := os.Mkdir(tr.point, 0o755); err != nil {
		e.t.Fatal(err)
	}
	do := func(action string, f func() error) {
		at := time.Now()
		if err := f(); err != nil {
			e.t.Fatalf("%s %s: %v", action, tr.point, err)
		}
		tr.steps = append(tr.steps, mountStep{action, at})
		time.Sleep(2 * time.Second)
	}
	mount := func() error { return unix.Mount("clifr-truth", tr.point, "tmpfs", 0, "size=1m") }
	do("mount", mount)
	do("remount", func() error { return unix.Mount("", tr.point, "", unix.MS_REMOUNT|unix.MS_RDONLY, "") })
	do("unmount", func() error { return unix.Unmount(tr.point, 0) })
	do("mount", mount)
	do("unmount", func() error { return unix.Unmount(tr.point, 0) })
	e.t.Logf("mounts: %d changes of %s", len(tr.steps), tr.point)
	return tr
}

func (e *env) checkMounts(tr mountTruth) {
	const sc = "mounts"
	var rows []struct {
		TS      int64  `json:"ts_ms"`
		Action  string `json:"action"`
		Point   string `json:"mount_point"`
		FSType  string `json:"fstype"`
		Options string `json:"options"`
	}
	e.query(&rows, "mounts", "--start_from", e.recStart.Format(timeLayout), "--end_at", e.recEnd.Format(timeLayout))
	var got []int
	for i, r := range rows {
		if r.Point == tr.point && r.Action != "present" {
			got = append(got, i)
		}
	}
	var order, timed, ro int
	var worst int64
	for i, s := range tr.steps {
		if i >= len(got) {
			break
		}
		r := rows[got[i]]
		if r.Action != s.action || r.FSType != "tmpfs" {
			continue
		}
		order++
		d := abs(r.TS - s.at.UnixMilli())
		worst = max(worst, d)
		if d <= 1000 {
			timed++
		}
		if s.action == "remount" && strings.HasPrefix(r.Options, "ro") {
			ro++
		}
	}
	n := len(tr.steps)
	e.res.add(sc, "clifr mounts: changes in order", order, n, "tmpfs: mount, remount, unmount, mount, unmount; %d rows recorded for the mount point", len(got))
	e.res.add(sc, "clifr mounts: time", timed, n, "within 1 s; largest difference %d ms", worst)
	e.res.add(sc, "clifr mounts: remount shows read-only", ro, 1, "")

	// The mount table at a moment: present after the first mount, absent after the unmount.
	at := func(t time.Time) int {
		var table []struct {
			Point string `json:"mount_point"`
		}
		e.query(&table, "mounts", "--at", t.Format(timeLayout))
		n := 0
		for _, r := range table {
			if r.Point == tr.point {
				n++
			}
		}
		return n
	}
	e.res.add(sc, "clifr mounts --at: mounted", at(tr.steps[0].at.Add(1500*time.Millisecond)), 1, "1.5 s after the first mount")
	e.res.add(sc, "clifr mounts --at: not mounted", at(tr.steps[2].at.Add(1500*time.Millisecond)), 0, "1.5 s after the unmount")
}

// --- deleted file ---

func (e *env) checkDeleted(pid int, path string, start, end time.Time) {
	const sc = "deleted file held open"
	type row struct {
		FD      string `json:"fd"`
		Name    string `json:"name"`
		Deleted bool   `json:"deleted"`
	}
	has := func(t time.Time) int {
		var rows []row
		e.query(&rows, "lsof", "-p", strconv.Itoa(pid), "--at", t.Format(timeLayout))
		n := 0
		for _, r := range rows {
			if r.Deleted && strings.HasPrefix(r.Name, path) {
				n++
			}
		}
		return n
	}
	hold := end.Sub(start)
	found := 0
	var moments []string
	for _, f := range []float64{0.3, 0.5, 0.9} {
		at := start.Add(time.Duration(float64(hold) * f)).Truncate(time.Second)
		found += has(at)
		moments = append(moments, "+"+at.Sub(start).Round(time.Second).String())
	}
	e.res.add(sc, "clifr lsof -p --at: listed as deleted", found, 3, "held %s; asked at %s", hold.Round(time.Second), strings.Join(moments, ", "))
	after := end.Add(e.sc.after / 2).Truncate(time.Second).Add(time.Second)
	e.res.add(sc, "clifr lsof -p --at: gone after the release", has(after), 0, "%s after the process ended", after.Sub(end).Round(time.Second))

	// How soon it was recorded, and until when.
	var held []struct {
		Name      string `json:"name"`
		Deleted   bool   `json:"deleted"`
		FirstSeen int64  `json:"first_seen_ms"`
		LastSeen  int64  `json:"last_seen_ms"`
	}
	e.query(&held, "lsof", "-p", strconv.Itoa(pid), "--start_from", e.recStart.Format(timeLayout), "--end_at", e.recEnd.Format(timeLayout))
	n := 0
	note := ""
	for _, h := range held {
		if h.Deleted && strings.HasPrefix(h.Name, path) {
			n++
			note = fmt.Sprintf("first seen %.1f s after it was deleted, last seen %.1f s before the release (open-file walks are sampled)",
				float64(h.FirstSeen-start.UnixMilli())/1000, float64(end.UnixMilli()-h.LastSeen)/1000)
		}
	}
	e.res.add(sc, "clifr lsof (range): one holding", n, 1, "%s", note)
}

// --- recorder health ---

func (e *env) checkDrops() {
	var st struct {
		Events map[string]struct {
			Events  int64 `json:"events"`
			Dropped int64 `json:"dropped"`
		} `json:"events_by_source"`
		Reconcile struct {
			Keyframes int `json:"keyframes"`
			Missing   int `json:"missing_from_events"`
			Extra     int `json:"extra_in_events"`
		} `json:"reconcile"`
		CPU   float64 `json:"recorder_cpu_pct_one_core"`
		RSSKB int64   `json:"recorder_rss_max_kb"`
	}
	e.query(&st, "stats")
	var events, dropped int64
	for _, s := range st.Events {
		events += s.Events
		dropped += s.Dropped
	}
	e.res.add("recorder", "events dropped", int(dropped), 0, "of %d events from all eBPF sources", events)
	e.res.add("recorder", "keyframe reconciliation: connections events missed or kept too long", st.Reconcile.Missing+st.Reconcile.Extra, 0,
		"%d keyframes; recorder CPU %.2f%% of one core, peak RSS %d MiB", st.Reconcile.Keyframes, st.CPU, st.RSSKB>>10)
}

func (e *env) query(v any, args ...string) {
	e.t.Helper()
	args = append(args, "--data-dir", e.data, "--json")
	cmd := exec.Command(e.clifr, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		e.t.Fatalf("clifr %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	if err := json.Unmarshal(out, v); err != nil {
		e.t.Fatalf("clifr %s: bad JSON: %v\n%.300s", strings.Join(args, " "), err, out)
	}
}

// report prints the table, fails the test for every check that is off and
// saves everything under the results directory.
func (e *env) report(root, recLog string) {
	var b strings.Builder
	fmt.Fprintf(&b, "# Ground truth, %s scale\n\nRecorded %s .. %s, kernel %s, %d CPUs.\n\n", e.res.Scale, e.res.Start, e.res.End, e.res.Kernel, e.res.CPUs)
	fmt.Fprintf(&b, "| Scenario | Check | Found | Expected | | Note |\n|---|---|---:|---:|---|---|\n")
	failed := 0
	for _, c := range e.res.Checks {
		mark := "ok"
		if c.Found != c.Expected {
			mark = "**DIFF**"
			failed++
			e.t.Errorf("%s / %s: found %d, expected %d (%s)", c.Scenario, c.Check, c.Found, c.Expected, c.Note)
		}
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %s | %s |\n", c.Scenario, c.Check, c.Found, c.Expected, mark, c.Note)
	}
	fmt.Fprintf(&b, "\n%d of %d checks differ.\n", failed, len(e.res.Checks))
	e.t.Logf("\n%s", b.String())

	out := *outFlag
	if out == "" {
		out = filepath.Join(root, "bench", "results", fmt.Sprintf("truth-%s-%s", e.res.Scale, e.recStart.Format("20060102-1504")))
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		e.t.Errorf("results: %v", err)
		return
	}
	os.WriteFile(filepath.Join(out, "truth.md"), []byte(b.String()), 0o644)
	js, _ := json.MarshalIndent(e.res, "", "  ")
	os.WriteFile(filepath.Join(out, "truth.json"), js, 0o644)
	if stats, err := exec.Command(e.clifr, "stats", "--data-dir", e.data).CombinedOutput(); err == nil {
		os.WriteFile(filepath.Join(out, "stats.txt"), stats, 0o644)
	}
	exec.Command("cp", recLog, filepath.Join(out, "recorder.log")).Run()
	exec.Command("cp", "-r", e.data, filepath.Join(out, "data")).Run()
	for _, f := range []string{"conns.jsonl", "resets.jsonl"} {
		exec.Command("cp", filepath.Join(e.dir, f), out).Run()
	}
	if uid, gid := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID"); uid != "" { // not left root-owned
		exec.Command("chown", "-R", uid+":"+gid, out).Run()
	}
	e.t.Logf("results in %s", out)
}
