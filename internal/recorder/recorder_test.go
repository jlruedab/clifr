package recorder

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"sosv/internal/cnproc"
	"sosv/internal/procfs"
	"sosv/internal/query"
	"sosv/internal/store"
)

// fakeProc is a writable proc-root for driving the recorder in tests.
type fakeProc struct {
	t    *testing.T
	root string
}

func newFakeProc(t *testing.T) *fakeProc {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "stat"), []byte("cpu 0\nbtime 1790000000\n"), 0o644)
	os.WriteFile(filepath.Join(root, "meminfo"), []byte("MemTotal: 1000000 kB\n"), 0o644)
	return &fakeProc{t: t, root: root}
}

// set writes (or rewrites) a process with the given start ticks and CPU ticks.
func (f *fakeProc) set(pid int, comm string, startTicks, cpu int) {
	dir := filepath.Join(f.root, fmt.Sprint(pid))
	os.MkdirAll(dir, 0o755)
	stat := fmt.Sprintf("%d (%s) S 1 %d %d 0 -1 0 0 0 0 0 %d 0 0 0 20 0 1 0 %d 4096000 100 0\n",
		pid, comm, pid, pid, cpu, startTicks)
	os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644)
	os.WriteFile(filepath.Join(dir, "statm"), []byte("1000 100 0 0 0 0 0\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "status"), []byte("Uid:\t0\t0\t0\t0\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "cmdline"), []byte("/bin/"+comm+"\x00-x\x00"), 0o644)
}

func (f *fakeProc) remove(pid int) { os.RemoveAll(filepath.Join(f.root, fmt.Sprint(pid))) }

func newTestRecorder(t *testing.T, root string) (*Recorder, string) {
	dbPath := filepath.Join(t.TempDir(), "t.db")
	r, err := New(Config{DB: dbPath, Interval: time.Second, FDInterval: time.Minute, ProcRoot: root},
		log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	return r, dbPath
}

func TestIntervalLifecycle(t *testing.T) {
	fp := newFakeProc(t)
	fp.set(10, "alpha", 100, 5)
	fp.set(20, "beta", 200, 0)
	r, dbPath := newTestRecorder(t, fp.root)

	t1 := time.UnixMilli(1790001000000)
	t2 := t1.Add(30 * time.Second)
	t3 := t2.Add(30 * time.Second)
	must(t, r.sample(t1, true))

	fp.set(10, "alpha", 100, 9) // CPU changed -> new proc_samples row
	fp.remove(20)               // beta exits
	fp.set(30, "gamma", 300, 0) // gamma starts
	must(t, r.sample(t2, false))

	// Same pid 30 but a different start time is a different process (pid reuse).
	fp.set(30, "delta", 400, 0)
	must(t, r.sample(t3, false))
	must(t, r.shutdown())
	r.db.Close()

	db, err := store.Open(dbPath, true)
	must(t, err)
	defer db.Close()

	type row struct {
		comm             string
		first, last, end int64
	}
	got := map[string]row{}
	rows, err := db.Query(`SELECT comm, first_seen, COALESCE(last_seen,-1), COALESCE(ended,-1) FROM processes`)
	must(t, err)
	for rows.Next() {
		var x row
		rows.Scan(&x.comm, &x.first, &x.last, &x.end)
		got[x.comm] = x
	}
	rows.Close()
	ms := func(t time.Time) int64 { return t.UnixMilli() }
	want := map[string]row{
		"alpha": {"alpha", ms(t1), ms(t3), -1},
		"beta":  {"beta", ms(t1), ms(t1), -1}, // no exit event: ended unknown
		"gamma": {"gamma", ms(t2), ms(t2), -1},
		"delta": {"delta", ms(t3), ms(t3), -1},
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %+v want %+v", k, got[k], w)
		}
	}
	var nsamp int
	db.QueryRow(`SELECT COUNT(*) FROM proc_samples`).Scan(&nsamp)
	// alpha 2 (changed once), beta 1, gamma 1, delta 1; unchanged samples add nothing.
	if nsamp != 5 {
		t.Errorf("proc_samples rows = %d, want 5", nsamp)
	}

	// Reconstruction between samples uses the latest sample at or before t.
	ps, s, err := query.PSAt(db, ms(t2)+10_000)
	must(t, err)
	if s != ms(t2) || len(ps) != 2 || ps[0].PID != 10 || ps[1].Command != "/bin/gamma -x" {
		t.Errorf("ps at t2+10s: sample %d rows %+v", s, ps)
	}
	if ps[0].Time != "0:00" || ps[0].VSZ != 4000 || ps[0].RSS != 400 || ps[0].Mem != "0.0" {
		t.Errorf("alpha values: %+v", ps[0])
	}
	ps, _, _ = query.PSAt(db, ms(t1))
	if len(ps) != 2 || ps[1].PID != 20 {
		t.Errorf("ps at t1: %+v", ps)
	}
}

func TestRecoverAfterCrash(t *testing.T) {
	fp := newFakeProc(t)
	fp.set(10, "alpha", 100, 5)
	r, dbPath := newTestRecorder(t, fp.root)
	t1 := time.UnixMilli(1790001000000)
	must(t, r.sample(t1, true))
	must(t, r.sample(t1.Add(time.Minute), false))
	r.db.Close() // no shutdown: simulates a crash

	r2, _ := New(Config{DB: dbPath, Interval: time.Second, FDInterval: time.Minute, ProcRoot: fp.root},
		log.New(io.Discard, "", 0))
	defer r2.db.Close()
	var last int64
	r2.db.(*store.DB).QueryRow(`SELECT last_seen FROM processes WHERE pid = 10`).Scan(&last)
	if last != t1.Add(time.Minute).UnixMilli() {
		t.Errorf("recovered last_seen = %d", last)
	}
	if r2.ids["processes"] != 1 {
		t.Errorf("id counter not restored: %d", r2.ids["processes"])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// setTCP writes <root>/net/tcp with one line per socket: "LADDR:PORT RADDR:PORT ST INODE" in /proc hex form.
func (f *fakeProc) setTCP(lines ...string) {
	os.MkdirAll(filepath.Join(f.root, "net"), 0o755)
	s := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for i, l := range lines {
		var la, ra, st, ino string
		fmt.Sscan(l, &la, &ra, &st, &ino)
		s += fmt.Sprintf("%4d: %s %s %s 00000000:00000000 00:00000000 00000000     0        0 %s 1\n", i, la, ra, st, ino)
	}
	os.WriteFile(filepath.Join(f.root, "net", "tcp"), []byte(s), 0o644)
}

func (f *fakeProc) setFD(pid, fd int, target string) {
	dir := filepath.Join(f.root, fmt.Sprint(pid), "fd")
	os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, fmt.Sprint(fd))
	os.Remove(p)
	if target != "" {
		os.Symlink(target, p)
	}
}

func TestSocketOwnership(t *testing.T) {
	fp := newFakeProc(t)
	fp.set(10, "server", 100, 0)
	fp.set(20, "client", 200, 0)
	fp.setTCP("0100007F:1E61 00000000:0000 0A 500") // 127.0.0.1:7777 LISTEN
	fp.setFD(10, 3, "socket:[500]")
	fp.setFD(10, 4, "/var/log/x")
	r, dbPath := newTestRecorder(t, fp.root)

	t1 := time.UnixMilli(1790001000000)
	t2, t3, t4 := t1.Add(30*time.Second), t1.Add(60*time.Second), t1.Add(90*time.Second)
	must(t, r.sample(t1, true)) // full walk: server owns 500

	// Client connects; the server accepts. Server is a known owner so the
	// partial walk finds the accepted socket; the client was never seen
	// owning sockets, so its socket stays unattributed until a full walk.
	fp.setTCP("0100007F:1E61 00000000:0000 0A 500",
		"0100007F:1E61 0100007F:C350 01 501", // server side 7777 -> 50000
		"0100007F:C350 0100007F:1E61 01 502") // client side 50000 -> 7777
	fp.setFD(10, 5, "socket:[501]")
	fp.setFD(20, 3, "socket:[502]")
	must(t, r.sample(t2, false))
	if len(r.owners) != 2 {
		t.Fatalf("after partial walk: %d owners, want 2 (listener + accepted)", len(r.owners))
	}
	must(t, r.sample(t3, true)) // full walk finds the client; owner backfilled to t2
	// Server closes the accepted socket's fd while the socket lingers.
	fp.setFD(10, 5, "")
	must(t, r.sample(t4, false))
	must(t, r.shutdown())
	r.db.Close()

	db, err := store.Open(dbPath, true)
	must(t, err)
	defer db.Close()
	ms := func(t time.Time) int64 { return t.UnixMilli() }
	type own struct{ first, last int64 }
	got := map[string]own{}
	rows, _ := db.Query(`SELECT p.comm, s.inode, o.first_seen, o.last_seen FROM sock_owners o
		JOIN processes p ON p.id = o.proc_id JOIN sockets s ON s.id = o.sock_id`)
	for rows.Next() {
		var comm string
		var ino int64
		var o own
		rows.Scan(&comm, &ino, &o.first, &o.last)
		got[fmt.Sprint(comm, ino)] = o
	}
	rows.Close()
	want := map[string]own{
		"server500": {ms(t1), ms(t4)},
		"server501": {ms(t2), ms(t3)}, // fd closed before t4
		"client502": {ms(t2), ms(t4)}, // backfilled to the socket's first_seen
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %+v want %+v", k, got[k], w)
		}
	}

	ss, err := query.SocketsAt(db, ms(t2), "tcp", query.SockFilter{})
	must(t, err)
	if len(ss) != 3 || ss[0].State != "LISTEN" || len(ss[0].Owners) != 1 || ss[0].Owners[0].Comm != "server" {
		t.Fatalf("ss at t2: %+v", ss)
	}
	f, _ := query.ParseSockFilter([]string{"dport", "=", ":7777"})
	ss, _ = query.SocketsAt(db, ms(t3), "tcp", f)
	if len(ss) != 1 || ss[0].Owners[0].Comm != "client" {
		t.Errorf("filtered ss at t3: %+v", ss)
	}
	groups, err := query.SocketsInRange(db, ms(t1), ms(t4), "tcp", query.SockFilter{})
	must(t, err)
	if len(groups) != 2 || groups[0].Process != "server,pid=10" || groups[0].Conns != 2 || groups[0].Peak != 2 {
		t.Errorf("groups: %+v", groups)
	}
}

func TestClassifyFD(t *testing.T) {
	names := sockNames{unix: map[uint64]string{7: "/run/x type=STREAM (LISTEN)"}, netlink: map[uint64]string{8: "ROUTE"}}
	reg := &procfs.FDStat{Mode: unix.S_IFREG}
	fifo := &procfs.FDStat{Mode: unix.S_IFIFO}
	cases := []struct {
		fd              procfs.FD
		flags           uint64
		st              *procfs.FDStat
		typ, mode, name string
	}{
		{procfs.FD{Num: 3, Target: "socket:[7]"}, 2, nil, "unix", "u", "/run/x type=STREAM (LISTEN)"},
		{procfs.FD{Num: 4, Target: "socket:[8]"}, 2, nil, "netlink", "u", "ROUTE"},
		{procfs.FD{Num: 5, Target: "pipe:[99]"}, 0, fifo, "FIFO", "r", "pipe"},
		{procfs.FD{Num: 6, Target: "anon_inode:[eventpoll]"}, 2, nil, "a_inode", "u", "[eventpoll]"},
		{procfs.FD{Num: 7, Target: "anon_inode:inotify"}, 0, nil, "a_inode", "r", "inotify"},
		{procfs.FD{Num: 8, Target: "/run/initctl"}, 2, fifo, "FIFO", "u", ""},
		{procfs.FD{Num: 9, Target: "/var/log/x.log (deleted)"}, 1, reg, "REG", "w", ""},
		{procfs.FD{Num: 10, Target: "/usr/lib/x"}, 0o10000000, reg, "REG", "u", ""}, // O_PATH
		{procfs.FD{Num: 11, Target: "/etc"}, 0o200000, nil, "DIR", "r", ""},         // no statx: O_DIRECTORY
		{procfs.FD{Num: procfs.FDCwd, Target: "/"}, 0, nil, "DIR", "", ""},
	}
	for _, c := range cases {
		typ, mode, name := classifyFD(c.fd, c.flags, true, c.st, names)
		if typ != c.typ || mode != c.mode || name != c.name {
			t.Errorf("%v: got %s %s %q, want %s %s %q", c.fd, typ, mode, name, c.typ, c.mode, c.name)
		}
	}
}

func TestOpenFiles(t *testing.T) {
	fp := newFakeProc(t)
	fp.set(10, "app", 100, 0)
	fp.setTCP()
	fp.setFD(10, 3, "/var/log/app.log")
	fp.setFD(10, 4, "/tmp/scratch")
	r, dbPath := newTestRecorder(t, fp.root)
	t1 := time.UnixMilli(1790001000000)
	t2, t3, t4 := t1.Add(30*time.Second), t1.Add(60*time.Second), t1.Add(90*time.Second)
	must(t, r.sample(t1, true))
	fp.setFD(10, 4, "/tmp/scratch (deleted)") // unlinked while open: new row, marked deleted
	fp.setFD(10, 3, "")                       // closed, but only noticed at the next full walk
	must(t, r.sample(t2, false))
	must(t, r.sample(t3, true))
	fp.remove(10)
	must(t, r.sample(t4, false))
	r.db.Close()

	db, err := store.Open(dbPath, true)
	must(t, err)
	defer db.Close()
	type f struct {
		first, last int64
		deleted     int
	}
	got := map[string]f{}
	rows, _ := db.Query(`SELECT target, first_seen, last_seen, deleted FROM open_files WHERE fd >= 0`)
	for rows.Next() {
		var tg string
		var x f
		rows.Scan(&tg, &x.first, &x.last, &x.deleted)
		got[tg] = x
	}
	rows.Close()
	ms := func(t time.Time) int64 { return t.UnixMilli() }
	want := map[string]f{
		"/var/log/app.log":       {ms(t1), ms(t1), 0},
		"/tmp/scratch":           {ms(t1), ms(t1), 0},
		"/tmp/scratch (deleted)": {ms(t3), ms(t3), 1}, // closed when the process ended
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %+v want %+v", k, got[k], w)
		}
	}
	// lsof between fd walks uses the last full walk.
	ls, _, sfd, err := query.LsofAt(db, ms(t2)+1000, query.LsofOptions{})
	must(t, err)
	if sfd != ms(t1) {
		t.Errorf("fd snapshot = %d, want t1", sfd)
	}
	var names []string
	for _, x := range ls {
		if x.FD == "3" || x.FD == "4" {
			names = append(names, x.Name)
		}
	}
	if len(names) != 2 {
		t.Errorf("lsof at t2: %v", names)
	}
}

func TestEvents(t *testing.T) {
	fp := newFakeProc(t)
	fp.set(10, "daemon", 100, 0)
	r, dbPath := newTestRecorder(t, fp.root)
	r.events = &eventQueue{}
	t1 := time.UnixMilli(1790001000000)
	t2 := t1.Add(30 * time.Second)
	must(t, r.sample(t1, true))

	boot := int64(1790000000000)
	short := procKey{pid: 50, start: boot + 1005*1000} // started at t1+5s, gone before t2
	adopted := procKey{pid: 60, start: boot + 1010*1000}
	daemonKey := procKey{pid: 10, start: boot + 1000}
	ev := func(k cnproc.Kind, key procKey, ts int64, cmd string) procEvent {
		return procEvent{kind: k, pid: key.pid, ts: ts, haveStat: true, key: key,
			attrs: store.ProcUpdate{PPID: 10, Comm: "x", Cmdline: cmd, Source: "event"}}
	}
	r.events.list = []procEvent{
		ev(cnproc.Fork, short, short.start, "/bin/daemon"),
		ev(cnproc.Exec, short, short.start+2, "/bin/hook --run"),
		ev(cnproc.Exit, short, short.start+340, ""),
		ev(cnproc.Fork, adopted, adopted.start, "/bin/worker"),
		ev(cnproc.Exit, daemonKey, t1.UnixMilli()+20_000, ""),
	}
	fp.set(60, "worker", 1010*100, 0) // still alive at t2
	fp.remove(10)                     // daemon exited (event above)
	must(t, r.sample(t2, false))
	must(t, r.shutdown())
	r.db.Close()

	db, err := store.Open(dbPath, true)
	must(t, err)
	defer db.Close()
	type row struct {
		cmd, src         string
		first, last, end int64
	}
	got := map[int]row{}
	rows, _ := db.Query(`SELECT pid, cmdline, source, first_seen, last_seen, COALESCE(ended, -1) FROM processes`)
	for rows.Next() {
		var pid int
		var x row
		rows.Scan(&pid, &x.cmd, &x.src, &x.first, &x.last, &x.end)
		got[pid] = x
	}
	rows.Close()
	want := map[int]row{
		50: {"/bin/hook --run", "event", short.start, short.start + 340, short.start + 340},
		60: {"/bin/worker -x", "sample", adopted.start, t2.UnixMilli(), -1},
		10: {"/bin/daemon -x", "sample", t1.UnixMilli(), t1.UnixMilli(), t1.UnixMilli() + 20_000},
	}
	for pid, w := range want {
		if got[pid] != w {
			t.Errorf("pid %d: got %+v want %+v", pid, got[pid], w)
		}
	}
	// ps at t1+5.2s: the daemon (exits at t1+20s) and the short process (t1+5s..t1+5.34s).
	ps, _, err := query.PSAt(db, t1.UnixMilli()+5200)
	must(t, err)
	if len(ps) != 2 || ps[1].PID != 50 || ps[1].Stat != "-" {
		t.Errorf("ps at t1+5.2s: %+v", ps)
	}
	// ps at t1+25s: daemon exited at t1+20s per its exit event; worker started at t1+10s.
	ps, _, _ = query.PSAt(db, t1.UnixMilli()+25000)
	if len(ps) != 1 || ps[0].PID != 60 {
		t.Errorf("ps at t1+25s: %+v", ps)
	}
	life, err := query.Life(db, 0, t2.UnixMilli(), regexp.MustCompile("hook"))
	must(t, err)
	if len(life) != 1 || life[0].Duration != 340 || life[0].EndKind != "exact" {
		t.Errorf("life: %+v", life)
	}
}

func TestSkipOnOverrun(t *testing.T) {
	fp := newFakeProc(t)
	fp.set(10, "a", 100, 0)
	dbPath := filepath.Join(t.TempDir(), "t.db")
	r, err := New(Config{DB: dbPath, Interval: 200 * time.Millisecond, FDInterval: time.Second,
		Duration: 1500 * time.Millisecond, ProcRoot: fp.root}, log.New(io.Discard, "", 0))
	must(t, err)
	n := 0
	r.afterSample = func() {
		n++
		if n == 2 {
			time.Sleep(650 * time.Millisecond) // overruns ~3 slots
		}
	}
	must(t, r.Run(context.Background()))
	db, _ := store.Open(dbPath, true)
	defer db.Close()
	var skipped, guard, samples int
	db.QueryRow(`SELECT COUNT(*) FROM samples WHERE skipped = 1`).Scan(&skipped)
	db.QueryRow(`SELECT COUNT(*) FROM samples WHERE skipped = 0`).Scan(&samples)
	db.QueryRow(`SELECT COUNT(*) FROM guard_events WHERE kind = 'skip'`).Scan(&guard)
	if skipped < 2 || skipped > 4 || guard != skipped {
		t.Errorf("skipped=%d guard events=%d, want 2..4 and equal", skipped, guard)
	}
	// 1.5s at 200ms is ~8 slots: the skipped ones must not run back to back.
	if samples+skipped > 9 {
		t.Errorf("samples=%d skipped=%d: more slots than time allows", samples, skipped)
	}
}

func TestCPUBudget(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	defer r.db.Close()
	r.cfg.CPUBudget = 0.02
	r.cfg.BudgetWindow = 5 * time.Minute
	r.fdInterval = 2 * time.Minute
	t0 := time.UnixMilli(1790001000000)
	b := &store.Batch{}
	// 1% of a core for 5 minutes: within budget.
	for i := 0; i <= 10; i++ {
		r.checkBudget(t0.Add(time.Duration(i)*30*time.Second), int64(i)*300_000, b)
	}
	if r.fdInterval != 2*time.Minute || len(b.Guard) != 0 {
		t.Fatalf("within budget: fd-interval %s, guard %v", r.fdInterval, b.Guard)
	}
	// Then 4% of a core: as soon as the rolling 5-minute average crosses 2%
	// the guard doubles the interval once and starts a new window.
	cpu := int64(10 * 300_000)
	for i := 11; i <= 20; i++ {
		cpu += 1_200_000
		r.checkBudget(t0.Add(time.Duration(i)*30*time.Second), cpu, b)
	}
	if r.fdInterval != 4*time.Minute || len(b.Guard) != 1 || b.Guard[0].Kind != "fd_interval_up" {
		t.Fatalf("over budget: fd-interval %s, guard %+v", r.fdInterval, b.Guard)
	}
	// Still over budget: keeps doubling up to the cap, then reports once.
	for i := 26; i <= 400; i++ {
		cpu += 1_200_000
		r.checkBudget(t0.Add(time.Duration(i)*30*time.Second), cpu, b)
	}
	last := b.Guard[len(b.Guard)-1]
	if r.fdInterval != maxFDInterval || last.Kind != "budget_exceeded" {
		t.Errorf("at cap: fd-interval %s, last guard %+v", r.fdInterval, last)
	}
}
