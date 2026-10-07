package recorder

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

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
		"beta":  {"beta", ms(t1), ms(t1), ms(t2)},
		"gamma": {"gamma", ms(t2), ms(t2), ms(t3)},
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
	r2.db.QueryRow(`SELECT last_seen FROM processes WHERE pid = 10`).Scan(&last)
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
