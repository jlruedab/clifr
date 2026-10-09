package verify

import (
	"path/filepath"
	"testing"

	"sosv/internal/store"
)

func TestParsePS(t *testing.T) {
	out := "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n" +
		"root           1  0.0  0.1  22176 13464 ?        Ss   17:54   0:01 /sbin/init splash\n" +
		"jlrueda     4990  0.0  0.1  10296  9576 pts/0    Ss+  Oct06   0:00 bash -c  two  spaces\n"
	m := parsePS(out)
	if len(m) != 2 || m[1].cmd != "/sbin/init splash" || m[1].rss != "13464" || m[4990].start != "Oct06" {
		t.Fatalf("%+v", m)
	}
	if m[4990].cmd != "bash -c  two  spaces" {
		t.Errorf("command with double spaces: %q", m[4990].cmd)
	}
}

func TestParseSS(t *testing.T) {
	out := "State  Recv-Q Send-Q Local Address:Port   Peer Address:Port Process\n" +
		"LISTEN 0      4096   127.0.0.53%lo:53          0.0.0.0:*     users:((\"systemd-resolve\",pid=791,fd=15))\n" +
		"ESTAB  0      0       192.168.1.10:22     192.168.1.12:51384 users:((\"sshd\",pid=5616,fd=3),(\"sshd\",pid=5595,fd=3))\n"
	m := parseSS(out, map[int]bool{5616: true})
	l := m["127.0.0.53%lo:53 0.0.0.0:*"]
	if l.state != "LISTEN" || l.sendQ != "4096" || l.users != "systemd-resolve/791/15" {
		t.Errorf("listen: %+v", l)
	}
	if e := m["192.168.1.10:22 192.168.1.12:51384"]; e.users != "sshd/5595/3" {
		t.Errorf("ignored pid not dropped: %+v", e)
	}
	for in, want := range map[string]struct {
		a string
		p int
	}{"127.0.0.53%lo:53": {"127.0.0.53", 53}, "[::]:22": {"::", 22}, "0.0.0.0:*": {"0.0.0.0", 0},
		"[::ffff:127.0.0.1]:5432": {"::ffff:127.0.0.1", 5432}} {
		if a, p := splitSSAddr(in); a != want.a || p != want.p {
			t.Errorf("splitSSAddr(%q) = %q %d", in, a, p)
		}
	}
}

func TestParseLsof(t *testing.T) {
	out := "COMMAND     PID   TID TASKCMD               USER   FD      TYPE             DEVICE  SIZE/OFF       NODE NAME\n" +
		"systemd       1                             root  cwd       DIR              252,0      4096          2 /\n" +
		"systemd       1                             root  mem       REG              252,0   625344    3676035 /usr/lib/libx.so\n" +
		"systemd       1                             root    4u  a_inode               0,15         0         69 [eventpoll:5,6,10]\n" +
		"dockerd    1028                             root   14uW     REG               0,4         0 4026531840 net\n" +
		"dockerd    1028  1030 dockerd               root   14u      REG               0,4         0 4026531840 net\n" +
		"kthreadd      2                             root  txt   unknown                                         /proc/2/exe\n" +
		"load       1945                             root 2488u     sock                0,8       0t0   48151623 protocol: TCP\n" +
		"lsof       9999                             root    3r      DIR               0,22        0          1 /proc\n"
	res := newResult("lsof -n -P")
	m := parseLsof(out, &res, map[int]bool{})
	if len(m) != 4 {
		t.Fatalf("rows: %+v", m)
	}
	if r := m["1945 2488"]; r.typ != "sock" || r.node != "48151623" {
		t.Errorf("unresolved socket: %+v", r)
	}
	if r := m["1 4"]; r.typ != "a_inode" || r.name != "[eventpoll]" || r.mode != "u" {
		t.Errorf("eventpoll: %+v", r)
	}
	if r := m["1028 14"]; r.mode != "u" {
		t.Errorf("lock flag not stripped: %+v", r)
	}
	for k, want := range map[string]int{"mem/DEL rows": 1, "thread (TID) rows": 1, "kernel-thread txt placeholders": 1, "recorder/tool processes": 1} {
		if res.Ignored[k] != want {
			t.Errorf("ignored %s = %d, want %d", k, res.Ignored[k], want)
		}
	}
}

func TestKworkerBase(t *testing.T) {
	for in, want := range map[string]string{
		"[kworker/1:3-events]": "[kworker/1:3]", "[kworker/u17:0+flush]": "[kworker/u17:0]",
		"[kworker/0:1]": "[kworker/0:1]", "/usr/bin/x -v": "/usr/bin/x -v",
	} {
		if got := kworkerBase(in); got != want {
			t.Errorf("%q -> %q", in, got)
		}
	}
}

func TestCompareChurnChanged(t *testing.T) {
	r := newResult("ss -tanp")
	same := []fieldPair{{"State", "ESTAB", "ESTAB"}}
	diff := []fieldPair{{"State", "TIME-WAIT", "ESTAB"}}
	r.compare("a", same, func() bool { t.Error("changed() called for an exact row"); return true })
	r.compare("b", diff, func() bool { return true })
	r.compare("c", diff, func() bool { return false })
	if r.Exact != 1 || r.ChurnChanged != 1 || r.FieldDiffs["State"] != 1 {
		t.Errorf("exact %d churn-changed %d state diffs %d, want 1 1 1", r.Exact, r.ChurnChanged, r.FieldDiffs["State"])
	}
}

// sockChanged and the lsof inode rule against a small database: a
// connection whose state changed after the sample, one that did not, and a
// socket lsof could not resolve.
func TestChangedInDB(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "v.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for i, ts := range []int64{1000, 31000, 61000} {
		exec(`INSERT INTO samples(id, ts, fd_walk) VALUES (?, ?, 1)`, i+1, ts)
	}
	exec(`INSERT INTO processes(id, pid, start_time, ppid, uid, comm, first_seen, source) VALUES (1, 50, 1, 1, 0, 'load', 0, 'sample')`)
	// Socket 1 changes state at 31000; socket 2 stays ESTAB.
	exec(`INSERT INTO sockets(id, inode, proto, family, laddr, lport, raddr, rport, first_seen) VALUES
		(1, 111, 'tcp', 4, '127.0.0.2', 40000, '127.0.0.1', 30000, 0),
		(2, 222, 'tcp', 4, '127.0.0.3', 40001, '127.0.0.1', 30000, 0)`)
	exec(`INSERT INTO sock_samples(sock_id, ts, state) VALUES (1, 0, 1), (1, 31000, 6), (2, 0, 1)`)
	exec(`INSERT INTO sock_owners(id, sock_id, proc_id, fd, first_seen) VALUES (1, 1, 1, 7, 0), (2, 2, 1, 8, 0)`)

	if !sockChanged(db, "127.0.0.2:40000 127.0.0.1:30000", 1000, 31000) {
		t.Error("state change after the sample not seen")
	}
	if sockChanged(db, "127.0.0.3:40001 127.0.0.1:30000", 1000, 31000) {
		t.Error("unchanged socket reported as changed")
	}

	hdr := "COMMAND PID TID TASKCMD USER   FD TYPE DEVICE SIZE/OFF     NODE NAME\n"
	out := hdr + "load     50              root    8u sock    0,8      0t0    222 protocol: TCP\n"
	res, err := compareLsof(db, snapshot{ts: 1500, endTS: 2000, sampleTS: 1000, cmd: "lsof -n -P", output: out, ignore: map[int]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 1 || res.Exact != 1 || res.Ignored["sockets lsof could not resolve (matched by inode)"] != 1 {
		t.Errorf("unresolved socket with the same inode: %+v", res)
	}
}
