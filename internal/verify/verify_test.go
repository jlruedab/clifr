package verify

import (
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

func TestParsePS(t *testing.T) {
	out := "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n" +
		"root           1  0.0  0.1  22176 13464 ?        Ss   17:54   0:01 /sbin/init splash\n" +
		"alice       4990  0.0  0.1  10296  9576 pts/0    Ss+  Oct06   0:00 bash -c  two  spaces\n"
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
	// Socket 1 changes state at 31000; socket 2 stays ESTAB.
	db := testrec.Open(t, nil,
		&store.Batch{Sample: store.Sample{TS: 1000, FDWalk: true},
			ProcInserts: []store.ProcRow{{ID: 1, PID: 50, StartTime: 1, PPID: 1, Comm: "load", Source: "sample"}},
			SockInserts: []store.SockRow{
				{ID: 1, Inode: 111, Proto: "tcp", Family: 4, LAddr: "127.0.0.2", LPort: 40000, RAddr: "127.0.0.1", RPort: 30000},
				{ID: 2, Inode: 222, Proto: "tcp", Family: 4, LAddr: "127.0.0.3", LPort: 40001, RAddr: "127.0.0.1", RPort: 30000}},
			SockSamples: []store.SockSample{{SockID: 1, TS: 0, State: 1}, {SockID: 2, TS: 0, State: 1}},
			OwnInserts:  []store.OwnerRow{{ID: 1, SockID: 1, ProcID: 1, FD: 7}, {ID: 2, SockID: 2, ProcID: 1, FD: 8}}},
		&store.Batch{Sample: store.Sample{TS: 31000, FDWalk: true},
			SockSamples: []store.SockSample{{SockID: 1, TS: 31000, State: 6}}},
		&store.Batch{Sample: store.Sample{TS: 61000, FDWalk: true}})

	if !sockChanged(db, "127.0.0.2:40000 127.0.0.1:30000", 1000, 31000) {
		t.Error("state change after the sample not seen")
	}
	if sockChanged(db, "127.0.0.3:40001 127.0.0.1:30000", 1000, 31000) {
		t.Error("unchanged socket reported as changed")
	}

	hdr := "COMMAND PID TID TASKCMD USER   FD TYPE DEVICE SIZE/OFF     NODE NAME\n"
	out := hdr + "load     50              root    8u sock    0,8      0t0    222 protocol: TCP\n"
	res, _, err := compareLsof(db, snapshot{ts: 1500, endTS: 2000, sampleTS: 1000, cmd: "lsof -n -P", output: out, ignore: map[int]bool{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 1 || res.Exact != 1 || res.Ignored["sockets lsof could not resolve (matched by inode)"] != 1 {
		t.Errorf("unresolved socket with the same inode: %+v", res)
	}
}

func TestParseNewTools(t *testing.T) {
	free := parseFree("               total        used        free      shared  buff/cache   available\n" +
		"Mem:        63964028     9566804    44232428     1302548    11100100    54397224\n" +
		"Swap:        8388604           0     8388604\n")
	if free["Mem:"]["available"] != "54397224" || free["Swap:"]["free"] != "8388604" || len(free) != 2 {
		t.Errorf("free: %v", free)
	}
	ef := parsePSEF("UID          PID    PPID  C STIME TTY          TIME CMD\n" +
		"postgres    3101    3085  0 09:21 ?        00:00:00 postgres: 18/main: checkpointer \n")
	if x := ef[3101]; x.uid != "postgres" || x.ppid != "3085" || x.stime != "09:21" || x.time != "00:00:00" ||
		x.cmd != "postgres: 18/main: checkpointer " {
		t.Errorf("ps -ef: %+v", x)
	}
	ns := parseNetstat("Active Internet connections (servers and established)\n"+
		"Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    \n"+
		"tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      3085/postgres       \n"+
		"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      3008/sshd: /usr/sbi \n"+
		"tcp6       0      0 :::22                   :::*                    LISTEN      7/x\n", map[int]bool{7: true})
	if x := ns["tcp 0.0.0.0:22 0.0.0.0:*"]; x.prog != "3008/sshd: /usr/sbi" || x.state != "LISTEN" {
		t.Errorf("netstat: %+v", x)
	}
	if x := ns["tcp6 :::22 :::*"]; x.prog != "-" {
		t.Errorf("netstat ignored pid: %+v", x)
	}
}

// TestRunRecordedNames: verify compares with the recorded host's user names
// (snapshots passwd), not those of the machine it runs on. uid 1000 is
// "vmuser" in the recording: on any machine running the test, it is someone
// else or nobody.
func TestRunRecordedNames(t *testing.T) {
	base := int64(1_790_000_000_000)
	db := testrec.Open(t, []string{"boot_ms", "1789990000000", "boot_id", "b1", "hostname", "vm1"},
		&store.Batch{Sample: store.Sample{TS: base},
			Snapshots: []store.SnapshotRow{
				{TS: base, Source: "passwd", Key: "0", Pos: 0, Full: true, Line: "0 root"},
				{TS: base, Source: "passwd", Key: "1000", Pos: 1, Full: true, Line: "1000 vmuser"}},
			ProcInserts: []store.ProcRow{{ID: 1, PID: 4242, StartTime: base - 5000, PPID: 1, UID: 1000, RUID: 1000,
				Comm: "sleep", Cmdline: "sleep 600", FirstSeen: base - 5000, Source: "sample"}},
			ProcSamples: []store.ProcSample{{ProcID: 1, TS: base, State: "S", Threads: 1, RSSKB: 1000, VSZKB: 5000}},
			Verify: []store.VerifySnap{{TS: base + 100, EndTS: base + 150, SampleTS: base, Cmd: "ps -ef",
				Output: "UID          PID    PPID  C STIME TTY          TIME CMD\n" +
					"vmuser      4242       1  0 10:00 ?        00:00:00 sleep 600\n"}}})
	rep, err := Run(db)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := rep.Totals["ps -ef"]
	if !ok || r.Matched != 1 {
		t.Fatalf("ps -ef not compared: %+v", rep.Totals)
	}
	if n := r.FieldDiffs["UID"]; n != 0 {
		t.Errorf("UID differs (this machine's names used): %v", r.Examples)
	}
}
