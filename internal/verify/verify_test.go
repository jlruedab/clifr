package verify

import "testing"

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
		"lsof       9999                             root    3r      DIR               0,22        0          1 /proc\n"
	res := newResult("lsof -n -P")
	m := parseLsof(out, &res, map[int]bool{})
	if len(m) != 3 {
		t.Fatalf("rows: %+v", m)
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
