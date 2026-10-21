package procfs

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var fixture = New("testdata/proc")

func TestPIDs(t *testing.T) {
	pids, err := fixture.PIDs()
	if err != nil {
		t.Fatal(err)
	}
	sort.Ints(pids)
	if len(pids) != 3 || pids[0] != 1 || pids[1] != 77 || pids[2] != 4242 {
		t.Fatalf("pids = %v", pids)
	}
}

func TestReadStatWeirdComm(t *testing.T) {
	s, err := fixture.ReadStat(4242)
	if err != nil {
		t.Fatal(err)
	}
	want := Stat{PID: 4242, Comm: "my (weird) prog", State: 'R', PPID: 1, PGRP: 4242, Session: 4242,
		TTY: 34816, TPGID: 4242, Utime: 512, Stime: 256, Nice: -5, NumThreads: 4, StartTime: 360000,
		VSize: 1048576, RSS: 256, MinFlt: 1, MajFlt: 3, Priority: 20, Processor: 1, RTPriority: 5, Policy: 1}
	if s != want {
		t.Fatalf("got  %+v\nwant %+v", s, want)
	}
	if TTYName(s.TTY) != "pts/0" {
		t.Errorf("tty = %s", TTYName(s.TTY))
	}
}

func TestParseStatMalformed(t *testing.T) {
	for _, in := range []string{"", "12 (x", "12 (x) S 1 2"} {
		if _, err := ParseStat([]byte(in)); err == nil || !IsGone(err) {
			t.Errorf("%q: want short-file error, got %v", in, err)
		}
	}
}

func TestStatusCmdlineStatm(t *testing.T) {
	st, err := fixture.ReadStatus(4242)
	if err != nil {
		t.Fatal(err)
	}
	if st.UID != 1001 || st.VmLckK != 16 || st.VolCtx != 120 || st.NonVolCtx != 7 {
		t.Errorf("status = %+v, want euid 1001, VmLck 16, context switches 120 and 7", st)
	}
	cmd, argv0, _ := fixture.ReadCmdline(4242)
	if cmd != "./prog --flag a b" || argv0 != len("./prog") {
		t.Errorf("cmdline = %q, argv[0] length %d", cmd, argv0)
	}
	if n := Argv0Len([]byte("/opt/chrome --type=renderer\x00")); n != len("/opt/chrome --type=renderer") {
		t.Errorf("one-string command line: argv[0] length %d", n)
	}
	if cmd, _, _ := fixture.ReadCmdline(77); cmd != "" {
		t.Errorf("kernel thread cmdline = %q", cmd)
	}
	size, res, shr, err := fixture.ReadStatm(4242)
	if err != nil || size != 256 || res != 260 || shr != 10 {
		t.Errorf("statm = %d %d %d %v", size, res, shr, err)
	}
	if w, err := fixture.ReadWchan(4242); w != "do_epoll_wait" {
		t.Errorf("wchan = %q %v", w, err)
	}
	if l, err := fixture.ReadLabel(4242); l != "unconfined" {
		t.Errorf("label = %q %v", l, err)
	}
	if c, err := fixture.ReadCgroup(4242); c != "0::/user.slice/user-1000.slice/session-2.scope" {
		t.Errorf("cgroup = %q %v", c, err)
	}
	if _, err := fixture.ReadLabel(77); err == nil {
		t.Errorf("label of a process without attr/current: no error")
	}
}

func TestVanishedProcess(t *testing.T) {
	_, err := fixture.ReadStat(99999)
	if !IsGone(err) {
		t.Fatalf("missing pid should look gone, got %v", err)
	}
	if _, err := fixture.ReadFDs(99999, false); !IsGone(err) {
		t.Fatalf("missing fd dir should look gone, got %v", err)
	}
}

func TestReadFDs(t *testing.T) {
	fds, err := fixture.ReadFDs(4242, false)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]string{}
	for _, f := range fds {
		got[f.Num] = f.Target
	}
	want := map[int]string{0: "/dev/null", 3: "socket:[98765]", 4: "/tmp/gone.log (deleted)", 5: "pipe:[555]"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("fd %d = %q, want %q", k, got[k], v)
		}
	}
	socks, _ := fixture.ReadFDs(4242, true)
	if len(socks) != 1 || socks[0].Num != 3 {
		t.Errorf("socketsOnly = %v", socks)
	}
	if ino, ok := SocketInode(socks[0].Target); !ok || ino != 98765 {
		t.Errorf("inode = %d %v", ino, ok)
	}
	special := fixture.ReadSpecialLinks(4242)
	if len(special) != 3 || special[0].Num != FDCwd || special[0].Target != "/home/u" {
		t.Errorf("special = %v", special)
	}
}

func TestSystemFiles(t *testing.T) {
	bt, err := fixture.BootTime()
	if err != nil || bt != 1790000000 {
		t.Errorf("btime = %d %v", bt, err)
	}
	mt, err := fixture.MemTotalKB()
	if err != nil || mt != 8000000 {
		t.Errorf("memtotal = %d %v", mt, err)
	}
}

func TestTTYName(t *testing.T) {
	cases := map[int]string{0: "?", 136<<8 | 0: "pts/0", 137<<8 | 0: "pts/256", 4<<8 | 1: "tty1", 4<<8 | 64: "ttyS0"}
	for nr, want := range cases {
		if got := TTYName(nr); got != want {
			t.Errorf("TTYName(%d) = %s, want %s", nr, got, want)
		}
	}
}

func TestFDFlagsAndUnix(t *testing.T) {
	fl, err := fixture.ReadFDFlags(4242, 4)
	if err != nil || fl != 0o100002 {
		t.Errorf("flags = %o %v", fl, err)
	}
	u, err := fixture.ReadNetUnix()
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint64]string{
		6956:  "/run/snapd.socket type=STREAM (LISTEN)",
		29796: "/run/systemd/journal/stdout type=STREAM (CONNECTED)",
		6228:  "type=DGRAM (CONNECTED)",
	}
	for k, v := range want {
		if u[k] != v {
			t.Errorf("unix %d = %q, want %q", k, u[k], v)
		}
	}
}

func TestParseMountInfo(t *testing.T) {
	in := "22 1 252:0 / / rw,relatime shared:1 - ext4 /dev/mapper/vg-root rw\n" +
		"95 22 0:45 / /mnt/my\\040data rw,nosuid master:2 - tmpfs tmp\\040fs rw,size=1024k\n" +
		"96 22 0:46 / /srv/nfs rw - nfs4 server:/export rw,vers=4.2\n"
	m := ParseMountInfo([]byte(in))
	if len(m) != 3 || m[1].Point != "/mnt/my data" || m[1].Source != "tmp fs" || m[1].FSType != "tmpfs" ||
		m[2].Source != "server:/export" || m[2].FSType != "nfs4" || m[0].ID != 22 {
		t.Errorf("%+v", m)
	}
}

func TestReadPIDLargeFile(t *testing.T) {
	// A command line longer than the pooled buffer, and one read after it
	// with a short file: the buffer grows and is reused correctly.
	root := t.TempDir()
	long := strings.Repeat("x", 10000)
	for pid, body := range map[string]string{"1": "prog\x00" + long + "\x00", "2": "short\x00arg\x00"} {
		if err := os.MkdirAll(filepath.Join(root, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "cmdline"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := New(root)
	if cmd, _, err := f.ReadCmdline(1); err != nil || cmd != "prog "+long {
		t.Fatalf("long cmdline: %d bytes, %v", len(cmd), err)
	}
	if cmd, _, err := f.ReadCmdline(2); err != nil || cmd != "short arg" {
		t.Fatalf("short cmdline after a long one: %q, %v", cmd, err)
	}
	if _, _, err := f.ReadCmdline(3); !IsGone(err) {
		t.Fatalf("missing process: %v, want gone", err)
	}
}

func BenchmarkReadStatSelf(b *testing.B) {
	f := New("")
	pid := os.Getpid()
	for b.Loop() {
		if _, err := f.ReadStat(pid); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReadStatSelfOSReadFile: the previous way, for comparison.
func BenchmarkReadStatSelfOSReadFile(b *testing.B) {
	p := filepath.Join("/proc", strconv.Itoa(os.Getpid()), "stat")
	for b.Loop() {
		buf, err := os.ReadFile(p)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := ParseStat(buf); err != nil {
			b.Fatal(err)
		}
	}
}
