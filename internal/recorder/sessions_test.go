package recorder

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clifr/internal/store"
)

// utmpRec builds one glibc utmp record.
func utmpRec(typ, pid int, line, id, user, host string, sec int, addr [4]byte) []byte {
	b := make([]byte, utmpRecSize)
	le := binary.LittleEndian
	le.PutUint16(b[0:], uint16(typ))
	le.PutUint32(b[4:], uint32(pid))
	copy(b[8:40], line)
	copy(b[40:44], id)
	copy(b[44:76], user)
	copy(b[76:332], host)
	le.PutUint32(b[336:], 7)
	le.PutUint32(b[340:], uint32(sec))
	le.PutUint32(b[344:], 123456)
	copy(b[348:352], addr[:])
	return b
}

func TestParseUtmp(t *testing.T) {
	var data []byte
	data = append(data, utmpRec(2, 0, "~", "~~", "reboot", "6.8.0", 1700000000, [4]byte{})...)
	data = append(data, utmpRec(1, 51, "~", "~~", "runlevel", "6.8.0", 1700000001, [4]byte{})...)
	data = append(data, utmpRec(7, 4242, "pts/1", "ts/1", "alice", "10.0.0.5", 1700000100, [4]byte{10, 0, 0, 5})...)
	data = append(data, utmpRec(8, 4000, "pts/0", "ts/0", "", "", 1700000050, [4]byte{})...)
	data = append(data, utmpRec(7, 99, "tty1", "tty1", "b\tob", "", 1700000200, [4]byte{})...)
	data = append(data, 1, 2, 3) // a torn record at the end: ignored
	got := parseUtmp(data)
	want := []string{
		"#0=2\t0\t~\t~~\treboot\t6.8.0\t0\t0\t7\t1700000000\t123456\t",
		"#1=1\t51\t~\t~~\trunlevel\t6.8.0\t0\t0\t7\t1700000001\t123456\t",
		"#2=7\t4242\tpts/1\tts/1\talice\t10.0.0.5\t0\t0\t7\t1700000100\t123456\t10.0.0.5",
		"#3=8\t4000\tpts/0\tts/0\t\t\t0\t0\t7\t1700000050\t123456\t",
		`#4=7	99	tty1	tty1	b\x09ob		0	0	7	1700000200	123456	`,
	}
	if len(got) != len(want) {
		t.Fatalf("%d lines, want %d", len(got), len(want))
	}
	for i, l := range got {
		if s := l.Key + "=" + l.Line; s != want[i] {
			t.Errorf("line %d:\n got %q\nwant %q", i, s, want[i])
		}
	}
}

func TestReadLogind(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "3"), []byte("# This is private data. Do not parse.\nUID=1000\nUSER=alice\nACTIVE=1\n"+
		"STATE=active\nREMOTE=1\nTYPE=tty\nCLASS=user\nTTY=pts/2\nREMOTE_HOST=10.1.2.3\nSERVICE=sshd\nLEADER=777\n"+
		"REALTIME=1795067864328231\nDEVICES=13:77 226:0\nCONTROLLER=:1.101\nLEADER_FD_SAVED=1\n"), 0o644)
	os.WriteFile(filepath.Join(dir, ".#3abc"), []byte("UID=1\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "3.ref"), nil, 0o644)
	old := logindDir
	logindDir = dir
	defer func() { logindDir = old }()
	lines, ok, err := readLogind()
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if len(lines) != 1 || lines[0].Key != "3" {
		t.Fatalf("got %v", lines)
	}
	want := "ID=3\tUID=1000\tUSER=alice\tACTIVE=1\tSTATE=active\tREMOTE=1\tTYPE=tty\tCLASS=user\tTTY=pts/2\tREMOTE_HOST=10.1.2.3\tSERVICE=sshd\tLEADER=777\tREALTIME=1795067864328231"
	if lines[0].Line != want {
		t.Errorf("got  %q\nwant %q", lines[0].Line, want)
	}
	logindDir = filepath.Join(dir, "none")
	if lines, ok, err := readLogind(); ok || err != nil || lines != nil {
		t.Errorf("no directory: %v %v %v", lines, ok, err)
	}
}

func TestSessionTTYs(t *testing.T) {
	utmp := map[string]string{
		"#0": "2\t0\t~\t~~\treboot\t\t0\t0\t0\t1\t0\t",
		"#1": "7\t1\tpts/1\tts/1\talice\t\t0\t0\t0\t1\t0\t",
		"#2": "8\t1\tpts/9\tts/9\t\t\t0\t0\t0\t1\t0\t",  // dead: not a session
		"#3": "7\t1\t../etc\tx\tbob\t\t0\t0\t0\t1\t0\t", // never outside /dev
		"#4": "7\t1\t/dev/tty3\tx\tbob\t\t0\t0\t0\t1\t0\t",
	}
	logind := map[string]string{"3": "UID=1000\tTTY=tty2", "1": "UID=1000\tCLASS=manager"}
	if got := strings.Join(sessionTTYs(utmp, logind), ","); got != "pts/1,tty2,tty3" {
		t.Errorf("got %s", got)
	}
	old := devDir
	devDir = "/dev"
	defer func() { devDir = old }()
	got := readTTYAtimes([]string{"null", "nonexistent-tty", "shm"}) // shm: a directory
	if len(got) != 1 || got[0].Key != "null" || !strings.HasPrefix(got[0].Line, "null\t") || !strings.HasSuffix(got[0].Line, "\t666\t259") {
		t.Errorf("got %v", got)
	}
}

// TestSampleSessions: a login, a logout and the file going away, as rows of
// the snapshots table.
func TestSampleSessions(t *testing.T) {
	dir := t.TempDir()
	oldU, oldL, oldD := utmpPath, logindDir, devDir
	utmpPath, logindDir, devDir = filepath.Join(dir, "utmp"), filepath.Join(dir, "sessions"), "/dev"
	defer func() { utmpPath, logindDir, devDir = oldU, oldL, oldD }()
	r := &Recorder{sys: newSysSampler("/proc")}
	r.sys.snaps = map[string]*snapState{}
	fail := func(string, error) bool { return false }
	sample := func() []store.SnapshotRow {
		var b store.Batch
		r.sampleSessions(&b, fail)
		return b.Snapshots
	}
	if rows := sample(); len(rows) != 0 { // neither exists: nothing
		t.Fatalf("no files: %v", rows)
	}
	boot := utmpRec(2, 0, "~", "~~", "reboot", "", 1, [4]byte{})
	os.WriteFile(utmpPath, boot, 0o644)
	if rows := sample(); len(rows) != 1 || !rows[0].Full || rows[0].Source != "utmp" {
		t.Fatalf("first read: %v", rows)
	}
	if rows := sample(); len(rows) != 0 {
		t.Fatalf("unchanged: %v", rows)
	}
	os.WriteFile(utmpPath, append(boot, utmpRec(7, 5, "null", "null", "alice", "", 2, [4]byte{})...), 0o644)
	rows := sample() // a new slot: keys changed, whole; and /dev/null's access time
	var utmpRows, ttyRows int
	for _, r := range rows {
		switch r.Source {
		case "utmp":
			utmpRows++
		case "ttyatime":
			ttyRows++
			if r.Key != "null" {
				t.Errorf("ttyatime %v", r)
			}
		}
	}
	if utmpRows != 2 || ttyRows != 1 {
		t.Fatalf("login: %v", rows)
	}
	os.WriteFile(utmpPath, append(boot, utmpRec(8, 5, "null", "null", "", "", 3, [4]byte{})...), 0o644)
	rows = sample() // the slot reused for DEAD_PROCESS: one changed line, no terminal left
	if len(rows) != 2 || rows[0].Source != "utmp" || rows[0].Full || rows[0].Key != "#1" ||
		rows[1].Source != "ttyatime" || rows[1].Pos != -1 {
		t.Fatalf("logout: %v", rows)
	}
	os.Remove(utmpPath)
	if rows := sample(); len(rows) != 1 || rows[0].Pos != -1 || rows[0].Source != "utmp" {
		t.Fatalf("removed: %v", rows)
	}
}

// BenchmarkReadSessions: one system sample's read on this machine.
func BenchmarkReadSessions(b *testing.B) {
	for b.Loop() {
		rd := readSessions()
		var u, l map[string]string
		if rd.haveLogind {
			l = map[string]string{}
			for _, s := range rd.logind {
				l[s.Key] = s.Line
			}
		}
		readTTYAtimes(sessionTTYs(u, l))
	}
}
