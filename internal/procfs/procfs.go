// Package procfs parses the parts of /proc that sosv needs. Every path goes
// through FS so tests can point it at a fixture directory (--proc-root).
// It never reads /proc/<pid>/environ.
package procfs

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// ClockTicks is USER_HZ. It is 100 on every Linux architecture sosv targets.
const ClockTicks = 100

type FS struct {
	Root string
}

func New(root string) FS {
	if root == "" {
		root = "/proc"
	}
	return FS{Root: root}
}

func (f FS) path(parts ...string) string {
	return filepath.Join(append([]string{f.Root}, parts...)...)
}

// IsGone reports whether err means the process (or fd) disappeared while we
// were reading it. Callers skip such entries silently.
func IsGone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) ||
		errors.Is(err, syscall.ENOENT) || errors.Is(err, errShort)
}

var errShort = errors.New("short or malformed file")

// PIDs lists the numeric entries of the proc root (processes, not threads).
func (f FS) PIDs() ([]int, error) {
	d, err := os.Open(f.Root)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0, len(names))
	for _, n := range names {
		if n[0] < '0' || n[0] > '9' {
			continue
		}
		if pid, err := strconv.Atoi(n); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// Stat holds the fields of /proc/<pid>/stat that sosv uses.
type Stat struct {
	PID        int
	Comm       string
	State      byte
	PPID       int
	PGRP       int
	Session    int
	TTY        int // tty_nr, encoded device number
	TPGID      int
	Utime      uint64 // clock ticks
	Stime      uint64
	Nice       int
	NumThreads int
	StartTime  uint64 // clock ticks after boot
	VSize      uint64 // bytes
	RSS        int64  // pages
}

func (f FS) ReadStat(pid int) (Stat, error) {
	b, err := os.ReadFile(f.path(strconv.Itoa(pid), "stat"))
	if err != nil {
		return Stat{}, err
	}
	return ParseStat(b)
}

// ParseStat parses /proc/<pid>/stat. comm may contain spaces and parentheses,
// so it is delimited by the first '(' and the last ')'.
func ParseStat(b []byte) (Stat, error) {
	var s Stat
	open := bytes.IndexByte(b, '(')
	close := bytes.LastIndexByte(b, ')')
	if open < 0 || close < open {
		return s, errShort
	}
	pid, err := strconv.Atoi(string(bytes.TrimSpace(b[:open])))
	if err != nil {
		return s, errShort
	}
	s.PID = pid
	s.Comm = string(b[open+1 : close])
	rest := strings.Fields(string(b[close+1:]))
	// rest[0] is field 3 (state); field n is rest[n-3]. We need up to field 24.
	if len(rest) < 22 {
		return s, errShort
	}
	field := func(n int) string { return rest[n-3] }
	s.State = field(3)[0]
	s.PPID = atoi(field(4))
	s.PGRP = atoi(field(5))
	s.Session = atoi(field(6))
	s.TTY = atoi(field(7))
	s.TPGID = atoi(field(8))
	s.Utime = atou(field(14))
	s.Stime = atou(field(15))
	s.Nice = atoi(field(19))
	s.NumThreads = atoi(field(20))
	s.StartTime = atou(field(22))
	s.VSize = atou(field(23))
	s.RSS = int64(atoi(field(24)))
	return s, nil
}

// ReadStatm returns total program size and resident set size in pages.
// RSS comes from statm rather than stat: since kernel 6.2 the stat value is
// an approximate per-CPU counter while statm (like ps) uses the exact sum.
func (f FS) ReadStatm(pid int) (size, resident int64, err error) {
	b, err := os.ReadFile(f.path(strconv.Itoa(pid), "statm"))
	if err != nil {
		return 0, 0, err
	}
	return ParseStatm(b)
}

func ParseStatm(b []byte) (size, resident int64, err error) {
	fs := strings.Fields(string(b))
	if len(fs) < 2 {
		return 0, 0, errShort
	}
	return int64(atoi(fs[0])), int64(atoi(fs[1])), nil
}

// Status holds the fields of /proc/<pid>/status that sosv uses.
type Status struct {
	UID    int // effective uid, what `ps aux` shows as USER
	VmLckK int64
}

func (f FS) ReadStatus(pid int) (Status, error) {
	b, err := os.ReadFile(f.path(strconv.Itoa(pid), "status"))
	if err != nil {
		return Status{}, err
	}
	return ParseStatus(b)
}

func ParseStatus(b []byte) (Status, error) {
	var s Status
	found := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Uid:"):
			fs := strings.Fields(line[4:])
			if len(fs) >= 2 {
				s.UID = atoi(fs[1])
				found = true
			}
		case strings.HasPrefix(line, "VmLck:"):
			fs := strings.Fields(line[6:])
			if len(fs) >= 1 {
				s.VmLckK = int64(atoi(fs[0]))
			}
		}
	}
	if !found {
		return s, errShort
	}
	return s, nil
}

// ReadCmdline returns argv joined by spaces, or "" for kernel threads and
// zombies.
func (f FS) ReadCmdline(pid int) (string, error) {
	b, err := os.ReadFile(f.path(strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return "", err
	}
	return ParseCmdline(b), nil
}

func ParseCmdline(b []byte) string {
	b = bytes.TrimRight(b, "\x00")
	return string(bytes.ReplaceAll(b, []byte{0}, []byte{' '}))
}

// FD is one entry of /proc/<pid>/fd, or one of the special links
// cwd, rtd (root) and txt (exe), which use negative numbers.
type FD struct {
	Num    int
	Target string
}

const (
	FDCwd = -1
	FDRtd = -2
	FDTxt = -3
)

// ReadFDs lists /proc/<pid>/fd and resolves each link. If socketsOnly is set,
// only "socket:[inode]" targets are returned (the link still has to be read).
func (f FS) ReadFDs(pid int, socketsOnly bool) ([]FD, error) {
	dir := f.path(strconv.Itoa(pid), "fd")
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return nil, err
	}
	out := make([]FD, 0, len(names))
	for _, n := range names {
		num, err := strconv.Atoi(n)
		if err != nil {
			continue
		}
		t, err := os.Readlink(dir + "/" + n)
		if err != nil {
			continue // fd closed between readdir and readlink
		}
		if socketsOnly && !strings.HasPrefix(t, "socket:[") {
			continue
		}
		out = append(out, FD{Num: num, Target: t})
	}
	return out, nil
}

// ReadSpecialLinks returns cwd, root and exe links (as lsof's cwd/rtd/txt).
// Missing or unreadable links (kernel threads) are skipped.
func (f FS) ReadSpecialLinks(pid int) []FD {
	var out []FD
	base := f.path(strconv.Itoa(pid))
	for _, l := range []struct {
		name string
		num  int
	}{{"cwd", FDCwd}, {"root", FDRtd}, {"exe", FDTxt}} {
		if t, err := os.Readlink(base + "/" + l.name); err == nil {
			out = append(out, FD{Num: l.num, Target: t})
		}
	}
	return out
}

// SocketInode extracts the inode from a "socket:[12345]" link target.
func SocketInode(target string) (uint64, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	n, err := strconv.ParseUint(target[8:len(target)-1], 10, 64)
	return n, err == nil
}

// BootTime returns btime from /proc/stat (Unix seconds).
func (f FS) BootTime() (int64, error) {
	b, err := os.ReadFile(f.path("stat"))
	if err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			return strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
	}
	return 0, fmt.Errorf("btime not found in %s", f.path("stat"))
}

// MemTotalKB returns MemTotal from /proc/meminfo.
func (f FS) MemTotalKB() (int64, error) {
	b, err := os.ReadFile(f.path("meminfo"))
	if err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			fs := strings.Fields(v)
			if len(fs) > 0 {
				return strconv.ParseInt(fs[0], 10, 64)
			}
		}
	}
	return 0, fmt.Errorf("MemTotal not found")
}

// TTYName converts tty_nr to the name ps shows ("pts/0", "tty1", "?").
func TTYName(ttyNr int) string {
	if ttyNr == 0 {
		return "?"
	}
	major := (ttyNr >> 8) & 0xfff
	minor := (ttyNr & 0xff) | ((ttyNr >> 12) & 0xfff00)
	switch {
	case major >= 136 && major <= 143:
		return fmt.Sprintf("pts/%d", minor+(major-136)*256)
	case major == 4 && minor < 64:
		return fmt.Sprintf("tty%d", minor)
	case major == 4:
		return fmt.Sprintf("ttyS%d", minor-64)
	case major == 5 && minor == 1:
		return "console"
	}
	return "?"
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func atou(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}
