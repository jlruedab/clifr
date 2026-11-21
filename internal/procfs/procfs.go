// Package procfs parses the parts of /proc that clifr needs. Every path goes
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
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ClockTicks is USER_HZ. It is 100 on every Linux architecture clifr targets.
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

// bufPool holds the buffers of readPID.
var bufPool = sync.Pool{New: func() any { b := make([]byte, 4096); return &b }}

// readPID reads <root>/<pid>/<name> with raw system calls into a pooled
// buffer and passes it to parse, which must not keep it. Per file that is
// openat, read and close: os.ReadFile also stats the file, goes through the
// runtime's poller and allocates the path and the contents (together a
// sixth of the recorder's CPU at the busy load). A read shorter than the
// space left is the end of the file: /proc fills a read as far as it can,
// and so does a regular file in a fixture.
func (f FS) readPID(pid int, name string, parse func([]byte) error) error {
	_, err := f.readPIDMax(pid, name, 0, parse)
	return err
}

// readPIDMax is readPID that passes at most max bytes to parse (0: no
// limit) and reports whether the file was longer (it reads at most twice
// max to find out).
func (f FS) readPIDMax(pid int, name string, max int, parse func([]byte) error) (cut bool, err error) {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	var pathBuf [128]byte // the NUL-terminated path, without allocating
	path := append(pathBuf[:0], f.Root...)
	path = append(path, '/')
	path = strconv.AppendInt(path, int64(pid), 10)
	path = append(path, '/')
	path = append(path, name...)
	path = append(path, 0)
	fd, err := openat(path)
	if err != nil {
		return false, &fs.PathError{Op: "open", Path: string(path[:len(path)-1]), Err: err}
	}
	defer unix.Close(fd)
	n := 0
	for {
		m, err := unix.Read(fd, buf[n:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return false, &fs.PathError{Op: "read", Path: string(path[:len(path)-1]), Err: err}
		}
		n += m
		if m == 0 || n < len(buf) {
			break
		}
		if max > 0 && n > max {
			return true, parse(buf[:max])
		}
		buf = append(buf, make([]byte, len(buf))...) // full: grow and read on
		*bp = buf
	}
	if max > 0 && n > max { // a short read past max
		return true, parse(buf[:max])
	}
	return false, parse(buf[:n])
}

var atFDCWD = unix.AT_FDCWD // a variable: the constant is negative

// openat opens a NUL-terminated path read-only.
func openat(path []byte) (int, error) {
	for {
		fd, _, e := unix.Syscall6(unix.SYS_OPENAT, uintptr(atFDCWD), uintptr(unsafe.Pointer(&path[0])),
			uintptr(unix.O_RDONLY|unix.O_CLOEXEC), 0, 0, 0)
		if e == unix.EINTR {
			continue
		}
		if e != 0 {
			return -1, e
		}
		return int(fd), nil
	}
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

// Stat holds the fields of /proc/<pid>/stat that clifr uses.
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
	Flags      uint64 // PF_* (include/linux/sched.h)
	MinFlt     uint64
	MajFlt     uint64
	Priority   int // top's PR: 20 + nice, or -1 - rt_priority (-100: "rt")
	Processor  int // CPU it last ran on
	RTPriority int
	Policy     int    // SCHED_*: 0 other, 1 fifo, 2 rr, 3 batch, 5 idle, 6 deadline
	BlkioTicks uint64 // delay waiting for block I/O (delay accounting; else 0)
	GuestTime  uint64 // ticks running a virtual CPU (included in Utime)
}

func (f FS) ReadStat(pid int) (st Stat, err error) {
	err = f.readPID(pid, "stat", func(b []byte) (err error) { st, err = ParseStat(b); return })
	return
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
	s.Flags = atou(field(9))
	s.MinFlt = atou(field(10))
	s.MajFlt = atou(field(12))
	s.Priority = atoi(field(18))
	if len(rest) >= 39 { // fields 39-41 since Linux 2.5
		s.Processor = atoi(field(39))
		s.RTPriority = atoi(field(40))
		s.Policy = atoi(field(41))
	}
	if len(rest) >= 41 { // fields 42-43 since Linux 2.6.18 / 2.6.24
		s.BlkioTicks = atou(field(42))
		s.GuestTime = atou(field(43))
	}
	return s, nil
}

// ReadStatm returns total program size, resident set size and its shared
// part (file and shmem pages: top's SHR) in pages. RSS comes from statm
// rather than stat: since kernel 6.2 the stat value is an approximate per-CPU
// counter while statm (like ps) uses the exact sum.
func (f FS) ReadStatm(pid int) (size, resident, shared int64, err error) {
	err = f.readPID(pid, "statm", func(b []byte) (err error) { size, resident, shared, err = ParseStatm(b); return })
	return
}

func ParseStatm(b []byte) (size, resident, shared int64, err error) {
	fs := strings.Fields(string(b))
	if len(fs) < 3 {
		return 0, 0, 0, errShort
	}
	return int64(atoi(fs[0])), int64(atoi(fs[1])), int64(atoi(fs[2])), nil
}

// Status holds the fields of /proc/<pid>/status that clifr uses.
type Status struct {
	UID    int // effective uid, what `ps aux` shows as USER
	RUID   int // real uid (pidstat's UID)
	RGID   int // real gid (atop's RGID)
	Tgid   int // process id; differs from the pid for threads
	VmLckK int64
	// Memory segments in kB (atop -m): stack, swapped out, data, text,
	// shared libraries.
	VmStkK, VmSwapK, VmDataK, VmExeK, VmLibK int64
	// Context switches of the main thread (status reports the task's own,
	// not the other threads'): voluntary (waits) and involuntary
	// (preemptions), what pidstat -w shows.
	VolCtx, NonVolCtx int64
}

func (f FS) ReadStatus(pid int) (st Status, err error) {
	err = f.readPID(pid, "status", func(b []byte) (err error) { st, err = ParseStatus(b); return })
	return
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
				s.RUID, s.UID = atoi(fs[0]), atoi(fs[1])
				found = true
			}
		case strings.HasPrefix(line, "Gid:"):
			if fs := strings.Fields(line[4:]); len(fs) >= 1 {
				s.RGID = atoi(fs[0])
			}
		case strings.HasPrefix(line, "VmStk:"):
			s.VmStkK = statusKB(line[6:])
		case strings.HasPrefix(line, "VmSwap:"):
			s.VmSwapK = statusKB(line[7:])
		case strings.HasPrefix(line, "VmData:"):
			s.VmDataK = statusKB(line[7:])
		case strings.HasPrefix(line, "VmExe:"):
			s.VmExeK = statusKB(line[6:])
		case strings.HasPrefix(line, "VmLib:"):
			s.VmLibK = statusKB(line[6:])
		case strings.HasPrefix(line, "Tgid:"):
			s.Tgid = atoi(strings.TrimSpace(line[5:]))
		case strings.HasPrefix(line, "VmLck:"):
			fs := strings.Fields(line[6:])
			if len(fs) >= 1 {
				s.VmLckK = int64(atoi(fs[0]))
			}
		case strings.HasPrefix(line, "voluntary_ctxt_switches:"):
			s.VolCtx = int64(atou(strings.TrimSpace(line[24:])))
		case strings.HasPrefix(line, "nonvoluntary_ctxt_switches:"):
			s.NonVolCtx = int64(atou(strings.TrimSpace(line[27:])))
		}
	}
	if !found {
		return s, errShort
	}
	return s, nil
}

// statusKB is a status line's "N kB" value.
func statusKB(v string) int64 {
	if fs := strings.Fields(v); len(fs) >= 1 {
		return int64(atoi(fs[0]))
	}
	return 0
}

// ReadCmdline returns argv joined by spaces, or "" for kernel threads and
// zombies.
// ReadCmdline returns the command line with its arguments joined by spaces,
// and the length of argv[0] in it (where the first NUL was).
func (f FS) ReadCmdline(pid int) (cmd string, argv0 int, err error) {
	cmd, argv0, _, _, err = f.ReadCmdlinePad(pid, 0)
	return
}

// ReadCmdlinePad is ReadCmdline plus the number of NUL bytes after the
// last argument: 1 normally, more when a process rewrote its arguments in
// place and padded them (postgres, sshd). systemd-cgls counts them.
// Only the first max bytes are kept (0: all); cut reports a longer command
// line, whose padding is then taken as 1.
func (f FS) ReadCmdlinePad(pid, max int) (cmd string, argv0, pad int, cut bool, err error) {
	cut, err = f.readPIDMax(pid, "cmdline", max, func(b []byte) error {
		cmd, argv0 = ParseCmdline(b), Argv0Len(b)
		pad = len(b) - len(bytes.TrimRight(b, "\x00"))
		return nil
	})
	if cut {
		pad = 1
	}
	return
}

// Argv0Len is the length of argv[0] in a raw command line: up to the first
// NUL, or all of it for a process that rewrote its command line as one
// string (net-tools takes the program name from argv[0]).
func Argv0Len(b []byte) int {
	b = bytes.TrimRight(b, "\x00")
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return i
	}
	return len(b)
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

// IO is /proc/<pid>/io: bytes read and written through system calls (rchar,
// wchar) and from/to storage (read_bytes, write_bytes, cancelled_write_bytes).
type IO struct {
	RChar, WChar, ReadBytes, WriteBytes, CancelledWrite int64
}

// ReadIO reads /proc/<pid>/io (root or the process's owner).
func (f FS) ReadIO(pid int) (io IO, err error) {
	err = f.readPID(pid, "io", func(b []byte) error {
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(line, ": ")
			if !ok {
				continue
			}
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			switch k {
			case "rchar":
				io.RChar = n
			case "wchar":
				io.WChar = n
			case "read_bytes":
				io.ReadBytes = n
			case "write_bytes":
				io.WriteBytes = n
			case "cancelled_write_bytes":
				io.CancelledWrite = n
			}
		}
		return nil
	})
	return
}

// ReadRunDelay returns the time the process has waited on a run queue, in
// ns (the second number of /proc/<pid>/schedstat: pidstat's %wait).
func (f FS) ReadRunDelay(pid int) (ns int64, err error) {
	err = f.readPID(pid, "schedstat", func(b []byte) error {
		fs := strings.Fields(string(b))
		if len(fs) < 2 {
			return errShort
		}
		ns = int64(atou(fs[1]))
		return nil
	})
	return
}

// Threads is what atop adds up over a process's live threads: their
// run-queue wait (schedstat), block-I/O delay (stat, clock ticks) and
// context switches (status), and how many are in each state (stat).
type Threads struct {
	RunDelayNS, BlkioTicks    int64
	VolCtx, NonVolCtx         int64
	Run, SleepI, SleepU, Idle int // R, S, D, I
}

// ReadThreads reads /proc/<pid>/task/*/{schedstat,stat,status}. A thread
// gone between the listing and its files is left out.
func (f FS) ReadThreads(pid int) (t Threads, err error) {
	d, err := os.Open(f.path(strconv.Itoa(pid), "task"))
	if err != nil {
		return t, err
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return t, err
	}
	read := 0
	for _, n := range names {
		if n == "" || n[0] < '0' || n[0] > '9' {
			continue
		}
		dir := "task/" + n + "/"
		var st Stat
		err := f.readPID(pid, dir+"stat", func(b []byte) (err error) { st, err = ParseStat(b); return })
		if err != nil {
			continue
		}
		read++
		switch st.State {
		case 'R':
			t.Run++
		case 'S':
			t.SleepI++
		case 'D':
			t.SleepU++
		case 'I':
			t.Idle++
		}
		t.BlkioTicks += int64(st.BlkioTicks)
		f.readPID(pid, dir+"schedstat", func(b []byte) error {
			if fs := strings.Fields(string(b)); len(fs) >= 2 {
				t.RunDelayNS += int64(atou(fs[1]))
			}
			return nil
		})
		f.readPID(pid, dir+"status", func(b []byte) error {
			if s, err := ParseStatus(b); err == nil {
				t.VolCtx += s.VolCtx
				t.NonVolCtx += s.NonVolCtx
			}
			return nil
		})
	}
	if read == 0 {
		return t, errShort
	}
	return t, nil
}

// ReadWchan returns /proc/<pid>/wchan: the kernel function the process
// waits in, or "0" while it runs (Linux 5.16+: also for a process the
// kernel cannot unwind).
func (f FS) ReadWchan(pid int) (w string, err error) {
	err = f.readPID(pid, "wchan", func(b []byte) error { w = string(b); return nil })
	return
}

// ReadLabel returns the security label of the process
// (/proc/<pid>/attr/current: SELinux context, AppArmor profile), what
// ps -Z prints as LABEL; an error without a security module that has one.
func (f FS) ReadLabel(pid int) (l string, err error) {
	err = f.readPID(pid, "attr/current", func(b []byte) error {
		l = strings.TrimRight(string(b), "\x00\n")
		return nil
	})
	return
}

// ReadCgroup returns /proc/<pid>/cgroup without its final newline: one line
// per hierarchy, "0::/path" on the unified hierarchy (cgroup v2).
// ReadNetNS returns the process's network namespace: the inode number in
// its /proc/<pid>/ns/net link ("net:[4026531840]").
func (f FS) ReadNetNS(pid int) (uint32, error) {
	l, err := os.Readlink(f.path(strconv.Itoa(pid), "ns", "net"))
	if err != nil {
		return 0, err
	}
	s, ok := strings.CutPrefix(l, "net:[")
	if !ok || !strings.HasSuffix(s, "]") {
		return 0, fmt.Errorf("ns/net of %d: %q", pid, l)
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 32)
	return uint32(n), err
}

// PIDDir is /proc/<pid> (under the root): its net/ files are the process's
// network namespace's.
func (f FS) PIDDir(pid int) string { return f.path(strconv.Itoa(pid)) }

func (f FS) ReadCgroup(pid int) (c string, err error) {
	err = f.readPID(pid, "cgroup", func(b []byte) error { c = strings.TrimRight(string(b), "\n"); return nil })
	return
}

// SystemdCgroup picks from /proc/<pid>/cgroup the path in the hierarchy
// systemd uses (what systemd-cgls shows): name=systemd's on cgroup v1 and
// hybrid systems, else the unified one ("0::/path"). v1 is true for the
// former (its directory is /sys/fs/cgroup/systemd, else /sys/fs/cgroup).
func SystemdCgroup(cgroup string) (path string, v1, ok bool) {
	for _, l := range strings.Split(cgroup, "\n") {
		_, rest, _ := strings.Cut(l, ":")
		ctl, p, found := strings.Cut(rest, ":")
		switch {
		case !found:
		case ctl == "name=systemd":
			return p, true, true
		case ctl == "" && strings.HasPrefix(l, "0:"):
			path, ok = p, true
		}
	}
	return path, false, ok
}

// ReadBootID returns /proc/sys/kernel/random/boot_id, which changes at
// every boot.
func (f FS) ReadBootID() (string, error) {
	b, err := os.ReadFile(f.path("sys", "kernel", "random", "boot_id"))
	return strings.TrimSpace(string(b)), err
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

// ReadFDFlags returns the open flags (octal "flags:" line) of
// /proc/<pid>/fdinfo/<fd>. Only read for newly seen fds.
func (f FS) ReadFDFlags(pid, fd int) (flags uint64, err error) {
	err = f.readPID(pid, "fdinfo/"+strconv.Itoa(fd), func(b []byte) (err error) { flags, err = ParseFDFlags(b); return })
	return
}

func ParseFDFlags(b []byte) (uint64, error) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "flags:"); ok {
			return strconv.ParseUint(strings.TrimSpace(v), 8, 64)
		}
	}
	return 0, errShort
}

// ReadNetUnix maps unix socket inodes to lsof's NAME, e.g.
// "/run/systemd/notify type=DGRAM (CONNECTED)".
func (f FS) ReadNetUnix() (map[uint64]string, error) {
	b, err := os.ReadFile(f.path("net", "unix"))
	if err != nil {
		return nil, err
	}
	return ParseNetUnix(b), nil
}

func ParseNetUnix(b []byte) map[uint64]string {
	out := map[uint64]string{}
	types := map[string]string{"0001": "STREAM", "0002": "DGRAM", "0005": "SEQPACKET"}
	lines := strings.Split(string(b), "\n")
	for _, l := range lines[1:] {
		// Num RefCount Protocol Flags Type St Inode [Path]
		fs := strings.Fields(l)
		if len(fs) < 7 {
			continue
		}
		ino, err := strconv.ParseUint(fs[6], 10, 64)
		if err != nil {
			continue
		}
		state := "UNCONNECTED"
		if flags, _ := strconv.ParseUint(fs[3], 16, 32); flags&0x10000 != 0 {
			state = "LISTEN"
		} else if fs[5] == "03" {
			state = "CONNECTED"
		}
		name := fmt.Sprintf("type=%s (%s)", types[fs[4]], state)
		if len(fs) >= 8 {
			name = fs[7] + " " + name
		}
		out[ino] = name
	}
	return out
}

var netlinkNames = map[int]string{0: "ROUTE", 2: "USERSOCK", 3: "FIREWALL", 4: "SOCK_DIAG", 5: "NFLOG",
	6: "XFRM", 7: "SELINUX", 8: "ISCSI", 9: "AUDIT", 10: "FIB_LOOKUP", 11: "CONNECTOR", 12: "NETFILTER",
	13: "IP6_FW", 14: "DNRTMSG", 15: "KOBJECT_UEVENT", 16: "GENERIC", 18: "SCSITRANSPORT", 19: "ECRYPTFS",
	20: "RDMA", 21: "CRYPTO", 22: "SMC"}

// ReadNetNetlink maps netlink socket inodes to their protocol name.
func (f FS) ReadNetNetlink() (map[uint64]string, error) {
	b, err := os.ReadFile(f.path("net", "netlink"))
	if err != nil {
		return nil, err
	}
	out := map[uint64]string{}
	lines := strings.Split(string(b), "\n")
	for _, l := range lines[1:] {
		// sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode
		fs := strings.Fields(l)
		if len(fs) < 10 {
			continue
		}
		ino, err := strconv.ParseUint(fs[9], 10, 64)
		if err != nil {
			continue
		}
		proto := atoi(fs[1])
		name, ok := netlinkNames[proto]
		if !ok {
			name = strconv.Itoa(proto)
		}
		out[ino] = name
	}
	return out, nil
}

// FDStat is what statx reports about the file behind an fd.
type FDStat struct {
	Mode  uint16 // S_IFMT bits
	Inode uint64
	Size  int64 // as cached: NFS revalidates it only when asked to sync
	Major uint32
	Minor uint32
}

// StatFD stats the file an fd points to with AT_STATX_DONT_SYNC, so a dead
// NFS server returns cached attributes instead of blocking the recorder.
func (f FS) StatFD(pid, fd int) (FDStat, error) {
	var sx unix.Statx_t
	p := f.path(strconv.Itoa(pid), "fd", strconv.Itoa(fd))
	err := unix.Statx(unix.AT_FDCWD, p, unix.AT_STATX_DONT_SYNC, unix.STATX_TYPE|unix.STATX_INO|unix.STATX_SIZE, &sx)
	if err != nil {
		return FDStat{}, err
	}
	return FDStat{Mode: sx.Mode & unix.S_IFMT, Inode: sx.Ino, Size: int64(sx.Size), Major: sx.Dev_major, Minor: sx.Dev_minor}, nil
}

// FDCount returns the number of open fds of pid: the size the kernel reports
// for /proc/<pid>/fd (Linux 6.2+). ok is false when it is unknown (older
// kernels report 0), so callers walk the directory instead.
func (f FS) FDCount(pid int) (n int, ok bool) {
	if f.Root != "/proc" {
		return 0, false // a fixture directory's size is not an fd count
	}
	st, err := os.Stat(f.path(strconv.Itoa(pid), "fd"))
	if err != nil || st.Size() <= 0 {
		return 0, false
	}
	return int(st.Size()), true
}

// MountInfo is one line of /proc/<pid>/mountinfo.
type MountInfo struct {
	ID, ParentID int
	Dev          string // major:minor of the file system
	Root         string // the directory of the file system mounted here
	Point        string
	Source       string
	FSType       string
	Options      string // per mount (VFS)
	SuperOptions string // per file system (super block)
	// Not in mountinfo; what util-linux mount shows (set by the recorder).
	LoopFile    string // backing file of a /dev/loopN source with autoclear set (until 2026-10-23: any)
	UserOptions string // userspace options from /run/mount/utab (x-...)
}

// ReadMountInfo reads /proc/self/mountinfo (the recorder's mount namespace;
// the recorder itself watches the host's, recorder.hostMountNS).
func (f FS) ReadMountInfo() ([]MountInfo, error) {
	b, err := os.ReadFile(f.path("self", "mountinfo"))
	if err != nil {
		return nil, err
	}
	return ParseMountInfo(b), nil
}

// ParseMountInfo parses mountinfo lines:
// 36 35 98:0 /mnt1 /mnt/parent rw,noatime master:1 - ext3 /dev/root rw,errors=continue
func ParseMountInfo(b []byte) []MountInfo {
	var out []MountInfo
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if len(f) < 6 || sep < 0 || sep+2 >= len(f) {
			continue
		}
		m := MountInfo{ID: atoi(f[0]), ParentID: atoi(f[1]), Dev: f[2], Root: UnescapeOctal(f[3]), Point: UnescapeOctal(f[4]),
			Options: f[5], FSType: f[sep+1], Source: UnescapeOctal(f[sep+2])}
		if sep+3 < len(f) {
			m.SuperOptions = f[sep+3]
		}
		out = append(out, m)
	}
	return out
}

// EscapeOctal escapes backslashes and the bytes in chars as \ooo, the
// kernel's escapes in mountinfo (UnescapeOctal undoes it), so that a field
// the recorder joins with others cannot contain their separator: file names
// and process names may hold tabs and newlines.
func EscapeOctal(s, chars string) string {
	if !strings.ContainsAny(s, chars+`\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '\\' || strings.IndexByte(chars, c) >= 0 {
			fmt.Fprintf(&b, "\\%03o", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// UnescapeOctal undoes the kernel's \040-style escaping of spaces etc.
func UnescapeOctal(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
