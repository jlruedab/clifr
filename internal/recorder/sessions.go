package recorder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// Login sessions (who, w, last; 2026-11-20): three snapshots sources.
//
//   - "utmp": every record of /run/utmp (RHEL 8/9, Ubuntu 22.04), one line
//     per slot, keyed "#n" by its position in the file (who lists in that
//     order; BOOT_TIME and RUN_LVL share id and line):
//     "type\tpid\tline\tid\tuser\thost\ttermination\texit\tsession\tsec\tusec\taddr".
//   - "logind": systemd-logind's sessions, /run/systemd/sessions/ID (where
//     there is no utmp, Ubuntu 25.10+, who and w ask logind), keyed by the
//     session id in directory order, "ID=id" and the "KEY=value" fields of logindKeys only,
//     tab-separated (no device list, controller or file descriptors).
//   - "ttyatime": each session's terminal device, "tty\tatime_ms\tmode\ttty_nr"
//     (mode octal): IDLE is the time since the terminal's last access, who -T
//     its group write bit; tty_nr the device as /proc/PID/stat has it (w).
//
// utmp and logind are read at every system sample and, through inotify,
// 200 ms after a change, so a login or logout is recorded within a second;
// ttyatime at system samples.

var (
	utmpPath  = "/run/utmp"
	logindDir = "/run/systemd/sessions"
	devDir    = "/dev"
)

// utmpRecSize: glibc's struct utmp on 64-bit Linux (x86_64, arm64: 32-bit
// ut_session and ut_tv for the 32-bit ABI's sake).
const utmpRecSize = 384

// utmp record types (utmp.h).
const (
	utmpUserProcess = 7
)

// logindKeys are the fields of a logind session file recorded, in this
// order.
var logindKeys = []string{"UID", "USER", "ACTIVE", "IS_DISPLAY", "STATE", "REMOTE", "TYPE", "CLASS", "SCOPE",
	"SEAT", "TTY", "DISPLAY", "REMOTE_HOST", "REMOTE_USER", "SERVICE", "VTNR", "LEADER", "REALTIME", "MONOTONIC"}

// sessDebounce: how long the watcher waits after a change for more.
const sessDebounce = 200 * time.Millisecond

// cstr is a fixed-size C string field as text: up to the first NUL, bytes
// below 0x20, 0x7f and '\\' as \xNN (a field never holds a tab or newline).
func cstr(b []byte) string {
	if i := slices.Index(b, 0); i >= 0 {
		b = b[:i]
	}
	return escField(string(b))
}

func escField(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f || c == '\\' {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f || c == '\\' {
			sb.WriteString(`\x`)
			sb.WriteString(strconv.FormatUint(uint64(c)>>4, 16))
			sb.WriteString(strconv.FormatUint(uint64(c)&15, 16))
			continue
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// parseUtmp turns utmp's records into the "utmp" source's lines.
func parseUtmp(data []byte) []procfs.SnapLine {
	le := binary.LittleEndian
	out := make([]procfs.SnapLine, 0, len(data)/utmpRecSize)
	for i := 0; i+utmpRecSize <= len(data); i += utmpRecSize {
		rec := data[i : i+utmpRecSize]
		addr := ""
		var a [16]byte
		copy(a[:], rec[348:364])
		if a != [16]byte{} {
			// IPv4 in the first word only, else IPv6 (w -i prints it)
			if [12]byte(a[4:16]) == [12]byte{} {
				addr = netip.AddrFrom4([4]byte(a[:4])).String()
			} else {
				addr = netip.AddrFrom16(a).String()
			}
		}
		f := []string{
			strconv.Itoa(int(int16(le.Uint16(rec[0:])))),
			strconv.Itoa(int(int32(le.Uint32(rec[4:])))),
			cstr(rec[8:40]),
			cstr(rec[40:44]),
			cstr(rec[44:76]),
			cstr(rec[76:332]),
			strconv.Itoa(int(int16(le.Uint16(rec[332:])))),
			strconv.Itoa(int(int16(le.Uint16(rec[334:])))),
			strconv.Itoa(int(int32(le.Uint32(rec[336:])))),
			strconv.Itoa(int(int32(le.Uint32(rec[340:])))),
			strconv.Itoa(int(int32(le.Uint32(rec[344:])))),
			addr,
		}
		out = append(out, procfs.SnapLine{Key: "#" + strconv.Itoa(i/utmpRecSize), Line: strings.Join(f, "\t")})
	}
	return out
}

// readUtmp reads /run/utmp; none (nil, nil) where there is no such file.
func readUtmp() ([]procfs.SnapLine, bool, error) {
	data, err := os.ReadFile(utmpPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return parseUtmp(data), true, nil
}

// readLogind reads logind's session files in directory order (as
// sd_get_sessions lists them); none where logind keeps no sessions.
func readLogind() ([]procfs.SnapLine, bool, error) {
	d, err := os.Open(logindDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	names, err := d.Readdirnames(-1) // unsorted: the directory's order
	d.Close()
	if err != nil {
		return nil, false, err
	}
	out := make([]procfs.SnapLine, 0, len(names))
	for _, n := range names {
		if n == "" || strings.ContainsAny(n, ".#") { // temporary files, N.ref FIFOs
			continue
		}
		data, err := os.ReadFile(filepath.Join(logindDir, n))
		if err != nil {
			continue // gone since the listing
		}
		vals := map[string]string{}
		for _, l := range strings.Split(string(data), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(k, "#") {
				vals[k] = v
			}
		}
		f := make([]string, 0, len(logindKeys)+1)
		f = append(f, "ID="+escField(n)) // who orders sessions by id
		for _, k := range logindKeys {
			if v, ok := vals[k]; ok {
				f = append(f, k+"="+escField(v))
			}
		}
		out = append(out, procfs.SnapLine{Key: escField(n), Line: strings.Join(f, "\t")})
	}
	return out, true, nil
}

// sessionTTYs are the terminals of the sessions in the last utmp and
// logind lines: utmp's user processes, logind's TTY.
func sessionTTYs(utmp, logind map[string]string) []string {
	seen := map[string]bool{}
	for _, l := range utmp {
		f := strings.Split(l, "\t")
		if len(f) > 2 && f[0] == strconv.Itoa(utmpUserProcess) {
			seen[strings.TrimPrefix(f[2], "/dev/")] = true
		}
	}
	for _, l := range logind {
		for _, kv := range strings.Split(l, "\t") {
			if v, ok := strings.CutPrefix(kv, "TTY="); ok {
				seen[strings.TrimPrefix(v, "/dev/")] = true
			}
		}
	}
	var out []string
	for t := range seen {
		if t != "" && !strings.Contains(t, "..") && !strings.HasPrefix(t, "/") && !strings.Contains(t, `\`) {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return out
}

// readTTYAtimes stats each terminal device: its last access (IDLE) and
// mode. Terminals that are not devices (":0", gone) are left out.
func readTTYAtimes(ttys []string) []procfs.SnapLine {
	out := make([]procfs.SnapLine, 0, len(ttys))
	for _, t := range ttys {
		var st unix.Stat_t
		if err := unix.Stat(filepath.Join(devDir, t), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
			continue
		}
		atime := st.Atim.Sec*1000 + st.Atim.Nsec/1e6
		maj, min := unix.Major(st.Rdev), unix.Minor(st.Rdev)
		ttyNr := min&0xff | maj<<8 | (min&^0xff)<<12 // as /proc/PID/stat's tty_nr: w matches processes by it
		out = append(out, procfs.SnapLine{Key: t, Line: t + "\t" + strconv.FormatInt(atime, 10) + "\t" +
			strconv.FormatUint(uint64(st.Mode&0o7777), 8) + "\t" + strconv.FormatUint(uint64(ttyNr), 10)})
	}
	return out
}

// sessRead is one read of utmp and logind.
type sessRead struct {
	ts                   int64
	utmp, logind         []procfs.SnapLine
	haveUtmp, haveLogind bool
	errUtmp, errLogind   error
}

func readSessions() sessRead {
	rd := sessRead{ts: time.Now().UnixMilli()}
	rd.utmp, rd.haveUtmp, rd.errUtmp = readUtmp()
	rd.logind, rd.haveLogind, rd.errLogind = readLogind()
	return rd
}

// sessWatch holds the watcher's reads until the next system sample. Reads
// are made under mu, the sample's own read too, so their times are in
// order: none is older than a read already written.
type sessWatch struct {
	mu    sync.Mutex
	reads []sessRead
}

// takeAndRead returns the watcher's reads and a read made now.
func (w *sessWatch) takeAndRead() []sessRead {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := append(w.reads, readSessions())
	w.reads = nil
	return out
}

func (w *sessWatch) read() {
	w.mu.Lock()
	w.reads = append(w.reads, readSessions())
	w.mu.Unlock()
}

// sampleSessions adds the sessions' rows at a system sample: the watcher's
// reads since the last sample, each at its time, then a read made now and
// the terminals' access times.
func (r *Recorder) sampleSessions(b *store.Batch, fail func(string, error) bool) {
	var reads []sessRead
	if r.sessions != nil {
		reads = r.sessions.takeAndRead()
	} else {
		reads = []sessRead{readSessions()}
	}
	for _, rd := range reads {
		if !fail("utmp", rd.errUtmp) && (rd.haveUtmp || r.sys.snaps["utmp"] != nil) {
			r.snapRows(rd.ts, b, "utmp", rd.utmp) // a file removed: an empty source
		}
		if !fail("logind sessions", rd.errLogind) && (rd.haveLogind || r.sys.snaps["logind"] != nil) {
			r.snapRows(rd.ts, b, "logind", rd.logind)
		}
	}
	var utmp, logind map[string]string
	if st := r.sys.snaps["utmp"]; st != nil {
		utmp = st.lines
	}
	if st := r.sys.snaps["logind"]; st != nil {
		logind = st.lines
	}
	ttys := sessionTTYs(utmp, logind)
	if len(ttys) > 0 || r.sys.snaps["ttyatime"] != nil {
		r.snapRows(reads[len(reads)-1].ts, b, "ttyatime", readTTYAtimes(ttys))
	}
}

// startSessions watches utmp and logind's session directory with inotify
// and reads both sessDebounce after a change. Without inotify the system
// samples still read them.
func (r *Recorder) startSessions(done <-chan struct{}) (stop func()) {
	if r.fs.Root != "/proc" {
		return nil // fixtures: the sessions are this machine's
	}
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		r.log.Warnf("login sessions: inotify: %v (read at system samples only)", err)
		return nil
	}
	w := &sessWatch{}
	r.sessions = w
	type watch struct {
		path string
		mask uint32
		wd   int
	}
	watches := []*watch{
		{utmpPath, unix.IN_MODIFY | unix.IN_CLOSE_WRITE | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF, -1},
		{logindDir, unix.IN_CREATE | unix.IN_MOVED_TO | unix.IN_MOVED_FROM | unix.IN_DELETE | unix.IN_CLOSE_WRITE |
			unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_ONLYDIR, -1},
	}
	add := func() {
		for _, wt := range watches {
			if wt.wd < 0 {
				if wd, err := unix.InotifyAddWatch(fd, wt.path, wt.mask); err == nil {
					wt.wd = wd
				}
			}
		}
	}
	add()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer unix.Close(fd)
		buf := make([]byte, 4096)
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		var due time.Time // a read is due then
		lastAdd := time.Now()
		for {
			select {
			case <-done:
				return
			default:
			}
			wait := 1000
			if !due.IsZero() {
				if d := time.Until(due); d <= 0 {
					w.read()
					due = time.Time{}
				} else {
					wait = int(d/time.Millisecond) + 1
				}
			}
			if time.Since(lastAdd) >= 10*time.Second { // utmp created later, a watch dropped
				add()
				lastAdd = time.Now()
			}
			if _, err := unix.Poll(fds, wait); err != nil && err != unix.EINTR {
				r.log.Errorf("login sessions: %v", err)
				return
			}
			n, err := unix.Read(fd, buf)
			if err != nil {
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
					continue
				}
				r.log.Errorf("login sessions: %v", err)
				return
			}
			for off := 0; off+unix.SizeofInotifyEvent <= n; {
				ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
				name := ""
				if ev.Len > 0 && off+unix.SizeofInotifyEvent+int(ev.Len) <= n {
					nb := buf[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+int(ev.Len)]
					name = string(bytes.TrimRight(nb, "\x00"))
				}
				off += unix.SizeofInotifyEvent + int(ev.Len)
				if ev.Mask&unix.IN_IGNORED != 0 {
					for _, wt := range watches {
						if wt.wd == int(ev.Wd) {
							wt.wd = -1
						}
					}
				}
				if strings.ContainsAny(name, ".#") { // logind's temporary files
					continue
				}
				if due.IsZero() {
					due = time.Now().Add(sessDebounce)
				}
			}
		}
	}()
	return wg.Wait
}
