// Parts of this file follow util-linux's misc-utils/lslocks.c (GPL-2.0-or-later), used under the
// GPL-3.0: see LICENSING.md and packaging/notices/util-linux.txt.

package recorder

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"

	"clifr/internal/procfs"
)

// lockFile is where lslocks finds a lock's file: the fd of the holder and
// the path it links to.
type lockFile struct {
	fd   string
	path string
}

// lockResolver keeps what was found for each lock's file between reads.
type lockResolver struct {
	files map[string]lockFile // "pid ino"
	ofd   map[string]string   // OFD lock (the line without pid) -> "pid\tcomm" of its holder
	ofdOf string              // the OFD lock lines ofd was found for
	ofdAt time.Time           // when they were
}

// ofdScanEvery: the holders of OFD locks are looked for at most this often.
// The scan reads the fdinfo of every fd of every process, and any user can
// change the OFD lock lines at every sample. Until the next scan a new OFD
// lock has no holder (lslocks' pid -1).
const ofdScanEvery = time.Minute

// ofdDue reports whether to look for the holders of these OFD lock lines.
func (r *lockResolver) ofdDue(lines string, now time.Time) bool {
	return lines != r.ofdOf && now.Sub(r.ofdAt) >= ofdScanEvery
}

var locks = &lockResolver{}

// readLocks reads /proc/locks with what lslocks adds to each lock: the
// path and size of the locked file and, for an OFD lock (pid -1), its
// holder from the "lock:" lines of the processes' fdinfo (lslocks 2.41; at
// most every ofdScanEvery).
// Each line is "<the lock line without its ordinal>\t<path>\t<size>\t<holder
// pid>\t<holder command>" (empty when not found), in /proc/locks' order; the
// path and the command with tabs, newlines and backslashes as \ooo (since
// 2026-10-27).
func readLocks() ([]procfs.SnapLine, error) {
	b, err := os.ReadFile("/proc/locks")
	if err != nil {
		return nil, err
	}
	r := locks
	if r.files == nil {
		r.files = map[string]lockFile{}
	}
	text := strings.TrimSuffix(string(b), "\n")
	if text == "" {
		return nil, nil
	}
	lines := strings.Split(text, "\n")
	var ofdLines []string
	for i, l := range lines {
		if _, rest, ok := strings.Cut(l, ": "); ok {
			lines[i] = rest
		}
		if strings.HasPrefix(lines[i], "OFDLCK") {
			ofdLines = append(ofdLines, lines[i])
		}
	}
	if o, now := strings.Join(ofdLines, "\n"), time.Now(); r.ofdDue(o, now) {
		r.ofd, r.ofdOf, r.ofdAt = ofdHolders(ofdLines), o, now
	}
	used := map[string]bool{}
	out := make([]procfs.SnapLine, 0, len(lines))
	seen := map[string]int{}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) > 0 && f[0] == "->" {
			f = f[1:]
		}
		var path, size, holder string
		if len(f) >= 7 {
			pid := f[3]
			if pid == "-1" {
				holder = r.ofd[ofdKey(l)]
				pid, _, _ = strings.Cut(holder, "\t")
			}
			if _, ino, ok := lockDevIno(f[4]); ok && pid != "" && pid != "-1" {
				key := pid + " " + strconv.FormatUint(ino, 10)
				used[key] = true
				var sz int64
				var found bool
				if lf, ok := r.files[key]; ok {
					sz, found = lockFileSize(pid, lf.fd, ino)
					path = lf.path
				}
				if !found {
					var lf lockFile
					lf, sz, found = findLockFile(pid, ino)
					if found {
						r.files[key], path = lf, lf.path
					} else {
						delete(r.files, key)
						path = ""
					}
				}
				if found {
					size = strconv.FormatInt(sz, 10)
				}
			}
		}
		if holder == "" {
			holder = "\t"
		}
		k := l
		if n := seen[l]; n > 0 {
			k += "#" + strconv.Itoa(n)
		}
		seen[l]++
		out = append(out, procfs.SnapLine{Key: k, Line: l + "\t" + procfs.EscapeOctal(path, "\t\n") + "\t" + size + "\t" + holder})
	}
	for k := range r.files {
		if !used[k] {
			delete(r.files, k)
		}
	}
	return out, nil
}

// lockDevIno parses /proc/locks' "MAJ:MIN:INODE" (hex device numbers).
func lockDevIno(s string) (dev string, ino uint64, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, false
	}
	ino, err := strconv.ParseUint(s[i+1:], 10, 64)
	return s[:i], ino, err == nil
}

// procFS: the locks are this machine's (machineSnaps), read from /proc.
var procFS = procfs.New("/proc")

// statLockFD stats the file behind an fd of pid with procfs.StatFD, which
// does not wait for the file system: plain stat(2) of a file on an NFS
// server that stopped answering blocks, and with it every sample.
func statLockFD(pid, fd string) (procfs.FDStat, error) {
	p, err1 := strconv.Atoi(pid)
	n, err2 := strconv.Atoi(fd)
	if err1 != nil || err2 != nil {
		return procfs.FDStat{}, strconv.ErrSyntax
	}
	return procFS.StatFD(p, n)
}

// findLockFile is lslocks' get_filename_sz: the first fd of pid (not 0:
// lslocks skips it) on inode ino, or that it cannot stat, and its link.
func findLockFile(pid string, ino uint64) (lockFile, int64, bool) {
	dir := "/proc/" + pid + "/fd/"
	d, err := os.Open(dir)
	if err != nil {
		return lockFile{}, 0, false
	}
	names, _ := d.Readdirnames(-1)
	d.Close()
	for _, n := range names {
		if v, err := strconv.Atoi(n); err != nil || v == 0 {
			continue
		}
		st, statErr := statLockFD(pid, n)
		if statErr == nil && st.Inode != ino {
			continue
		}
		target, err := os.Readlink(dir + n)
		if err != nil || target == "" {
			return lockFile{}, 0, false
		}
		return lockFile{fd: n, path: target}, st.Size, true
	}
	return lockFile{}, 0, false
}

// lockFileSize is the size of the file behind a known fd, if the fd is
// still on that inode.
func lockFileSize(pid, fd string, ino uint64) (int64, bool) {
	st, err := statLockFD(pid, fd)
	if err != nil || st.Inode != ino {
		return 0, false
	}
	return st.Size, true
}

// ofdKey is an OFD lock line without its pid, as fdinfo's "lock:" lines
// give it (lslocks' is_holder compares all but the pid and id).
func ofdKey(line string) string {
	f := strings.Fields(line)
	blocked := len(f) > 0 && f[0] == "->"
	if blocked {
		f = f[1:]
	}
	if len(f) < 7 {
		return line
	}
	return strconv.FormatBool(blocked) + " " + f[0] + " " + f[1] + " " + f[2] + " " + f[4] + " " + f[5] + " " + f[6]
}

// ofdHolders finds the holders of OFD locks as lslocks 2.41 does: the
// first process, in /proc's order, with an fd whose fdinfo has a "lock:"
// line for it. It reads every fd's fdinfo of every process, so it runs only
// when the OFD lock lines change.
func ofdHolders(ofd []string) map[string]string {
	if len(ofd) == 0 {
		return nil
	}
	want := map[string]bool{}
	for _, l := range ofd {
		want[ofdKey(l)] = true
	}
	out := map[string]string{}
	proc, err := os.Open("/proc")
	if err != nil {
		return out
	}
	pids, _ := proc.Readdirnames(-1)
	proc.Close()
	for _, pid := range pids {
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		comm, err := os.ReadFile("/proc/" + pid + "/comm")
		if err != nil {
			continue
		}
		d, err := os.Open("/proc/" + pid + "/fdinfo")
		if err != nil {
			continue
		}
		fds, _ := d.Readdirnames(-1)
		d.Close()
		for _, fd := range fds {
			f, err := os.Open("/proc/" + pid + "/fdinfo/" + fd)
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				l, ok := strings.CutPrefix(sc.Text(), "lock:\t")
				if !ok {
					continue
				}
				if _, rest, ok := strings.Cut(l, ": "); ok {
					l = rest
				}
				if k := ofdKey(l); want[k] {
					if _, done := out[k]; !done {
						out[k] = pid + "\t" + procfs.EscapeOctal(strings.TrimSuffix(string(comm), "\n"), "\t\n")
					}
				}
			}
			f.Close()
		}
		if len(out) == len(want) {
			break
		}
	}
	return out
}
