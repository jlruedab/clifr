package recorder

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"clifr/internal/procfs"
)

// sysctlDeprecated are the names sysctl -a leaves out (procps' DEPRECATED).
var sysctlDeprecated = map[string]bool{"base_reachable_time": true, "retrans_time": true}

// readSysctl reads /proc/sys as procps' sysctl -a (3.3 and 4.0 alike)
// walks it: each directory in its own order (procfs: by name; a mounted
// binfmt_misc: its own), deprecated names and files without read
// permission skipped, every line of a file printed as "name = line" with
// the name's '.' and '/' swapped (sysctl's slashdot). Each SnapLine is one
// printed line, keyed by the name ("#n" for a file's later lines).
func readSysctl() ([]procfs.SnapLine, error) {
	var out []procfs.SnapLine
	buf := make([]byte, 4096)
	var walk func(dir string)
	walk = func(dir string) {
		d, err := os.Open(dir)
		if err != nil {
			return
		}
		names, _ := d.Readdirnames(-1) // the directory's order; Go leaves out . and ..
		d.Close()
		for _, n := range names {
			if sysctlDeprecated[n] {
				continue
			}
			p := dir + "/" + n
			var st syscall.Stat_t
			if syscall.Lstat(p, &st) != nil {
				continue
			}
			if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
				// sysctl follows it if it stays under /proc (is_proc_path)
				if real, err := filepath.EvalSymlinks(p); err != nil || !strings.HasPrefix(real, "/proc/") || syscall.Stat(p, &st) != nil {
					continue
				}
			}
			if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
				walk(p)
				continue
			}
			if st.Mode&syscall.S_IRUSR == 0 {
				continue
			}
			name := sysctlName(strings.TrimPrefix(p, "/proc/sys/"))
			fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
			if err != nil {
				continue
			}
			n, err := readAll(fd, &buf)
			syscall.Close(fd)
			if err != nil || n == 0 {
				continue
			}
			text := strings.TrimSuffix(string(buf[:n]), "\n")
			for i, line := range strings.Split(text, "\n") {
				key := name
				if i > 0 {
					key += "#" + strconv.Itoa(i)
				}
				out = append(out, procfs.SnapLine{Key: key, Line: name + " = " + line})
			}
		}
	}
	walk("/proc/sys")
	return out, nil
}

// sysctlName is procps' slashdot(name, '/', '.'): the separators swapped
// ('/' to '.', and a '.' within a name to '/').
func sysctlName(p string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '/':
			return '.'
		case '.':
			return '/'
		}
		return r
	}, p)
}

// readAll reads an open file into *buf, growing it as needed: a /proc file
// fills each read as far as it can, so a short read is its end.
func readAll(fd int, buf *[]byte) (int, error) {
	n := 0
	for {
		if n == len(*buf) {
			*buf = append(*buf, make([]byte, len(*buf))...)
		}
		m, err := syscall.Read(fd, (*buf)[n:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return n, err
		}
		if m == 0 {
			return n, nil
		}
		n += m
	}
}
