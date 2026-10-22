package recorder

import (
	"bytes"
	"path"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// cgroupSeen is what this run last wrote for a cgroup path.
type cgroupSeen struct {
	ts, id int64
}

// noteCgroup writes a cgroups row for the systemd cgroup of a process (from
// /proc/<pid>/cgroup) and for each ancestor that this run has not written
// in the last store.NetSnapshotMS or that was recreated since (a new id: a
// unit restarted, a user logged in again). Ancestors of an unchanged cgroup
// are unchanged too. Only on the real /proc: fixtures have no cgroup file
// system.
func (r *Recorder) noteCgroup(cgroup string, ts int64, b *store.Batch) {
	if !r.sys.sysfs {
		return
	}
	p, v1, ok := procfs.SystemdCgroup(cgroup)
	if !ok {
		return
	}
	root := "/sys/fs/cgroup"
	if v1 {
		root = "/sys/fs/cgroup/systemd"
	}
	for {
		var st syscall.Stat_t
		if err := syscall.Stat(root+p, &st); err != nil {
			return // gone already
		}
		id := int64(st.Ino)
		if last, seen := r.cgroups[p]; seen && last.id == id && ts-last.ts < store.NetSnapshotMS {
			return
		}
		r.cgroups[p] = cgroupSeen{ts: ts, id: id}
		xattrs, delegate := cgroupXattrs(root + p)
		b.Cgroups = append(b.Cgroups, store.CgroupRow{TS: ts, Path: p, Delegate: delegate, ID: id, Xattrs: xattrs})
		if p == "/" || p == "" {
			return
		}
		p = path.Dir(p)
	}
}

// cgroupXattrs returns a cgroup directory's user.* and trusted.* attributes
// as "name=value" lines in the kernel's order, and systemd's
// cg_is_delegated: trusted.delegate, else user.delegate, a boolean.
func cgroupXattrs(dir string) (string, bool) {
	names := make([]byte, 4096)
	n, err := unix.Listxattr(dir, names)
	if err != nil {
		return "", false
	}
	var b strings.Builder
	delegate := map[string]bool{}
	val := make([]byte, 256)
	for _, name := range strings.Split(strings.TrimRight(string(names[:n]), "\x00"), "\x00") {
		if !strings.HasPrefix(name, "user.") && !strings.HasPrefix(name, "trusted.") {
			continue
		}
		m, err := unix.Getxattr(dir, name, val)
		if err != nil { // gone, or longer than systemd's values
			continue
		}
		v := string(bytes.TrimRight(val[:m], "\x00"))
		b.WriteString(name + "=" + v + "\n")
		if strings.HasSuffix(name, ".delegate") {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "1", "yes", "y", "true", "t", "on":
				delegate[name] = true
			default:
				delegate[name] = false
			}
		}
	}
	d, ok := delegate["trusted.delegate"]
	if !ok {
		d = delegate["user.delegate"]
	}
	return b.String(), d
}
