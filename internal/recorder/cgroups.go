package recorder

import (
	"errors"
	"path"
	"strings"

	"golang.org/x/sys/unix"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// noteCgroup writes a cgroups row for the systemd cgroup of a process (from
// /proc/<pid>/cgroup) and each of its ancestors that this run has not
// written in the last store.NetSnapshotMS: whether systemd delegated it
// (systemd-cgls marks those). Only on the real /proc: fixtures have no
// cgroup file system.
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
		if last, seen := r.cgroups[p]; seen && ts-last < store.NetSnapshotMS {
			return // its ancestors were written with it
		}
		r.cgroups[p] = ts
		b.Cgroups = append(b.Cgroups, store.CgroupRow{TS: ts, Path: p, Delegate: delegated(root + p)})
		if p == "/" || p == "" {
			return
		}
		p = path.Dir(p)
	}
}

// delegated is systemd's cg_is_delegated: the trusted.delegate attribute,
// else user.delegate, a boolean.
func delegated(dir string) bool {
	buf := make([]byte, 16)
	for _, attr := range []string{"trusted.delegate", "user.delegate"} {
		n, err := unix.Getxattr(dir, attr, buf)
		if errors.Is(err, unix.ENODATA) {
			continue
		}
		if err != nil {
			return false
		}
		switch strings.ToLower(strings.TrimSpace(string(buf[:n]))) {
		case "1", "yes", "y", "true", "t", "on":
			return true
		}
		return false
	}
	return false
}
