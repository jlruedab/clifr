package recorder

import (
	"sync"

	"golang.org/x/sys/unix"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// fsUsage measures each mounted file system (statfs, what df shows) once per
// sample in a goroutine of its own: statfs of a network file system whose
// server is gone can block, and must not stall the samples. While a round
// still runs, the next ones are skipped. A row is stored when a file
// system's numbers changed, and hourly (retention would otherwise delete
// the only row of one that does not change, read-only ones).
type fsUsage struct {
	mu      sync.Mutex
	busy    bool
	skipped int
	last    map[fsKey]store.FSSample // TS = when written
	pending []store.FSSample
}

// fsKey: mount ids are reused after an unmount, so a mount is its id with
// its device and mount point.
type fsKey struct {
	id         int
	dev, point string
}

// noUsage are the file systems df leaves out as dummies or that have no
// blocks: statfs of them is not worth a call (autofs would even trigger a
// mount).
var noUsage = map[string]bool{"autofs": true, "proc": true, "subfs": true, "debugfs": true, "devpts": true,
	"fusectl": true, "fuse.portal": true, "mqueue": true, "rpc_pipefs": true, "sysfs": true, "devfs": true,
	"kernfs": true, "ignore": true, "tracefs": true, "securityfs": true, "cgroup": true, "cgroup2": true,
	"pstore": true, "bpf": true, "configfs": true, "binfmt_misc": true, "nsfs": true, "hugetlbfs": true}

func (u *fsUsage) take() []store.FSSample {
	u.mu.Lock()
	defer u.mu.Unlock()
	p := u.pending
	u.pending = nil
	return p
}

// start begins a round for the mounts at ts unless one is still running.
func (u *fsUsage) start(ts int64, mounts []procfs.MountInfo, log *Logger) {
	u.mu.Lock()
	if u.busy {
		u.skipped++
		if u.skipped == 1 || u.skipped%100 == 0 {
			log.Warnf("file-system usage: statfs still running from an earlier sample (%d skipped)", u.skipped)
		}
		u.mu.Unlock()
		return
	}
	u.busy = true
	cur := make(map[fsKey]bool, len(mounts))
	for _, m := range mounts {
		cur[fsKey{m.ID, m.Dev, m.Point}] = true
	}
	for k := range u.last {
		if !cur[k] {
			delete(u.last, k) // unmounted
		}
	}
	if u.last == nil {
		u.last = map[fsKey]store.FSSample{}
	}
	u.mu.Unlock()
	_, root := hostMountNS()
	go func() {
		var rows []store.FSSample
		for _, m := range mounts {
			if noUsage[m.FSType] {
				continue
			}
			var st unix.Statfs_t
			if unix.Statfs(root+m.Point, &st) != nil {
				continue
			}
			s := store.FSSample{MountID: m.ID, FrSize: st.Frsize, Blocks: int64(st.Blocks), BFree: int64(st.Bfree),
				BAvail: int64(st.Bavail), Files: int64(st.Files), FFree: int64(st.Ffree)}
			if u.keep(fsKey{m.ID, m.Dev, m.Point}, &s, ts) {
				rows = append(rows, s)
			}
		}
		u.mu.Lock()
		u.pending = append(u.pending, rows...)
		u.busy = false
		u.mu.Unlock()
	}()
}

// keep reports whether s (TS 0) is written at ts: when it changed or the
// last row of that file system is an hour old. It sets s.TS then.
func (u *fsUsage) keep(k fsKey, s *store.FSSample, ts int64) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	prev, ok := u.last[k]
	at := prev.TS
	if prev.TS = 0; ok && prev == *s && ts-at < store.NetSnapshotMS {
		return false
	}
	s.TS = ts
	u.last[k] = *s
	return true
}
