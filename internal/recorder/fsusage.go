package recorder

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/metrics"
	"clifr/internal/procfs"
	"clifr/internal/store"
)

// fsUsage measures each mounted file system (statfs, what df shows) once per
// sample in a goroutine of its own: statfs of a network file system whose
// server is gone can block, and must not stall the samples. Each mount's
// call is waited for at most statfsWait; one that does not return by then is
// "stuck" (guard event statfs_stuck) and skipped until it returns
// (statfs_ok), so a hung mount costs one blocked thread and the others are
// still measured. While a round still runs, the next ones are skipped. A row
// is stored when a file system's numbers changed, and hourly (retention
// would otherwise delete the only row of one that does not change,
// read-only ones).
type fsUsage struct {
	mu      sync.Mutex
	busy    bool
	skipped int
	last    map[fsKey]store.FSSample // TS = when written
	stuck   map[fsKey]int64          // mount -> when its statfs call began
	pending []store.FSSample
	guard   []store.GuardEvent
}

// statfsWait is how long a round waits for one mount's statfs; statfs is
// unix.Statfs (tests replace both).
var (
	statfsWait = time.Second
	statfs     = unix.Statfs
)

// statfsDetail is the detail of the statfs_stuck and statfs_ok guard
// events: the mount point first (query.statfsStalls finds it by the last ": statfs ").
func statfsDetail(point, fstype, source, what string) string {
	return fmt.Sprintf("%s: statfs %s (%s %s)", point, what, fstype, source)
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

// takeGuard returns the statfs_stuck and statfs_ok events since the last call.
func (u *fsUsage) takeGuard() []store.GuardEvent {
	u.mu.Lock()
	defer u.mu.Unlock()
	g := u.guard
	u.guard = nil
	return g
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
	for k := range u.stuck {
		if !cur[k] {
			delete(u.stuck, k) // unmounted (umount -l) while its call hangs
		}
	}
	if u.last == nil {
		u.last = map[fsKey]store.FSSample{}
		u.stuck = map[fsKey]int64{}
	}
	u.mu.Unlock()
	_, root := hostMountNS()
	go func() {
		var rows []store.FSSample
		for _, m := range mounts {
			if noUsage[m.FSType] {
				continue
			}
			k := fsKey{m.ID, m.Dev, m.Point}
			u.mu.Lock()
			_, stuck := u.stuck[k]
			u.mu.Unlock()
			if stuck {
				continue
			}
			if s, ok := u.measure(m, k, root, ts, log); ok && u.keep(k, &s, ts) {
				rows = append(rows, s)
			}
		}
		u.mu.Lock()
		u.pending = append(u.pending, rows...)
		u.busy = false
		u.mu.Unlock()
	}()
}

// measure runs statfs of m, waiting at most statfsWait. A call that takes
// longer marks the mount stuck and goes on in the background: when it
// returns it stores its row itself and clears the mark.
func (u *fsUsage) measure(m procfs.MountInfo, k fsKey, root string, ts int64, log *Logger) (store.FSSample, bool) {
	type result struct {
		s  store.FSSample
		ok bool
	}
	done := make(chan result, 1)
	began := time.Now()
	go func() {
		var st unix.Statfs_t
		err := statfs(root+m.Point, &st)
		done <- result{store.FSSample{MountID: m.ID, FrSize: st.Frsize, Blocks: int64(st.Blocks), BFree: int64(st.Bfree),
			BAvail: int64(st.Bavail), Files: int64(st.Files), FFree: int64(st.Ffree)}, err == nil}
	}()
	t := time.NewTimer(statfsWait)
	defer t.Stop()
	select {
	case r := <-done:
		return r.s, r.ok
	case <-t.C:
	}
	u.mu.Lock()
	u.stuck[k] = ts
	u.guard = append(u.guard, store.GuardEvent{TS: began.UnixMilli(), Kind: "statfs_stuck",
		Detail: statfsDetail(m.Point, m.FSType, m.Source, fmt.Sprintf("not answering after %s", statfsWait))})
	u.mu.Unlock()
	log.Warnf("file-system usage: statfs of %s (%s) not answering; skipped until it returns", m.Point, m.FSType)
	go func() {
		r := <-done
		now := time.Now()
		u.mu.Lock()
		_, still := u.stuck[k] // false: unmounted meanwhile
		delete(u.stuck, k)
		u.guard = append(u.guard, store.GuardEvent{TS: now.UnixMilli(), Kind: "statfs_ok",
			Detail: statfsDetail(m.Point, m.FSType, m.Source, fmt.Sprintf("answered after %s", now.Sub(began).Round(time.Second)))})
		u.mu.Unlock()
		log.Printf("file-system usage: statfs of %s answered after %s", m.Point, now.Sub(began).Round(time.Second))
		if still && r.ok && u.keep(k, &r.s, now.UnixMilli()) {
			u.mu.Lock()
			u.pending = append(u.pending, r.s)
			u.mu.Unlock()
		}
	}()
	return store.FSSample{}, false
}

// current returns, for /metrics, the last statfs numbers of each mount of
// the table that Node Exporter's default filters keep (a mount not measured
// yet, or that statfs refused, is left out).
func (u *fsUsage) current(mounts []procfs.MountInfo) []metrics.FSUsage {
	u.mu.Lock()
	defer u.mu.Unlock()
	var out []metrics.FSUsage
	for _, m := range mounts {
		if !metrics.ServedFS(m.Point, m.FSType) {
			continue
		}
		s, ok := u.last[fsKey{m.ID, m.Dev, m.Point}]
		if !ok {
			continue
		}
		bs := int64(s.FrSize)
		out = append(out, metrics.FSUsage{Device: m.Source, FSType: m.FSType, MountPoint: m.Point,
			ReadOnly: slices.Contains(strings.Split(m.Options, ","), "ro"),
			Size:     s.Blocks * bs, Free: s.BFree * bs, Avail: s.BAvail * bs, Files: s.Files, FilesFree: s.FFree})
	}
	return out
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
