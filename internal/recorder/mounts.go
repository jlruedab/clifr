package recorder

import (
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// Mount changes are events: the kernel flags /proc/self/mountinfo with
// POLLPRI whenever the mount table changes, and the watcher diffs it by
// mount ID. Only the recorder's mount namespace (the host's) is watched.
//
// The file is opened with a raw open(2), not os.Open: Go would register it
// with its own epoll, and the kernel's poll of mountinfo consumes the change
// notification, so our poll would intermittently miss changes.

type mountWatch struct {
	mu      sync.Mutex
	pending []store.MountEvent
	known   map[int]procfs.MountInfo
}

func (w *mountWatch) take() []store.MountEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	p := w.pending
	w.pending = nil
	return p
}

// diff records the changes from the known table to now.
func (w *mountWatch) diff(now []procfs.MountInfo, ts int64, action string) {
	cur := map[int]procfs.MountInfo{}
	ev := func(a string, m procfs.MountInfo) store.MountEvent {
		return store.MountEvent{TS: ts, Action: a, MountID: m.ID, Point: m.Point, Source: m.Source, FSType: m.FSType, Options: m.Options}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, m := range now {
		cur[m.ID] = m
		old, ok := w.known[m.ID]
		switch {
		case !ok:
			w.pending = append(w.pending, ev(action, m))
		case old.Options != m.Options:
			w.pending = append(w.pending, ev("remount", m))
		}
	}
	for id, m := range w.known {
		if _, ok := cur[id]; !ok {
			w.pending = append(w.pending, ev("unmount", m))
		}
	}
	w.known = cur
}

// startMounts records the mounts present now and watches for changes.
func (r *Recorder) startMounts(done <-chan struct{}) (stop func()) {
	if r.fs.Root != "/proc" {
		return nil // fixtures: nothing to watch
	}
	fd, err := unix.Open("/proc/self/mountinfo", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		r.log.Warnf("mount changes not recorded: %v", err)
		return nil
	}
	w := &mountWatch{known: map[int]procfs.MountInfo{}}
	buf := make([]byte, 64<<10)
	read := func() ([]procfs.MountInfo, bool) {
		var out []byte
		for off := int64(0); ; {
			n, err := unix.Pread(fd, buf, off)
			if err != nil {
				return nil, false
			}
			if n == 0 {
				return procfs.ParseMountInfo(out), true
			}
			out = append(out, buf[:n]...)
			off += int64(n)
		}
	}
	now, ok := read()
	if !ok {
		unix.Close(fd)
		r.log.Warnf("mount changes not recorded: cannot read mountinfo")
		return nil
	}
	w.diff(now, time.Now().UnixMilli(), "present")
	r.mounts = w
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLPRI}}
		for {
			select {
			case <-done:
				return
			default:
			}
			n, err := unix.Poll(fds, 1000)
			if err != nil && err != unix.EINTR {
				r.log.Errorf("mount watch: %v", err)
				return
			}
			if n > 0 && fds[0].Revents&(unix.POLLPRI|unix.POLLERR) != 0 {
				if m, ok := read(); ok {
					w.diff(m, time.Now().UnixMilli(), "mount")
				}
			}
		}
	}()
	return func() { wg.Wait(); unix.Close(fd) }
}
