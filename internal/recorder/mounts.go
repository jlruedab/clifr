package recorder

import (
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// Mount changes are events: the kernel flags a mountinfo file with POLLPRI
// whenever the mount table changes, and the watcher diffs it by mount ID.
// Only the host's mount namespace is watched (hostMountNS: init's, which
// differs from clifrd's own under the shipped unit).
//
// The file is opened with a raw open(2), not os.Open: Go would register it
// with its own epoll, and the kernel's poll of mountinfo consumes the change
// notification, so our poll would intermittently miss changes.

type mountWatch struct {
	mu      sync.Mutex
	pending []store.MountEvent
	known   map[int]procfs.MountInfo
	order   []procfs.MountInfo // the table in mountinfo order
}

// table returns the current mount table in mountinfo order.
func (w *mountWatch) table() []procfs.MountInfo {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.order
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
	seq := 0
	ev := func(a string, m procfs.MountInfo) store.MountEvent {
		return store.MountEvent{TS: ts, Action: a, MountID: m.ID, Point: m.Point, Source: m.Source, FSType: m.FSType,
			Options: m.Options, SuperOptions: m.SuperOptions, Dev: m.Dev, Root: m.Root, Seq: seq,
			LoopFile: m.LoopFile, UserOptions: m.UserOptions}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, m := range now {
		seq = i
		cur[m.ID] = m
		old, ok := w.known[m.ID]
		switch {
		case !ok:
			w.pending = append(w.pending, ev(action, m))
		case old.Options != m.Options || old.SuperOptions != m.SuperOptions:
			w.pending = append(w.pending, ev("remount", m))
		}
	}
	w.order = now
	seq = -1
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
	proc, _ := hostMountNS()
	fd, err := unix.Open(proc+"/mountinfo", unix.O_RDONLY|unix.O_CLOEXEC, 0)
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
				return withMountExtras(procfs.ParseMountInfo(out)), true
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

// withMountExtras adds what util-linux mount shows beyond mountinfo: the
// backing file of loop devices with autoclear set (mount -o loop, snaps;
// libmount's mnt_pretty_path shows any other one as /dev/loopN) and the
// userspace options libmount keeps in /run/mount/utab (matched by mount
// point and root, like libmount).
func withMountExtras(ms []procfs.MountInfo) []procfs.MountInfo {
	utab := map[string]string{}
	if b, err := os.ReadFile("/run/mount/utab"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			var target, root, opts string
			for _, f := range strings.Fields(line) {
				k, v, _ := strings.Cut(f, "=")
				switch k {
				case "TARGET":
					target = procfs.UnescapeOctal(v)
				case "ROOT":
					root = procfs.UnescapeOctal(v)
				case "OPTS":
					opts = v
				}
			}
			if target != "" && opts != "" {
				utab[target+"\x00"+root] = opts
			}
		}
	}
	for i := range ms {
		m := &ms[i]
		m.UserOptions = utab[m.Point+"\x00"+m.Root]
		if dev, ok := strings.CutPrefix(m.Source, "/dev/loop"); ok {
			ac, _ := os.ReadFile("/sys/block/loop" + dev + "/loop/autoclear")
			if b, err := os.ReadFile("/sys/block/loop" + dev + "/loop/backing_file"); err == nil && strings.TrimSpace(string(ac)) == "1" {
				m.LoopFile = strings.TrimSpace(string(b))
			}
		}
	}
	return ms
}
