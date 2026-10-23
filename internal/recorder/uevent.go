package recorder

import (
	"bytes"
	"sync"

	"golang.org/x/sys/unix"
)

// Uevent multicast groups: the kernel's, and udev's (sent after udev has
// processed the event and written its database, which lsblk reads).
const (
	ueventKernel = 1
	ueventUdev   = 2
)

// startUevents marks the block devices for reading at the next system
// sample when the kernel or udev reports a change to one (a disk added, a
// partition table read, a loop device attached, a file system made). Without
// it they are still read every blockReadMS.
func (r *Recorder) startUevents(done <-chan struct{}) (stop func()) {
	if !r.sys.sysfs {
		return nil
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_KOBJECT_UEVENT)
	if err == nil {
		err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: ueventKernel | ueventUdev})
		if err != nil {
			unix.Close(fd)
		}
	}
	if err != nil {
		r.log.Warnf("block device changes: %v (read every %ds instead)", err, blockReadMS/1000)
		return nil
	}
	dirty := &r.sys.blockDirty
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer unix.Close(fd)
		buf := make([]byte, 64<<10)
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		for {
			select {
			case <-done:
				return
			default:
			}
			if n, err := unix.Poll(fds, 500); err != nil && err != unix.EINTR {
				r.log.Errorf("block device changes: %v", err)
				return
			} else if n <= 0 {
				continue
			}
			n, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
			switch {
			case err == unix.ENOBUFS: // events lost: read anyway
				dirty.Store(true)
			case err == nil && bytes.Contains(buf[:n], []byte("SUBSYSTEM=block\x00")):
				dirty.Store(true)
			}
		}
	}()
	return wg.Wait
}

// blockReadMS: how often the block devices are read without a uevent.
const blockReadMS = 60_000

// blockDue reports whether the block devices are to be read at this system
// sample: at the first, after a uevent, and every blockReadMS.
func (s *sysSampler) blockDue(ts int64) bool {
	if dirty := s.blockDirty.Swap(false); dirty || s.blockLast == nil || ts-s.blockRead >= blockReadMS {
		s.blockRead = ts
		return true
	}
	return false
}
