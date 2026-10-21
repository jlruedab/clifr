package recorder

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/rtnl"
	"clifr/internal/store"
)

// netWatch records the interface addresses: a snapshot at the start, every
// store.NetSnapshotMS and after lost notifications, and in between each
// change the kernel announces, at the time it does.
type netWatch struct {
	mu   sync.Mutex
	rows []store.AddrRow
	seq  int // orders the changes of one millisecond
}

func (w *netWatch) take() []store.AddrRow {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.rows
	w.rows = nil
	return out
}

func (w *netWatch) add(rows ...store.AddrRow) {
	w.mu.Lock()
	w.rows = append(w.rows, rows...)
	w.mu.Unlock()
}

func addrRow(ts int64, action string, seq int, a *rtnl.Addr) store.AddrRow {
	return store.AddrRow{TS: ts, Action: action, Seq: seq, Family: a.Family, PrefixLen: a.PrefixLen, Scope: a.Scope,
		Index: a.Index, Flags: int64(a.Flags), Local: a.Local, Address: a.Address, Broadcast: a.Broadcast,
		Anycast: a.Anycast, Multicast: a.Multicast, Label: a.Label, Metric: a.Metric, Proto: a.Proto,
		Valid: a.Valid, Preferred: a.Preferred}
}

// snapshot writes every address as "present".
func (w *netWatch) snapshot() error {
	addrs, err := rtnl.DumpAddrs()
	if err != nil {
		return err
	}
	ts := time.Now().UnixMilli()
	rows := make([]store.AddrRow, len(addrs))
	for i := range addrs {
		rows[i] = addrRow(ts, "present", i, &addrs[i])
	}
	w.add(rows...)
	return nil
}

// startNet subscribes to address changes and takes the first snapshot.
func (r *Recorder) startNet(done <-chan struct{}) (stop func()) {
	if r.fs.Root != "/proc" {
		return nil // fixtures: netlink would describe this machine
	}
	mon, err := rtnl.NewMonitor(rtnl.GroupIPv4Addr | rtnl.GroupIPv6Addr)
	if err != nil {
		r.log.Warnf("address changes not recorded: %v", err)
		return nil
	}
	w := &netWatch{}
	if err := w.snapshot(); err != nil { // after subscribing: no change is missed in between
		mon.Close()
		r.log.Warnf("addresses not recorded: %v", err)
		return nil
	}
	r.net = w
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1<<16)
		fds := []unix.PollFd{{Fd: int32(mon.Fd()), Events: unix.POLLIN}}
		last := time.Now()
		for {
			select {
			case <-done:
				return
			default:
			}
			if time.Since(last) >= store.NetSnapshotMS*time.Millisecond {
				if err := w.snapshot(); err != nil {
					r.log.Errorf("address snapshot: %v", err)
				}
				last = time.Now()
			}
			if n, err := unix.Poll(fds, 1000); err != nil && err != unix.EINTR {
				r.log.Errorf("address watch: %v", err)
				return
			} else if n <= 0 {
				continue
			}
			addrs, err := mon.Read(buf)
			switch {
			case errors.Is(err, rtnl.ErrOverflow):
				r.log.Warnf("address changes lost (kernel buffer overflow): taking a new snapshot")
				if err := w.snapshot(); err != nil {
					r.log.Errorf("address snapshot: %v", err)
				}
				last = time.Now()
				continue
			case err != nil:
				r.log.Errorf("address watch: %v", err)
				return
			}
			ts := time.Now().UnixMilli()
			for i := range addrs {
				action := "add"
				if addrs[i].Deleted {
					action = "del"
				}
				w.seq++
				w.add(addrRow(ts, action, w.seq, &addrs[i]))
			}
		}
	}()
	return func() { wg.Wait(); mon.Close() }
}
