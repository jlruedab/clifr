package recorder

import (
	"bytes"
	"errors"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/store"
)

// kmsgWatch records the kernel log from /dev/kmsg: every record as it is
// written (at the start, those still in the buffer), and, at the start and
// at most every kmsgRingMS while records arrive, the oldest record left in
// the buffer and the clocks dmesg -T computes times from.
type kmsgWatch struct {
	mu   sync.Mutex
	rows []store.KmsgRow
}

const kmsgRingMS = 10_000

func (w *kmsgWatch) take() []store.KmsgRow {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.rows
	w.rows = nil
	return out
}

func (w *kmsgWatch) add(r store.KmsgRow) {
	w.mu.Lock()
	w.rows = append(w.rows, r)
	w.mu.Unlock()
}

// parseKmsg parses one /dev/kmsg record: "PRIO,SEQ,USEC,FLAGS[,caller=ID,...];TEXT\n"
// and continuation lines (" KEY=VALUE", not kept).
func parseKmsg(b []byte) (r store.KmsgRow, ok bool) {
	head, text, found := bytes.Cut(b, []byte{';'})
	if !found {
		return r, false
	}
	if i := bytes.IndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	fields := bytes.Split(head, []byte{','})
	if len(fields) < 3 {
		return r, false
	}
	prio, err1 := strconv.Atoi(string(fields[0]))
	seq, err2 := strconv.ParseInt(string(fields[1]), 10, 64)
	usec, err3 := strconv.ParseInt(string(fields[2]), 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return r, false
	}
	r = store.KmsgRow{Kind: "msg", Prio: prio, Seq: seq, MonoUS: usec, Msg: string(text)}
	for _, f := range fields[3:] {
		if c, ok := bytes.CutPrefix(f, []byte("caller=")); ok {
			r.Caller = string(c)
		}
	}
	return r, true
}

// kmsgClocks: CLOCK_REALTIME - CLOCK_BOOTTIME and CLOCK_BOOTTIME -
// CLOCK_MONOTONIC, in µs.
func kmsgClocks() (boot, susp int64) {
	var rt, bt, mt unix.Timespec
	unix.ClockGettime(unix.CLOCK_REALTIME, &rt)
	unix.ClockGettime(unix.CLOCK_BOOTTIME, &bt)
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &mt)
	return (rt.Nano() - bt.Nano()) / 1000, (bt.Nano() - mt.Nano()) / 1000
}

// oldestKmsg is the sequence number of the oldest record in the buffer.
func oldestKmsg() (int64, bool) {
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, false
	}
	defer unix.Close(fd)
	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EPIPE) { // overwritten while reading: the next one
			continue
		}
		if err != nil || n <= 0 {
			return 0, false
		}
		r, ok := parseKmsg(buf[:n])
		return r.Seq, ok
	}
}

// startKmsg reads /dev/kmsg until done.
func (r *Recorder) startKmsg(done <-chan struct{}) (stop func()) {
	if r.fs.Root != "/proc" {
		return nil // fixtures: the kernel log is this machine's
	}
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		r.log.Warnf("kernel log not recorded: %v (needs CAP_SYSLOG with kernel.dmesg_restrict=1)", err)
		return nil
	}
	bootID, _ := r.fs.ReadBootID()
	w := &kmsgWatch{}
	r.kmsg = w
	var lastRing store.KmsgRow
	ring := func() {
		oldest, ok := oldestKmsg()
		if !ok {
			return
		}
		boot, susp := kmsgClocks()
		// The boot time drifts with the clock's adjustments: a new row
		// when it moved by 1 ms.
		if oldest == lastRing.Seq && susp == lastRing.SuspUS && abs(boot-lastRing.BootUS) < 1000 && lastRing.TS != 0 {
			return
		}
		lastRing = store.KmsgRow{TS: time.Now().UnixMilli(), BootID: bootID, Kind: "ring", Seq: oldest, BootUS: boot, SuspUS: susp}
		w.add(lastRing)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer unix.Close(fd)
		buf := make([]byte, 16384)
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		ring()
		lastCheck, pending := time.Now(), false
		for {
			select {
			case <-done:
				return
			default:
			}
			n, err := unix.Read(fd, buf)
			switch {
			case errors.Is(err, unix.EAGAIN):
				if pending && time.Since(lastCheck) >= kmsgRingMS*time.Millisecond {
					ring()
					lastCheck, pending = time.Now(), false
				}
				if _, err := unix.Poll(fds, 1000); err != nil && err != unix.EINTR {
					r.log.Errorf("kernel log: %v", err)
					return
				}
				continue
			case errors.Is(err, unix.EPIPE):
				r.log.Warnf("kernel log records overwritten before they were read")
				continue
			case errors.Is(err, unix.EINTR):
				continue
			case err != nil:
				r.log.Errorf("kernel log: %v", err)
				return
			}
			rec, ok := parseKmsg(buf[:n])
			if !ok {
				continue
			}
			rec.TS, rec.BootID = time.Now().UnixMilli(), bootID
			rec.Msg = r.redact.Text(rec.Msg)
			w.add(rec)
			pending = true
		}
	}()
	return wg.Wait
}

func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
