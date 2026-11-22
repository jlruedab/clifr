package recorder

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clifr/internal/procfs"
)

// TestIOPrioOf: the priority as iotop shows it, set or derived from the
// policy (sched_getscheduler's, with SCHED_RESET_ON_FORK) and nice value.
func TestIOPrioOf(t *testing.T) {
	raw := map[int]int{}
	sched := map[int]int{}
	r := &Recorder{
		ioprioGet: func(tid int) (int, error) {
			v, ok := raw[tid]
			if !ok {
				return -1, errors.New("gone")
			}
			return v, nil
		},
		schedGet: func(tid int) (int, error) { return sched[tid], nil },
	}
	for i, c := range []struct {
		raw, nice, policy, sched int
		want                     string
	}{
		{0, 0, 0, 0, "be/4"},
		{0, -5, 0, 0, "be/3"},
		{0, -20, 0, 0, "be/0"},
		{0, 19, 0, 0, "be/7"},
		{0, 0, 3, 3, "be/4"},           // SCHED_BATCH
		{0, 0, 1, 1, "rt/4"},           // SCHED_FIFO
		{0, 0, 2, 2, "rt/4"},           // SCHED_RR
		{0, 1, 1, 0x40000001, "be/4"},  // SCHED_FIFO | SCHED_RESET_ON_FORK (rtkit)
		{0, 10, 5, 5, "idle"},          // SCHED_IDLE
		{0, 10, 5, 0x40000005, "be/6"}, // SCHED_IDLE | SCHED_RESET_ON_FORK
		{2<<13 | 3, 0, 0, 0, "be/3"},   // jbd2
		{2<<13 | 7, -20, 0, 0, "be/7"}, // set: nice does not matter
		{1 << 13, 0, 0, 0, "rt/0"},     // rt/0 set
		{3<<13 | 7, 19, 5, 5, "idle"},  // localsearch
		{3 << 13, 0, 0, 0, "idle"},     // clifrd
	} {
		raw[i], sched[i] = c.raw, c.sched
		if got := ioprioName(r.ioprioOf(i, c.nice, c.policy)); got != c.want {
			t.Errorf("%+v: %s, want %s", c, got, c.want)
		}
	}
	if r.ioprioOf(99, 0, 0) != -1 {
		t.Error("gone: not unknown")
	}
	if v := r.ioprioOf(13, 19, 5); v != 3<<13|7 {
		t.Errorf("set idle/7: %#x", v)
	}
}

// TestIOPrioDif: "?dif" when the threads' names differ; gone threads are
// left out; no getter (fixtures) means unknown and no flag.
func TestIOPrioDif(t *testing.T) {
	raw := map[int]int{1: 0, 2: 0, 3: 3 << 13, 4: 3<<13 | 7}
	r := &Recorder{ioprioGet: func(tid int) (int, error) {
		v, ok := raw[tid]
		if !ok {
			return -1, errors.New("gone")
		}
		return v, nil
	}}
	same := []procfs.ThreadPrio{{TID: 1}, {TID: 2}, {TID: 9, Nice: 19}}
	if r.ioprioDif(same) != 0 {
		t.Error("same names (a gone thread left out): dif")
	}
	if r.ioprioDif([]procfs.ThreadPrio{{TID: 1}, {TID: 2, Nice: -10}}) != 1 {
		t.Error("nice 0 and -10: no dif")
	}
	if r.ioprioDif([]procfs.ThreadPrio{{TID: 1}, {TID: 3}}) != 1 {
		t.Error("be/4 and idle: no dif")
	}
	if r.ioprioDif([]procfs.ThreadPrio{{TID: 3}, {TID: 4}}) != 0 {
		t.Error("idle/0 and idle/7 (both \"idle\"): dif")
	}
	if (&Recorder{}).ioprioOf(1, 0, 0) != -1 || (&Recorder{}).ioprioDif(same) != 0 {
		t.Error("no getter: not unknown")
	}
}

// TestSysIOPrioGet: the system calls themselves, on this process.
func TestSysIOPrioGet(t *testing.T) {
	v, err := sysIOPrioGet(os.Getpid())
	if err != nil || v < 0 || v>>13 > 3 {
		t.Fatalf("ioprio_get: %d %v", v, err)
	}
	if p, err := sysSchedGet(os.Getpid()); err != nil || p&^0x40000000 > 7 {
		t.Fatalf("sched_getscheduler: %d %v", p, err)
	}
}

// TestFreshBySchedstat: a process charged no CPU tick (a kernel thread such
// as jbd2 writing megabytes in microseconds) has its I/O counters re-read
// when its main thread's time on a CPU (schedstat, ns) changed; the threads'
// own counters (task/PID/io) are what iotop adds up.
func TestFreshBySchedstat(t *testing.T) {
	fp := newFakeProc(t)
	fp.set(10, "jbd2", 100, 5)
	dir := filepath.Join(fp.root, "10")
	io := func(whole, own int) {
		os.WriteFile(filepath.Join(dir, "io"), []byte(fmt.Sprintf("read_bytes: 0\nwrite_bytes: %d\ncancelled_write_bytes: 0\n", whole)), 0o644)
		os.MkdirAll(filepath.Join(dir, "task", "10"), 0o755)
		os.WriteFile(filepath.Join(dir, "task", "10", "io"), []byte(fmt.Sprintf("read_bytes: 0\nwrite_bytes: %d\ncancelled_write_bytes: 0\n", own)), 0o644)
	}
	sched := func(run int) {
		os.WriteFile(filepath.Join(dir, "schedstat"), []byte(fmt.Sprintf("%d 50 3\n", run)), 0o644)
	}
	io(1000, 1000)
	sched(1_000_000)
	r, _ := newTestRecorder(t, fp.root)
	r.cfg.ProcIO = true
	t1 := time.UnixMilli(1790001000000)
	must(t, r.sample(t1, true))
	got := func() (int64, int64) { s := r.byPID[10].sample; return s.WriteBytes, s.ThrWriteBytes }
	if w, own := got(); w != 1000 || own != 1000 {
		t.Fatalf("first sample: %d %d", w, own)
	}
	io(9000, 5000) // wrote, and reaped a child that wrote 4000
	must(t, r.sample(t1.Add(30*time.Second), false))
	if w, own := got(); w != 1000 || own != 1000 {
		t.Errorf("no tick, no run time: re-read (%d %d)", w, own)
	}
	sched(1_000_400) // ran 400 ns: no tick
	must(t, r.sample(t1.Add(60*time.Second), false))
	if w, own := got(); w != 9000 || own != 5000 {
		t.Errorf("ran without a tick: not re-read (%d %d)", w, own)
	}
}
