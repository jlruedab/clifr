package recorder

import (
	"errors"
	"os"
	"testing"

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
