// I/O priorities as iotop shows them: the derivation from the scheduling
// policy and nice value and the names follow iotop 0.6's iotop/ioprio.py
// (Copyright (c) 2007 Guillaume Chazarain, GPL-2.0-or-later;
// packaging/notices/iotop.txt).

package recorder

import (
	"fmt"

	"clifr/internal/procfs"

	"golang.org/x/sys/unix"
)

// I/O priorities (schema 13, for clifr iotop), recorded as both iotops show
// them: the class and data set with ioprio_set, else what they derive from
// the scheduling policy and nice value. ioprio_get and sched_getscheduler
// are system calls, not /proc reads: with --proc-root fixtures the recorder
// has no getters and records -1 (unknown).

const (
	ioprioWhoProcess = 1
	ioprioClassShift = 13
	ioprioClassRT    = 1
	ioprioClassBE    = 2
	ioprioClassIdle  = 3
	schedFIFO        = 1
	schedRR          = 2
	schedIdle        = 5
)

// sysIOPrioGet returns a task's I/O priority as the kernel stores it
// (class << 13 | data; class 0: none set).
func sysIOPrioGet(tid int) (int, error) {
	v, _, errno := unix.Syscall(unix.SYS_IOPRIO_GET, ioprioWhoProcess, uintptr(tid), 0)
	if errno != 0 {
		return -1, errno
	}
	return int(v), nil
}

// sysSchedGet returns a task's scheduling policy as sched_getscheduler does:
// with SCHED_RESET_ON_FORK (0x40000000) when set, which stat leaves out.
func sysSchedGet(tid int) (int, error) {
	v, _, errno := unix.Syscall(unix.SYS_SCHED_GETSCHEDULER, uintptr(tid), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(v), nil
}

// ioprioOf returns a task's I/O priority as iotop shows it (class << 13 |
// data), -1 when unknown. Without one set, iotop asks sched_getscheduler:
// SCHED_FIFO and SCHED_RR give rt/((nice+20)/5), SCHED_IDLE idle, anything
// else (also a real-time policy with SCHED_RESET_ON_FORK, as rtkit's canary
// thread has) be/((nice+20)/5). stat's policy has no such flag, so the
// system call is made for those three policies only.
func (r *Recorder) ioprioOf(tid, nice, policy int) int {
	if r.ioprioGet == nil {
		return -1
	}
	v, err := r.ioprioGet(tid)
	if err != nil {
		return -1
	}
	if v>>ioprioClassShift != 0 {
		return v
	}
	if (policy == schedFIFO || policy == schedRR || policy == schedIdle) && r.schedGet != nil {
		if p, err := r.schedGet(tid); err == nil {
			policy = p
		}
	}
	switch policy {
	case schedFIFO, schedRR:
		return ioprioClassRT<<ioprioClassShift | (nice+20)/5
	case schedIdle:
		return ioprioClassIdle << ioprioClassShift
	}
	return ioprioClassBE<<ioprioClassShift | (nice+20)/5
}

// ioprioName is an I/O priority as iotop 0.6 prints it ("rt/N", "be/N",
// "idle"; iotop-c: "id/N").
func ioprioName(v int) string {
	switch v >> ioprioClassShift {
	case ioprioClassRT:
		return fmt.Sprintf("rt/%d", v&(1<<ioprioClassShift-1))
	case ioprioClassIdle:
		return "idle"
	}
	return fmt.Sprintf("be/%d", v&(1<<ioprioClassShift-1))
}

// ioprioDif returns 1 when the threads' I/O priorities, as iotop 0.6 prints
// them, differ (iotop -P prints "?dif"), else 0. A thread gone before its
// ioprio_get is left out.
func (r *Recorder) ioprioDif(threads []procfs.ThreadPrio) int {
	first := ""
	for _, t := range threads {
		v := r.ioprioOf(t.TID, t.Nice, t.Policy)
		if v < 0 {
			continue
		}
		if n := ioprioName(v); first == "" {
			first = n
		} else if n != first {
			return 1
		}
	}
	return 0
}
