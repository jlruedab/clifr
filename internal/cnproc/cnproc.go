// Package cnproc listens to the kernel proc connector (NETLINK_CONNECTOR,
// CN_IDX_PROC) for fork, exec and exit events. It needs CAP_NET_ADMIN.
package cnproc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type Kind int

const (
	Fork Kind = iota + 1
	Exec
	Exit
)

func (k Kind) String() string { return [...]string{"", "fork", "exec", "exit"}[k] }

// Event is a process-level event (thread events are dropped).
type Event struct {
	Kind        Kind
	PID         int
	ParentPID   int    // fork only
	TimestampNS uint64 // CLOCK_MONOTONIC, ns
	ExitCode    uint32 // exit only
}

const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procCnMcastIgnore = 2

	evFork = 0x00000001
	evExec = 0x00000002
	evExit = 0x80000000

	nlHdrLen = 16
	cnMsgLen = 20
)

type Listener struct {
	fd int
	// Lost counts receive-buffer overruns (ENOBUFS); events were dropped.
	Lost int
}

// Listen subscribes to proc events.
func Listen() (*Listener, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return nil, fmt.Errorf("netlink connector socket: %w", err)
	}
	// A large buffer absorbs bursts while the reader is busy reading /proc.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 8<<20); err != nil {
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20)
	}
	// Wake up every second so the reader can notice shutdown.
	tv := unix.Timeval{Sec: 1}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc, Pid: uint32(os.Getpid())}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind proc connector: %w", err)
	}
	l := &Listener{fd: fd}
	if err := l.control(procCnMcastListen); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return l, nil
}

func (l *Listener) control(op uint32) error {
	ne := binary.NativeEndian
	b := make([]byte, nlHdrLen+cnMsgLen+4)
	ne.PutUint32(b[0:], uint32(len(b)))
	ne.PutUint16(b[4:], unix.NLMSG_DONE)
	ne.PutUint32(b[12:], uint32(os.Getpid()))
	c := b[nlHdrLen:]
	ne.PutUint32(c[0:], cnIdxProc)
	ne.PutUint32(c[4:], cnValProc)
	ne.PutUint16(c[16:], 4)
	ne.PutUint32(c[20:], op)
	if err := unix.Sendto(l.fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("proc connector subscribe: %w", err)
	}
	return nil
}

// Close unsubscribes and closes the socket. Call it after the reader stopped.
func (l *Listener) Close() error {
	l.control(procCnMcastIgnore)
	return unix.Close(l.fd)
}

// Read waits up to one second for the next datagram and returns its process
// events (none on timeout).
func (l *Listener) Read(buf []byte) ([]Event, error) {
	for {
		n, _, err := unix.Recvfrom(l.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EAGAIN) {
				return nil, nil
			}
			if errors.Is(err, unix.ENOBUFS) {
				l.Lost++
				continue
			}
			return nil, err
		}
		return Parse(buf[:n]), nil
	}
}

// Parse decodes netlink messages carrying cn_msg + proc_event.
func Parse(b []byte) []Event {
	ne := binary.NativeEndian
	var out []Event
	for len(b) >= nlHdrLen {
		l := int(ne.Uint32(b[0:]))
		if l < nlHdrLen || l > len(b) {
			break
		}
		msg := b[nlHdrLen:l]
		if len(msg) >= cnMsgLen+16 && ne.Uint32(msg[0:]) == cnIdxProc {
			if e, ok := parseProcEvent(msg[cnMsgLen:]); ok {
				out = append(out, e)
			}
		}
		b = b[(l+3)&^3:]
	}
	return out
}

// parseProcEvent decodes struct proc_event: what, cpu, timestamp_ns, then
// the per-event union.
func parseProcEvent(p []byte) (Event, bool) {
	ne := binary.NativeEndian
	what := ne.Uint32(p[0:])
	ts := ne.Uint64(p[8:])
	d := p[16:]
	u32 := func(i int) int { return int(ne.Uint32(d[i*4:])) }
	switch what {
	case evFork:
		if len(d) < 16 || u32(2) != u32(3) { // child_pid != child_tgid: a thread
			return Event{}, false
		}
		return Event{Kind: Fork, PID: u32(3), ParentPID: u32(1), TimestampNS: ts}, true
	case evExec:
		if len(d) < 8 {
			return Event{}, false
		}
		return Event{Kind: Exec, PID: u32(1), TimestampNS: ts}, true
	case evExit:
		if len(d) < 12 || u32(0) != u32(1) { // a thread exiting
			return Event{}, false
		}
		return Event{Kind: Exit, PID: u32(1), TimestampNS: ts, ExitCode: uint32(u32(2))}, true
	}
	return Event{}, false
}

// ExitStatus splits an exit event's code (the task's exit_code, a wait
// status) into the exit code or the signal that killed the process, as
// bpfproc.Event.ExitStatus does.
func (e Event) ExitStatus() (code, signal int) {
	if sig := int(e.ExitCode & 0x7f); sig != 0 {
		return 0, sig
	}
	return int(e.ExitCode>>8) & 0xff, 0
}
