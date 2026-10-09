// Package bpftcp loads the eBPF programs in tcpevents.bpf.c and reads TCP
// connection events: state changes (with the owner, and on close the
// connection's retransmit and reset counts), accepted connections and their
// fds, and the application closing its socket.
//
// Needs the same privileges as internal/bpfproc. It prefers the ring buffer
// and fentry/fexit, and falls back to a perf event array and kprobes.
package bpftcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Kind uint32

const (
	State         Kind = 1 // a TCP state change
	Accept        Kind = 2 // the owner of an accepted connection
	AcceptFD      Kind = 3 // ... and the fd the accept syscall returned
	AppClose      Kind = 4 // the application closed the socket
	TimeWaitStart Kind = 5 // continues as a time-wait socket in state New (TimeWait or FinWait2)
	ActiveReset   Kind = 6 // sent an RST on abort (after its TCP_CLOSE)
	TimeWaitEnd   Kind = 7 // a time-wait socket went away (addresses in the event)
)

func (k Kind) String() string {
	if k >= State && k <= TimeWaitEnd {
		return [...]string{"", "state", "accept", "accept_fd", "app_close", "time_wait", "active_reset", "time_wait_end"}[k]
	}
	return "unknown"
}

var Kinds = []Kind{State, Accept, AcceptFD, AppClose, TimeWaitStart, ActiveReset, TimeWaitEnd}

// TCP states, as the kernel numbers them.
const (
	Established = 1
	SynSent     = 2
	SynRecv     = 3
	FinWait1    = 4
	FinWait2    = 5
	TimeWait    = 6
	Close       = 7
	CloseWait   = 8
	LastAck     = 9
	Listen      = 10
	Closing     = 11
)

type Owner struct {
	PID     int    // 0: unknown
	StartNS uint64 // process start, ns since boot
	FD      int    // -1: unknown
	Inode   uint64 // 0: unknown
}

type Event struct {
	Kind     Kind
	MonoNS   uint64
	SK       uint64 // kernel sock pointer: identifies the connection while it exists
	Old, New int    // State
	Family   int    // 2 or 10
	SAddr    netip.Addr
	DAddr    netip.Addr
	SPort    int
	DPort    int
	Owner    Owner
	// State to Close: the connection's counters.
	Retransmits, ResetsSent, ResetsReceived uint32
}

type Options struct {
	ForcePerf    bool // perf event array even if a ring buffer is available
	ForceKprobes bool // kprobes even if fentry/fexit work
	BufferBytes  int  // ring buffer size, or perf buffer per CPU (0: default)
	MapEntries   int  // capacity of the per-connection maps (0: default 131072)
}

type Source struct {
	coll    *ebpf.Collection
	links   []link.Link
	rb      *ringbuf.Reader
	pr      *perf.Reader
	Buffer  string   // "ringbuf" or "perf"
	Probes  string   // "fentry" or "kprobe"
	Missing []string // optional hooks that could not be attached
	TWEnd   bool     // time-wait ends are reported (inet_twsk_kill attached)
	lost    atomic.Uint64
}

func Open(o Options) (*Source, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock rlimit: %w", err)
	}
	var errs []error
	for _, perfBuf := range []bool{false, true} {
		if !perfBuf && o.ForcePerf {
			continue
		}
		for _, fentry := range []bool{true, false} {
			if fentry && o.ForceKprobes {
				continue
			}
			s, err := open(perfBuf, fentry, o)
			if err == nil {
				return s, nil
			}
			errs = append(errs, fmt.Errorf("buffer %s, probes %s: %w", map[bool]string{false: "ringbuf", true: "perf"}[perfBuf],
				map[bool]string{true: "fentry", false: "kprobe"}[fentry], err))
		}
	}
	return nil, errors.Join(errs...)
}

func open(perfBuf, fentry bool, o Options) (s *Source, err error) {
	var spec *ebpf.CollectionSpec
	if perfBuf {
		spec, err = loadTcpPerf()
	} else {
		spec, err = loadTcpRB()
		if err == nil && o.BufferBytes > 0 {
			spec.Maps["events"].MaxEntries = uint32(o.BufferBytes)
		}
	}
	if err != nil {
		return nil, err
	}
	if o.MapEntries > 0 {
		spec.Maps["owners"].MaxEntries = uint32(o.MapEntries)
		spec.Maps["counters"].MaxEntries = uint32(o.MapEntries)
	}
	// fentry/fexit programs and their kprobe equivalents.
	pairs := [][2]string{{"handle_accept_fexit", "handle_accept_kret"}, {"handle_close_fentry", "handle_close_kprobe"},
		{"handle_tw_fentry", "handle_tw_kprobe"}, {"handle_active_reset_fentry", "handle_active_reset_kprobe"}}
	for _, p := range append(pairs, [2]string{"handle_tw_end_fentry", "handle_tw_end_kprobe"}) {
		if fentry {
			delete(spec.Programs, p[1])
		} else {
			delete(spec.Programs, p[0])
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}
	s = &Source{coll: coll, Buffer: "ringbuf", Probes: "kprobe"}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	tp := func(group, name, prog string, required bool) error {
		l, err := link.Tracepoint(group, name, coll.Programs[prog], nil)
		if err != nil {
			if required {
				return fmt.Errorf("attach %s:%s: %w", group, name, err)
			}
			s.Missing = append(s.Missing, group+":"+name)
			return nil
		}
		s.links = append(s.links, l)
		return nil
	}
	// The state tracepoint is attached last: everything that completes a
	// state change (owners, fds, time-wait, resets) is already in place
	// when the first one is reported.
	for _, t := range [][2]string{{"sys_enter_connect", "handle_enter_connect"}, {"sys_exit_connect", "handle_exit_connect"},
		{"sys_enter_listen", "handle_enter_listen"}, {"sys_exit_listen", "handle_exit_listen"},
		{"sys_exit_accept4", "handle_exit_accept4"}, {"sys_exit_accept", "handle_exit_accept"}} {
		tp("syscalls", t[0], t[1], false) // without them owners have no fd
	}
	for _, t := range [][2]string{{"tcp_retransmit_skb", "handle_retransmit"}, {"tcp_send_reset", "handle_send_reset"},
		{"tcp_receive_reset", "handle_receive_reset"}} {
		tp("tcp", t[0], t[1], false)
	}
	var l link.Link
	if fentry {
		for _, p := range pairs {
			if l, err = link.AttachTracing(link.TracingOptions{Program: coll.Programs[p[0]]}); err != nil {
				return
			}
			s.links = append(s.links, l)
		}
		s.Probes = "fentry"
	} else {
		for _, k := range []struct {
			fn, prog string
			ret      bool
		}{{"inet_csk_accept", "handle_accept_kret", true}, {"tcp_close", "handle_close_kprobe", false},
			{"tcp_time_wait", "handle_tw_kprobe", false}, {"tcp_send_active_reset", "handle_active_reset_kprobe", false}} {
			if k.ret {
				l, err = link.Kretprobe(k.fn, coll.Programs[k.prog], nil)
			} else {
				l, err = link.Kprobe(k.fn, coll.Programs[k.prog], nil)
			}
			if err != nil {
				return
			}
			s.links = append(s.links, l)
		}
	}
	// Optional: inet_twsk_kill is static and may be inlined or renamed.
	var twl link.Link
	var twErr error
	if fentry {
		twl, twErr = link.AttachTracing(link.TracingOptions{Program: coll.Programs["handle_tw_end_fentry"]})
	} else {
		twl, twErr = link.Kprobe("inet_twsk_kill", coll.Programs["handle_tw_end_kprobe"], nil)
	}
	if twErr == nil {
		s.links, s.TWEnd = append(s.links, twl), true
	} else {
		s.Missing = append(s.Missing, "inet_twsk_kill")
	}
	if err = tp("sock", "inet_sock_set_state", "handle_set_state", true); err != nil {
		return
	}
	if perfBuf {
		size := o.BufferBytes
		if size <= 0 {
			size = 512 << 10
		}
		s.pr, err = perf.NewReader(coll.Maps["events"], size)
		s.Buffer = "perf"
	} else {
		s.rb, err = ringbuf.NewReader(coll.Maps["events"])
	}
	return s, err
}

func (s *Source) Close() error {
	var errs []error
	for _, l := range s.links {
		errs = append(errs, l.Close())
	}
	if s.rb != nil {
		errs = append(errs, s.rb.Close())
	}
	if s.pr != nil {
		errs = append(errs, s.pr.Close())
	}
	s.coll.Close()
	return errors.Join(errs...)
}

var ErrTimeout = os.ErrDeadlineExceeded

// Read waits up to wait for the next event.
func (s *Source) Read(wait time.Duration) (Event, error) {
	for {
		var raw []byte
		if s.rb != nil {
			s.rb.SetDeadline(time.Now().Add(wait))
			rec, err := s.rb.Read()
			if err != nil {
				return Event{}, err
			}
			raw = rec.RawSample
		} else {
			s.pr.SetDeadline(time.Now().Add(wait))
			rec, err := s.pr.Read()
			if err != nil {
				return Event{}, err
			}
			if rec.LostSamples > 0 {
				s.lost.Add(rec.LostSamples)
				continue
			}
			raw = rec.RawSample
		}
		return decode(raw)
	}
}

// Counters returns the in-kernel counters of a connection still open.
func (s *Source) Counters(sk uint64) (retransmits, resetsSent, resetsReceived uint32, ok bool) {
	var c tcpRBCounters
	if err := s.coll.Maps["counters"].Lookup(sk, &c); err != nil {
		return 0, 0, 0, false
	}
	return c.Retransmits, c.ResetsSent, c.ResetsReceived, true
}

// NoSocketResets counts resets sent without a socket (e.g. a SYN to a closed port).
func (s *Source) NoSocketResets() uint64 {
	var perCPU []uint64
	var n uint64
	if err := s.coll.Maps["nosock_resets"].Lookup(uint32(0), &perCPU); err == nil {
		for _, v := range perCPU {
			n += v
		}
	}
	return n
}

// Drops returns, per kind, events the kernel side could not send, plus
// (index 0) perf samples lost without a known kind.
func (s *Source) Drops() map[Kind]uint64 {
	out := map[Kind]uint64{0: s.lost.Load()}
	for _, k := range Kinds {
		var perCPU []uint64
		if err := s.coll.Maps["drops"].Lookup(uint32(k), &perCPU); err == nil {
			for _, v := range perCPU {
				out[k] += v
			}
		}
	}
	return out
}

var eventSize = binary.Size(tcpRBTcpEvent{})

func decode(raw []byte) (Event, error) {
	if len(raw) < eventSize {
		return Event{}, fmt.Errorf("short TCP event: %d bytes", len(raw))
	}
	var r tcpRBTcpEvent
	if err := binary.Read(bytes.NewReader(raw[:eventSize]), binary.NativeEndian, &r); err != nil {
		return Event{}, err
	}
	e := Event{Kind: Kind(r.Kind), MonoNS: r.MonoNs, SK: r.Sk, Old: int(r.Oldstate), New: int(r.Newstate),
		Family: int(r.Family), SPort: int(r.Sport), DPort: int(r.Dport),
		Owner:       Owner{PID: int(r.Owner.Pid), StartNS: r.Owner.StartNs, FD: int(r.Owner.Fd), Inode: r.Owner.Inode},
		Retransmits: r.Counters.Retransmits, ResetsSent: r.Counters.ResetsSent, ResetsReceived: r.Counters.ResetsReceived}
	if e.Kind == State || e.Kind == TimeWaitEnd {
		if e.Family == 2 {
			e.SAddr = netip.AddrFrom4([4]byte(r.Saddr[:4]))
			e.DAddr = netip.AddrFrom4([4]byte(r.Daddr[:4]))
		} else {
			e.SAddr = netip.AddrFrom16(r.Saddr)
			e.DAddr = netip.AddrFrom16(r.Daddr)
		}
	}
	return e, nil
}
