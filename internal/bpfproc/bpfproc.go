// Package bpfproc loads the eBPF programs in procevents.bpf.c and reads
// process fork, exec and exit events and OOM kills from them.
//
// It needs CAP_BPF and CAP_PERFMON (or CAP_SYS_ADMIN on kernels before 5.8)
// and a kernel with BTF (/sys/kernel/btf/vmlinux) for CO-RE. It prefers the
// BPF ring buffer and a BTF tracepoint for fork, and falls back to a perf
// event array and the classic fork tracepoint.
package bpfproc

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"clifr/internal/procfs"
)

type Kind uint32

const (
	Fork Kind = 1
	Exec Kind = 2
	Exit Kind = 3
	OOM  Kind = 4
)

func (k Kind) String() string {
	if k >= Fork && k <= OOM {
		return [...]string{"", "fork", "exec", "exit", "oom"}[k]
	}
	return "unknown"
}

// Kinds lists the event kinds, for per-kind counters.
var Kinds = []Kind{Fork, Exec, Exit, OOM}

// ArgsMax is how many bytes of the command line an exec event carries.
const ArgsMax = 1023

type Event struct {
	Kind      Kind
	PID, PPID int // fork: PID is the child
	UID       int
	MonoNS    uint64 // CLOCK_MONOTONIC
	StartNS   uint64 // process start, ns since boot (0: unknown)
	Comm      string
	// Exec only.
	Filename      string
	Cmdline       string // arguments joined by spaces, like /proc/<pid>/cmdline
	Argv0Len      int    // length of argv[0] in Cmdline
	ArgsTruncated bool   // the command line was longer than ArgsMax
	// Exit only: the raw wait status (see ExitStatus).
	Status int32
	// OOM only: victim RSS from the tracepoint (0 on kernels that lack it).
	RSSKB uint64
	// Fork (tp_btf), exec and exit, if HaveTTY: controlling terminal (as
	// tty_nr in /proc/<pid>/stat), session and process group. Not set by the
	// classic fork tracepoint, OOM events and kernels before 4.19.
	HaveTTY        bool
	TTY, SID, PGRP int
}

// ExitStatus decodes Status: the exit code, or the signal that killed it.
func (e Event) ExitStatus() (code, signal int) {
	if sig := int(e.Status & 0x7f); sig != 0 {
		return 0, sig
	}
	return int(e.Status>>8) & 0xff, 0
}

// StartTicks is the start time in clock ticks since boot, as in
// /proc/<pid>/stat (the kernel's nsec_to_clock_t).
func (e Event) StartTicks() uint64 {
	return e.StartNS / uint64(1e9/procfs.ClockTicks)
}

type Options struct {
	ForcePerf        bool // use the perf event array even if a ring buffer is available
	ForceClassicFork bool // use the classic fork, exec and exit tracepoints even if tp_btf works
	BufferBytes      int  // ring buffer size, or perf buffer size per CPU (0: default)
}

type Source struct {
	coll   *ebpf.Collection
	links  []link.Link
	rb     *ringbuf.Reader
	rec    ringbuf.Record // reused by Read
	pr     *perf.Reader
	Buffer string // "ringbuf" or "perf"
	Fork   string // fork, exec and exit from "tp_btf" or classic "tracepoint"
	OOM    bool   // the oom:mark_victim tracepoint is attached
	lost   atomic.Uint64
}

// Open loads and attaches the programs, trying the preferred features first.
func Open(o Options) (*Source, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock rlimit: %w", err)
	}
	var errs []error
	for _, perfBuf := range []bool{false, true} {
		if !perfBuf && o.ForcePerf {
			continue
		}
		for _, btfFork := range []bool{true, false} {
			if btfFork && o.ForceClassicFork {
				continue
			}
			s, err := open(perfBuf, btfFork, o)
			if err == nil {
				return s, nil
			}
			errs = append(errs, fmt.Errorf("buffer %s, fork %s: %w", map[bool]string{false: "ringbuf", true: "perf"}[perfBuf],
				map[bool]string{true: "tp_btf", false: "tracepoint"}[btfFork], err))
		}
	}
	return nil, errors.Join(errs...)
}

func open(perfBuf, btfFork bool, o Options) (s *Source, err error) {
	var spec *ebpf.CollectionSpec
	if perfBuf {
		spec, err = loadProcPerf()
	} else {
		spec, err = loadProcRB()
		if o.BufferBytes > 0 {
			spec.Maps["events"].MaxEntries = uint32(o.BufferBytes)
		}
	}
	if err != nil {
		return nil, err
	}
	btfProgs := []string{"handle_exec_btf2", "handle_exec_btf", "handle_exit_btf2", "handle_exit_btf", "handle_fork_btf"}
	if btfFork {
		for _, p := range []string{"handle_fork_tp", "handle_exec", "handle_exit"} {
			delete(spec.Programs, p)
		}
	} else {
		for _, p := range btfProgs {
			delete(spec.Programs, p)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}
	s = &Source{coll: coll, Buffer: "ringbuf", Fork: "tracepoint"}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	attach := func(group, name, prog string) error {
		l, err := link.Tracepoint(group, name, coll.Programs[prog], nil)
		if err != nil {
			return fmt.Errorf("attach %s:%s: %w", group, name, err)
		}
		s.links = append(s.links, l)
		return nil
	}
	if btfFork {
		// The second exec and exit programs first: they report what the
		// first ones miss.
		for _, p := range btfProgs {
			var l link.Link
			if l, err = link.AttachTracing(link.TracingOptions{Program: coll.Programs[p]}); err != nil {
				return
			}
			s.links = append(s.links, l)
		}
		s.Fork = "tp_btf"
	} else {
		for _, t := range [][2]string{{"sched_process_exec", "handle_exec"}, {"sched_process_exit", "handle_exit"},
			{"sched_process_fork", "handle_fork_tp"}} {
			if err = attach("sched", t[0], t[1]); err != nil {
				return
			}
		}
	}
	s.OOM = attach("oom", "mark_victim", "handle_oom") == nil // optional
	if perfBuf {
		size := o.BufferBytes
		if size <= 0 {
			size = 256 << 10
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

// ErrTimeout is returned by Read when no event arrived within the wait.
var ErrTimeout = os.ErrDeadlineExceeded

// Read waits up to wait for the next event.
func (s *Source) Read(wait time.Duration) (Event, error) {
	for {
		var raw []byte
		if s.rb != nil {
			s.rb.SetDeadline(time.Now().Add(wait))
			if err := s.rb.ReadInto(&s.rec); err != nil {
				return Event{}, err
			}
			raw = s.rec.RawSample
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

// ErrFlushed is returned by ReadBatch once it has returned every event
// that was waiting when Flush was called.
var ErrFlushed = ringbuf.ErrFlushed // the same error as perf.ErrFlushed

// Flush makes the reader return what is waiting now, then ErrFlushed.
func (s *Source) Flush() error {
	if s.rb != nil {
		return s.rb.Flush()
	}
	return s.pr.Flush()
}

// batchMax bounds one ReadBatch.
const batchMax = 4096

// ReadBatch appends to dst the events that are waiting. With none waiting
// it blocks until the kernel wakes it (an event that must be handled at
// once, or a filling buffer: see OUTPUT in procevents.bpf.c), until wait,
// or until Flush. Events sent without a wake-up are taken at the next call.
// It returns ErrTimeout if nothing came and ErrFlushed (with the events
// before it) after a Flush.
func (s *Source) ReadBatch(dst []Event, wait time.Duration) ([]Event, error) {
	if s.rb == nil {
		e, err := s.Read(wait)
		if err != nil {
			return dst, err
		}
		return append(dst, e), nil
	}
	s.rb.SetDeadline(time.Now().Add(wait))
	n := len(dst)
	for len(dst)-n < batchMax {
		err := s.rb.ReadInto(&s.rec)
		if errors.Is(err, ErrTimeout) && len(dst) > n {
			return dst, nil
		}
		if err != nil {
			return dst, err
		}
		e, err := decode(s.rec.RawSample)
		if err != nil {
			return dst, err
		}
		dst = append(dst, e)
		if len(dst) == n+1 {
			s.rb.SetDeadline(time.Now()) // woken: take the rest without waiting
		}
	}
	return dst, nil
}

// Drops returns, per kind, the events the kernel side could not send, plus
// (index 0) perf samples lost without a known kind.
func (s *Source) Drops() map[Kind]uint64 {
	out := map[Kind]uint64{0: s.lost.Load()}
	m := s.coll.Maps["drops"]
	for _, k := range Kinds {
		var perCPU []uint64
		if err := m.Lookup(uint32(k), &perCPU); err == nil {
			for _, v := range perCPU {
				out[k] += v
			}
		}
	}
	return out
}

// MissedRuns counts the times the kernel did not run one of the programs
// because another BPF program was running on the CPU: events lost without a
// trace in Drops (0 before Linux 5.12). Execs and exits the first program
// missed and the second reported are not lost.
func (s *Source) MissedRuns() (n uint64) {
	for _, p := range s.coll.Programs {
		if st, err := p.Stats(); err == nil {
			n += st.RecursionMisses
		}
	}
	var rescued uint64
	if m := s.coll.Maps["busy"]; m != nil {
		for _, k := range []uint32{2, 3} { // RESCUED_EXEC, RESCUED_EXIT
			var perCPU []uint64
			if m.Lookup(k, &perCPU) == nil {
				for _, v := range perCPU {
					rescued += v
				}
			}
		}
	}
	return n - min(n, rescued)
}

// ProgStats returns, per program, how often it ran and for how long (ns),
// while the kernel collects BPF statistics (clifrd --bpf-stats, or
// sysctl kernel.bpf_stats_enabled); empty otherwise.
func (s *Source) ProgStats() map[string][2]uint64 {
	out := map[string][2]uint64{}
	for name, p := range s.coll.Programs {
		if st, err := p.Stats(); err == nil && st.RunCount > 0 {
			out[name] = [2]uint64{st.RunCount, uint64(st.Runtime)}
		}
	}
	return out
}

const eventSize = int(unsafe.Sizeof(procRBEvent{}))

const flagTTY = 1 // FLAG_TTY in procevents.bpf.c

// decode copies the raw event into the generated struct (host layout, the
// same bytes the kernel side wrote); no reflection. Fork, exit and OOM
// events stop before filename.
func decode(raw []byte) (Event, error) {
	var r procRBEvent
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&r)), eventSize), raw)
	e := Event{Kind: Kind(r.Kind), PID: int(r.Pid), PPID: int(r.Ppid), UID: int(r.Uid), MonoNS: r.MonoNs,
		StartNS: r.StartNs, Comm: cstr(r.Comm[:]), Status: r.ExitCode, RSSKB: r.RssKb,
		HaveTTY: r.Flags&flagTTY != 0, TTY: int(r.TtyNr), SID: int(r.Sid), PGRP: int(r.Pgrp)}
	if e.Kind == Exec {
		e.Filename = cstr(r.Filename[:])
		n := min(int(r.ArgsLen), ArgsMax)
		args := unsafe.Slice((*byte)(unsafe.Pointer(&r.Args[0])), n)
		e.Cmdline, e.Argv0Len = procfs.ParseCmdline(args), procfs.Argv0Len(args)
		e.ArgsTruncated = int(r.ArgsLen) > ArgsMax
	}
	return e, nil
}

// cstr converts a NUL-terminated C string.
func cstr(c []int8) string {
	b := unsafe.Slice((*byte)(unsafe.Pointer(&c[0])), len(c))
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
