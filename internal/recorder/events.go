package recorder

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/bpfproc"
	"clifr/internal/cnproc"
	"clifr/internal/procfs"
	"clifr/internal/store"
)

type evKind int

const (
	evFork evKind = iota + 1
	evExec
	evExit
	evOOM
)

// Event sources (the processes table's source column; "sample" otherwise).
const (
	srcEBPF   = "ebpf"
	srcCNProc = "proc_connector"
)

// procEvent is a process event from eBPF or the proc connector, with what
// was known about the process when it arrived (short-lived processes are
// gone by the next sample).
type procEvent struct {
	kind     evKind
	ts       int64 // wall clock, unix ms
	pid      int
	haveStat bool             // key and attrs are known
	key      procKey          // pid and start time
	attrs    store.ProcUpdate // comm, cmdline, uid, ppid, source; exec: exe, exec time
	tty      int
	sid      int
	pgrp     int
	// Exit (eBPF): exactly one of exitCode and signal is set.
	exitCode, signal *int
	// OOM: the victim's RSS at the kill, 0 if unknown.
	rssKB int64
	// Fork (eBPF): the command line is the parent's, set when the event is
	// applied.
	parentCmd bool
}

// evProc is a process known only from events so far.
type evProc struct {
	ev       procEvent // latest fork/exec info
	exit     int64     // exit time, 0 if not seen
	exitCode *int
	signal   *int
	oom      bool
}

// eventQueue is filled by the event reader goroutine and drained by each
// sample. Counters are cumulative, per recorder_stats source.
type eventQueue struct {
	mu       sync.Mutex
	list     []procEvent
	lost     int // proc connector receive-buffer overruns
	received map[string]int64
	reported map[string][2]int64     // received and dropped at the last report
	drops    func() map[string]int64 // eBPF: events the kernel side could not send
	progs    func() map[string][2]uint64
	// eBPF: flush asks the reader for every event sent so far; it signals
	// synced once they are queued. Nil for the proc connector.
	flush  func() error
	synced chan struct{}
}

// syncWait bounds how long a sample waits for the event reader.
const syncWait = 200 * time.Millisecond

// sync returns once the events sent before it are queued (or after
// syncWait). Most process events do not wake the reader (see OUTPUT in
// procevents.bpf.c), so without it an exit could arrive after the sample
// that found the process gone and be recorded as a second process.
func (q *eventQueue) sync() {
	if q.flush == nil {
		return
	}
	select {
	case <-q.synced: // left over from an earlier sync that timed out
	default:
	}
	if q.flush() != nil {
		return
	}
	t := time.NewTimer(syncWait)
	defer t.Stop()
	select {
	case <-q.synced:
	case <-t.C:
	}
}

// recorder_stats sources for the eBPF programs' own cost (with --bpf-stats):
// runs and nanoseconds per program, in the events column.
const (
	statBPFRuns = "bpf_runs:"
	statBPFNS   = "bpf_ns:"
)

func newEventQueue() *eventQueue {
	return &eventQueue{received: map[string]int64{}, reported: map[string][2]int64{}}
}

func (q *eventQueue) push(evs []procEvent, stat string, n int) {
	q.mu.Lock()
	q.list = append(q.list, evs...)
	q.received[stat] += int64(n)
	q.mu.Unlock()
}

func (q *eventQueue) take() ([]procEvent, int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	l := q.list
	q.list = nil
	return l, q.lost
}

// stats returns per source the events received and dropped since the last call.
func (q *eventQueue) stats(ts int64) []store.StatRow {
	var drops map[string]int64
	if q.drops != nil {
		drops = q.drops()
	}
	var progs map[string][2]uint64
	if q.progs != nil {
		progs = q.progs()
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for name, v := range progs {
		q.received[statBPFRuns+name], q.received[statBPFNS+name] = int64(v[0]), int64(v[1])
	}
	if q.lost > 0 {
		drops = map[string]int64{srcCNProc: int64(q.lost)}
	}
	seen := map[string]bool{}
	var out []store.StatRow
	for _, m := range []map[string]int64{q.received, drops} {
		for src := range m {
			if seen[src] {
				continue
			}
			seen[src] = true
			now := [2]int64{q.received[src], drops[src]}
			prev := q.reported[src]
			out = append(out, store.StatRow{TS: ts, Source: src, Events: now[0] - prev[0], Dropped: now[1] - prev[1]})
			q.reported[src] = now
		}
	}
	return out
}

// startEvents starts the configured event source: eBPF, else (with
// "auto") the proc connector. Without either the recorder samples only.
func (r *Recorder) startEvents(ctx context.Context) (stop func(), err error) {
	mode := r.cfg.Events
	if mode == "" {
		mode = "auto"
	}
	if r.fs.Root != "/proc" || mode == "none" {
		r.db.SetMeta("events", "none")
		return func() {}, nil // fixtures: events would describe the real system
	}
	if mode == "auto" || mode == srcEBPF {
		src, err := bpfproc.Open(r.cfg.EBPF)
		if err == nil {
			oom := "oom"
			if !src.OOM {
				oom = "no oom tracepoint"
			}
			desc := fmt.Sprintf("ebpf (%s, fork/exec/exit %s, %s)", src.Buffer, src.Fork, oom)
			r.db.SetMeta("events", desc)
			r.log.Printf("process events: %s", desc)
			return r.runEBPF(ctx, src), nil
		}
		if mode == srcEBPF {
			return nil, fmt.Errorf("eBPF events: %w", err)
		}
		r.log.Warnf("eBPF unavailable, falling back to the proc connector: %v", err)
	}
	l, err := cnproc.Listen()
	if err != nil {
		if mode == srcCNProc {
			return nil, err
		}
		r.log.Warnf("proc connector unavailable (%v); short-lived processes between samples will be missed", err)
		r.db.SetMeta("events", "unavailable: "+err.Error())
		return func() {}, nil
	}
	r.db.SetMeta("events", srcCNProc)
	r.log.Printf("process events: proc connector")
	return r.runCNProc(ctx, l), nil
}

func (r *Recorder) runCNProc(ctx context.Context, l *cnproc.Listener) (stop func()) {
	r.events = newEventQueue()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 64<<10)
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			default:
			}
			evs, err := l.Read(buf)
			if err != nil {
				r.log.Errorf("proc connector read: %v; continuing with sampling only", err)
				return
			}
			enriched := make([]procEvent, 0, len(evs))
			for _, e := range evs {
				enriched = append(enriched, r.enrich(e))
			}
			r.events.push(enriched, srcCNProc, len(evs))
			r.events.mu.Lock()
			r.events.lost = l.Lost
			r.events.mu.Unlock()
		}
	}()
	return func() {
		close(done)
		wg.Wait()
		l.Close()
	}
}

func (r *Recorder) runEBPF(ctx context.Context, src *bpfproc.Source) (stop func()) {
	r.events = newEventQueue()
	r.events.drops = func() map[string]int64 {
		out := map[string]int64{}
		for k, n := range src.Drops() {
			if n > 0 || k != 0 {
				out[ebpfStat(k)] = int64(n)
			}
		}
		if n := src.MissedRuns(); n > 0 {
			out["ebpf_missed_runs"] = int64(n)
		}
		return out
	}
	r.events.progs = src.ProgStats
	r.events.flush, r.events.synced = src.Flush, make(chan struct{}, 1)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var batch []bpfproc.Event
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			default:
			}
			var err error
			batch, err = src.ReadBatch(batch[:0], time.Second)
			if err != nil && !errors.Is(err, bpfproc.ErrTimeout) && !errors.Is(err, bpfproc.ErrFlushed) {
				r.log.Errorf("eBPF event read: %v; continuing with sampling only", err)
				return
			}
			for _, e := range batch {
				if pe, ok := r.fromBPF(e); ok {
					r.events.push([]procEvent{pe}, ebpfStat(e.Kind), 1)
				} else {
					r.events.push(nil, ebpfStat(e.Kind), 1)
				}
			}
			if errors.Is(err, bpfproc.ErrFlushed) {
				select {
				case r.events.synced <- struct{}{}:
				default:
				}
			}
		}
	}()
	return func() {
		close(done)
		wg.Wait()
		src.Close()
	}
}

func ebpfStat(k bpfproc.Kind) string { return "ebpf_" + k.String() }

// clockRef is one reading of both clocks, for converting the
// CLOCK_MONOTONIC times of a batch of events without two system calls each.
type clockRef struct{ wallMS, monoNS int64 }

func newClockRef() clockRef {
	var mono unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono)
	return clockRef{time.Now().UnixMilli(), mono.Nano()}
}

// at converts a CLOCK_MONOTONIC event time to wall-clock unix ms.
func (c clockRef) at(monoNS uint64) int64 {
	return c.wallMS - max(c.monoNS-int64(monoNS), 0)/1e6
}

// wallMS converts a CLOCK_MONOTONIC event time to wall-clock unix ms.
func wallMS(monoNS uint64) int64 { return newClockRef().at(monoNS) }

// fromBPF turns an eBPF event into a procEvent. Exec, exit and (tp_btf)
// fork events carry the process's start time, so the key is exact without
// reading /proc; /proc is read only for what the event lacks.
func (r *Recorder) fromBPF(e bpfproc.Event) (procEvent, bool) {
	pe := procEvent{pid: e.PID, ts: wallMS(e.MonoNS)}
	if e.StartNS != 0 {
		pe.haveStat = true
		pe.key = procKey{pid: e.PID, start: r.boot + int64(e.StartTicks())*1000/procfs.ClockTicks}
		pe.attrs = store.ProcUpdate{PPID: e.PPID, UID: e.UID, Comm: e.Comm, Source: srcEBPF}
	}
	switch e.Kind {
	case bpfproc.Fork:
		if !pe.haveStat { // classic tracepoint: look the child up like the proc connector does
			if st, err := r.fs.ReadStatus(e.PID); err == nil && st.Tgid != e.PID {
				return pe, false // a thread
			}
			pe = r.enrich(cnproc.Event{Kind: cnproc.Fork, PID: e.PID, TimestampNS: e.MonoNS})
			pe.attrs.Source = srcEBPF
			return pe, true
		}
		pe.kind = evFork
		// The child runs the parent's command line until it execs; it is
		// taken from the parent when the event is applied, not read from
		// /proc here (the largest /proc read at the busy load).
		pe.parentCmd = true
		r.eventTTY(&pe, e)
	case bpfproc.Exec:
		pe.kind = evExec
		pe.attrs.Cmdline, pe.attrs.Exe, pe.attrs.ExecTS = e.Cmdline, e.Filename, pe.ts
		if e.ArgsTruncated {
			if full, err := r.fs.ReadCmdline(e.PID); err == nil && full != "" {
				pe.attrs.Cmdline = full
			}
		}
		r.eventTTY(&pe, e)
	case bpfproc.Exit:
		pe.kind = evExit
		if e.HaveTTY { // a process seen only at its exit is stored from this event
			pe.tty, pe.sid, pe.pgrp = e.TTY, e.SID, e.PGRP
		}
		code, sig := e.ExitStatus()
		if sig != 0 {
			pe.signal = &sig
		} else {
			pe.exitCode = &code
		}
	case bpfproc.OOM:
		pe.kind = evOOM
		// The victim is being killed: read what /proc still shows right now.
		if st, err := r.fs.ReadStat(e.PID); err == nil {
			pe.haveStat = true
			pe.key = procKey{pid: e.PID, start: r.boot + int64(st.StartTime)*1000/procfs.ClockTicks}
			pe.attrs = store.ProcUpdate{PPID: st.PPID, Comm: st.Comm, Source: srcEBPF}
			pe.tty, pe.sid, pe.pgrp = st.TTY, st.Session, st.PGRP
			pe.attrs.Cmdline, _ = r.fs.ReadCmdline(e.PID)
			if _, res, err := r.fs.ReadStatm(e.PID); err == nil {
				pe.rssKB = res * int64(pageKB)
			}
		}
		if e.RSSKB > 0 {
			pe.rssKB = int64(e.RSSKB)
		}
	default:
		return pe, false
	}
	return pe, true
}

// parentCmdline is the command line of the process ppid as the events
// applied so far leave it: the one a child sees right after its fork, since
// events are applied in order. A parent the recorder does not know yet is
// read from /proc.
func (r *Recorder) parentCmdline(ppid int) string {
	if e := r.byPID[ppid]; e != nil && e.exit == 0 {
		return e.upd.Cmdline
	}
	if k, ok := r.evByPID[ppid]; ok {
		if ep := r.evProcs[k]; ep != nil && ep.exit == 0 {
			return ep.ev.attrs.Cmdline
		}
	}
	cmd, _ := r.fs.ReadCmdline(ppid)
	return cmd
}

// eventTTY sets terminal, session and process group from the event, or
// from /proc/<pid>/stat on kernels where the event lacks them.
func (r *Recorder) eventTTY(pe *procEvent, e bpfproc.Event) {
	if e.HaveTTY {
		pe.tty, pe.sid, pe.pgrp = e.TTY, e.SID, e.PGRP
		return
	}
	if st, err := r.fs.ReadStat(pe.pid); err == nil {
		pe.tty, pe.sid, pe.pgrp = st.TTY, st.Session, st.PGRP
	}
}

// enrich turns a proc connector event into a procEvent, reading the
// process's stat (and status/cmdline for fork and exec) right away.
// Failures are fine: the process may already be gone.
func (r *Recorder) enrich(e cnproc.Event) procEvent {
	kind := map[cnproc.Kind]evKind{cnproc.Fork: evFork, cnproc.Exec: evExec, cnproc.Exit: evExit}[e.Kind]
	pe := procEvent{kind: kind, pid: e.PID, ts: wallMS(e.TimestampNS)}
	st, err := r.fs.ReadStat(e.PID)
	if err != nil {
		return pe
	}
	pe.haveStat = true
	pe.key = procKey{pid: e.PID, start: r.boot + int64(st.StartTime)*1000/procfs.ClockTicks}
	pe.attrs = store.ProcUpdate{PPID: st.PPID, Comm: st.Comm, Source: srcCNProc}
	pe.tty, pe.sid, pe.pgrp = st.TTY, st.Session, st.PGRP
	if kind == evExit {
		return pe
	}
	if status, err := r.fs.ReadStatus(e.PID); err == nil {
		pe.attrs.UID = status.UID
	}
	pe.attrs.Cmdline, _ = r.fs.ReadCmdline(e.PID)
	if kind == evExec {
		pe.attrs.ExecTS = pe.ts
	}
	return pe
}

// applyEvents folds queued events into the trackers. It runs at the start
// of a sample, before the process walk.
func (r *Recorder) applyEvents(ts int64, b *store.Batch) int {
	if r.events == nil {
		return 0
	}
	r.events.sync()
	evs, lost := r.events.take()
	if lost > r.lostReported {
		b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "events_lost",
			Detail: "proc connector receive buffer overflowed; some process events were dropped"})
		r.lostReported = lost
	}
	for _, ev := range evs {
		switch ev.kind {
		case evFork, evExec:
			if !ev.haveStat {
				continue // gone before we could read it: nothing reliable to store
			}
			if ev.parentCmd {
				ev.attrs.Cmdline = r.parentCmdline(ev.attrs.PPID)
			}
			if e := r.procs[ev.key]; e != nil {
				if ev.kind == evExec { // a sampled process exec'd: new command line
					u := e.upd
					u.Comm, u.Cmdline, u.UID, u.Exe, u.ExecTS = ev.attrs.Comm, ev.attrs.Cmdline, ev.attrs.UID, ev.attrs.Exe, ev.attrs.ExecTS
					if u != e.upd {
						e.upd = u
						b.ProcUpdates = append(b.ProcUpdates, u)
					}
				}
				continue
			}
			ep := r.evProc(ev)
			if ep.ev.kind == 0 || ev.kind == evExec || ep.ev.attrs.Cmdline == "" {
				ep.ev = ev
			}
		case evExit:
			key, ok := r.keyOf(ev)
			if !ok {
				continue
			}
			if e := r.procs[key]; e != nil {
				e.exit = ev.ts
				if ev.exitCode != nil || ev.signal != nil {
					b.ProcExits = append(b.ProcExits, store.ProcExit{ID: e.id, ExitTS: &ev.ts, ExitCode: ev.exitCode, Signal: ev.signal})
				}
				continue
			}
			ep := r.evProcs[key]
			if ep == nil {
				if !ev.haveStat {
					continue
				}
				ep = r.evProc(ev) // eBPF: seen only at its exit, which says who it was
			}
			ep.exit, ep.exitCode, ep.signal = ev.ts, ev.exitCode, ev.signal
		case evOOM:
			r.applyOOM(ev, b)
		}
	}
	return len(evs)
}

// evProc returns (creating it if needed) the event-only process for ev.
func (r *Recorder) evProc(ev procEvent) *evProc {
	ep := r.evProcs[ev.key]
	if ep == nil {
		ep = &evProc{ev: ev}
		r.evProcs[ev.key] = ep
	}
	r.evByPID[ev.pid] = ev.key
	return ep
}

// keyOf finds the process an event refers to.
func (r *Recorder) keyOf(ev procEvent) (procKey, bool) {
	if ev.haveStat {
		return ev.key, true
	}
	if key, ok := r.evByPID[ev.pid]; ok {
		return key, true
	}
	if e := r.byPID[ev.pid]; e != nil {
		return e.key, true
	}
	return procKey{}, false
}

// applyOOM records an OOM kill and, for a sampled victim, a process sample
// at the kill with its RSS then, so ps shows its memory at the kill.
func (r *Recorder) applyOOM(ev procEvent, b *store.Batch) {
	o := store.OOMEvent{TS: ev.ts, PID: ev.pid, Comm: ev.attrs.Comm, RSSKB: ev.rssKB}
	key, ok := r.keyOf(ev)
	if ok {
		o.StartTime = key.start
	}
	if e := r.procs[key]; ok && e != nil {
		if o.Comm == "" {
			o.Comm = e.upd.Comm
		}
		if ev.rssKB > 0 && e.hasSamp {
			s := e.sample
			s.TS, s.RSSKB = ev.ts, ev.rssKB
			b.ProcSamples = append(b.ProcSamples, s)
			e.sample = s
			o.Snapshot = true
		}
		b.ProcExits = append(b.ProcExits, store.ProcExit{ID: e.id, OOMKilled: true})
	} else if ok {
		ep := r.evProcs[key]
		if ep == nil && ev.haveStat {
			ep = r.evProc(ev)
		}
		if ep != nil {
			ep.oom = true
		}
	}
	b.OOMEvents = append(b.OOMEvents, o)
}

// flushEventProcs writes processes that only events saw (they started and
// exited between samples). It runs after the process walk, which adopts
// event-known processes that are still alive.
// A process with no exit event is kept for one more sample if its event is
// recent, since it may have been forked after the walk listed /proc.
func (r *Recorder) flushEventProcs(ts int64, b *store.Batch) {
	for key, ep := range r.evProcs {
		ev := ep.ev
		if ep.exit == 0 && ev.ts > ts-1000 {
			continue
		}
		row := store.ProcRow{ID: r.nextID("processes"), PID: key.pid, StartTime: key.start,
			PPID: ev.attrs.PPID, UID: ev.attrs.UID, Comm: ev.attrs.Comm, Cmdline: ev.attrs.Cmdline,
			TTY: ev.tty, SID: ev.sid, PGRP: ev.pgrp, FirstSeen: key.start, Source: ev.attrs.Source,
			Exe: ev.attrs.Exe, ExitCode: ep.exitCode, Signal: ep.signal, OOMKilled: ep.oom}
		if ev.attrs.ExecTS != 0 {
			row.ExecTS = &ev.attrs.ExecTS
		}
		last := key.start
		if ep.exit != 0 {
			last = ep.exit
			row.Ended = &last
			if ep.exitCode != nil || ep.signal != nil {
				row.ExitTS = &last
			}
		}
		row.LastSeen = &last
		b.ProcInserts = append(b.ProcInserts, row)
		delete(r.evProcs, key)
		if r.evByPID[key.pid] == key {
			delete(r.evByPID, key.pid)
		}
	}
}
