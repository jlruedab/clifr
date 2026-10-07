package recorder

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"sosv/internal/cnproc"
	"sosv/internal/procfs"
	"sosv/internal/store"
)

// procEvent is a proc connector event enriched with what /proc showed at
// the moment it arrived (short-lived processes are gone by the next sample).
type procEvent struct {
	kind     cnproc.Kind
	ts       int64 // wall clock, unix ms
	pid      int
	haveStat bool
	key      procKey
	attrs    store.ProcUpdate // comm, cmdline, uid, ppid
	tty      int
	sid      int
	pgrp     int
}

// evProc is a process known only from events so far.
type evProc struct {
	ev   procEvent // latest fork/exec info
	exit int64     // exit time, 0 if not seen
}

type eventQueue struct {
	mu   sync.Mutex
	list []procEvent
	lost int // cumulative ENOBUFS count
}

func (q *eventQueue) take() ([]procEvent, int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	l := q.list
	q.list = nil
	return l, q.lost
}

// startEvents subscribes to the proc connector. If that fails the recorder
// warns and continues with sampling only.
func (r *Recorder) startEvents(ctx context.Context) (stop func()) {
	if r.fs.Root != "/proc" {
		return func() {} // fixtures: events would describe the real system
	}
	l, err := cnproc.Listen()
	if err != nil {
		r.log.Printf("warning: proc connector unavailable (%v); short-lived processes between samples will be missed", err)
		r.db.SetMeta("events", "unavailable: "+err.Error())
		return func() {}
	}
	r.db.SetMeta("events", "cn_proc")
	r.events = &eventQueue{}
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
				r.log.Printf("proc connector read: %v; continuing with sampling only", err)
				return
			}
			enriched := make([]procEvent, 0, len(evs))
			for _, e := range evs {
				enriched = append(enriched, r.enrich(e))
			}
			r.events.mu.Lock()
			r.events.list = append(r.events.list, enriched...)
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

// enrich reads the process's stat (and status/cmdline for fork and exec)
// right away. Failures are fine: the process may already be gone.
func (r *Recorder) enrich(e cnproc.Event) procEvent {
	var mono unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono)
	ageNS := mono.Nano() - int64(e.TimestampNS)
	pe := procEvent{kind: e.Kind, pid: e.PID, ts: time.Now().UnixMilli() - max(ageNS, 0)/1e6}
	st, err := r.fs.ReadStat(e.PID)
	if err != nil {
		return pe
	}
	pe.haveStat = true
	pe.key = procKey{pid: e.PID, start: r.boot + int64(st.StartTime)*1000/procfs.ClockTicks}
	pe.attrs = store.ProcUpdate{PPID: st.PPID, Comm: st.Comm, Source: "event"}
	pe.tty, pe.sid, pe.pgrp = st.TTY, st.Session, st.PGRP
	if e.Kind == cnproc.Exit {
		return pe
	}
	if status, err := r.fs.ReadStatus(e.PID); err == nil {
		pe.attrs.UID = status.UID
	}
	pe.attrs.Cmdline, _ = r.fs.ReadCmdline(e.PID)
	return pe
}

// applyEvents folds queued events into the trackers. It runs at the start
// of a sample, before the process walk.
func (r *Recorder) applyEvents(ts int64, b *store.Batch) int {
	if r.events == nil {
		return 0
	}
	evs, lost := r.events.take()
	if lost > r.lostReported {
		b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "events_lost",
			Detail: "proc connector receive buffer overflowed; some process events were dropped"})
		r.lostReported = lost
	}
	for _, ev := range evs {
		switch ev.kind {
		case cnproc.Fork, cnproc.Exec:
			if !ev.haveStat {
				continue // gone before we could read it: nothing reliable to store
			}
			if e := r.procs[ev.key]; e != nil {
				if ev.kind == cnproc.Exec { // a sampled process exec'd: new command line
					u := e.upd
					u.Comm, u.Cmdline, u.UID = ev.attrs.Comm, ev.attrs.Cmdline, ev.attrs.UID
					if u != e.upd {
						e.upd = u
						b.ProcUpdates = append(b.ProcUpdates, u)
					}
				}
				continue
			}
			ep := r.evProcs[ev.key]
			if ep == nil {
				ep = &evProc{}
				r.evProcs[ev.key] = ep
			}
			if ep.ev.kind == 0 || ev.kind == cnproc.Exec || ep.ev.attrs.Cmdline == "" {
				ep.ev = ev
			}
			r.evByPID[ev.pid] = ev.key
		case cnproc.Exit:
			key, ok := ev.key, ev.haveStat
			if !ok {
				key, ok = r.evByPID[ev.pid]
			}
			if !ok {
				if e := r.byPID[ev.pid]; e != nil {
					key, ok = e.key, true
				}
			}
			if !ok {
				continue
			}
			if e := r.procs[key]; e != nil {
				e.exit = ev.ts
			} else if ep := r.evProcs[key]; ep != nil {
				ep.exit = ev.ts
			}
		}
	}
	return len(evs)
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
			TTY: ev.tty, SID: ev.sid, PGRP: ev.pgrp, FirstSeen: key.start, Source: "event"}
		last := key.start
		if ep.exit != 0 {
			last = ep.exit
			row.Ended = &last
		}
		row.LastSeen = &last
		b.ProcInserts = append(b.ProcInserts, row)
		delete(r.evProcs, key)
		if r.evByPID[key.pid] == key {
			delete(r.evByPID, key.pid)
		}
	}
}
