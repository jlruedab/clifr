package recorder

import (
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"sosv/internal/bpftcp"
	"sosv/internal/procfs"
	"sosv/internal/sockdiag"
	"sosv/internal/store"
)

// TCP from events: eBPF reports every connection's state changes, owner and
// close; a full sock_diag dump every KeyframeInterval records queues and
// UDP, and is reconciled with the event state. This replaces v1's socket
// dump and socket-owner walk at every sample.

type tuple struct {
	family       int
	laddr, raddr netip.Addr
	lport, rport int
}

type tconn struct {
	row         store.TCPConn
	sk          uint64 // 0: known only from a keyframe so far
	state       int
	lastEvent   int64
	lingerState int // set by a time-wait event just before TCP_CLOSE
	lingerTS    int64
	seq         int  // transitions so far
	lingerDone  bool // its time-wait ended (written, then forgotten, by flushTCP)
	dirty       bool
}

func (c *tconn) tuple() tuple {
	l, _ := netip.ParseAddr(c.row.LAddr)
	r, _ := netip.ParseAddr(c.row.RAddr)
	return tuple{c.row.Family, l, r, c.row.LPort, c.row.RPort}
}

// holder is a process holding a socket fd, from the last full fd walk.
type holder struct {
	key procKey
	fd  int
}

type tcpTracker struct {
	src *bpftcp.Source

	mu       sync.Mutex
	queue    []bpftcp.Event
	spare    []bpftcp.Event // the array of the batch applied last
	rows     store.Batch    // transitions and guard events of the events applied since the last sample
	received map[string]int64
	reported map[string][2]int64

	conns        map[uint64]*tconn // open, by sock pointer
	unattached   map[tuple]*tconn  // open, from a keyframe, no events yet
	lingering    map[tuple]*tconn  // closed, still a time-wait socket
	recentClosed map[uint64]*tconn // latest closed in this sample per sock pointer (late resets, app close)
	closedNow    []*tconn          // all closed in this sample: a pointer can be reused within one
	byInode      map[uint64]*tconn
	udpInodes    map[uint64]bool // from the last keyframe
	holders      map[uint64]holder
	// fdActive: processes that opened, accepted or closed a connection since
	// the last fd walk; their fds changed even if their fd count did not.
	fdActive map[int]bool

	lastKeyframe time.Time
	keyframes    int
	finTimeout   int64 // ms, the FIN_WAIT2 time-wait length
	pendingDump  []sockdiag.Socket
	pendingInode map[uint64]bool
	dumpStart    int64
}

const timeWaitMS = 60_000 // TCP_TIMEWAIT_LEN

func newTCPTracker(src *bpftcp.Source) *tcpTracker {
	t := &tcpTracker{src: src, received: map[string]int64{}, reported: map[string][2]int64{},
		conns: map[uint64]*tconn{}, unattached: map[tuple]*tconn{}, lingering: map[tuple]*tconn{},
		recentClosed: map[uint64]*tconn{}, byInode: map[uint64]*tconn{}, udpInodes: map[uint64]bool{},
		holders: map[uint64]holder{}, fdActive: map[int]bool{}, finTimeout: 60_000}
	if b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_fin_timeout"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 {
			t.finTimeout = int64(n) * 1000
		}
	}
	return t
}

// startTCP loads the TCP programs and starts reading their events.
// tcpReadPause is how long the reader leaves the event buffer alone while
// events are frequent. Events carry their own kernel time and are applied
// later anyway, so the pause costs nothing but buffer space.
const tcpReadPause = 20 * time.Millisecond

// tcpStat: the recorder_stats source of each event kind.
var tcpStat = func() map[bpftcp.Kind]string {
	m := map[bpftcp.Kind]string{}
	for _, k := range bpftcp.Kinds {
		m[k] = "tcp_" + k.String()
	}
	return m
}()

func (r *Recorder) startTCP(done <-chan struct{}) (stop func(), err error) {
	src, err := bpftcp.Open(r.cfg.TCPBPF)
	if err != nil {
		return nil, err
	}
	t := newTCPTracker(src)
	r.tcp = t
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var batch []bpftcp.Event
		for {
			select {
			case <-done:
				return
			default:
			}
			var err error
			batch, err = src.ReadBatch(batch[:0], time.Second, tcpReadPause)
			if err != nil && !errors.Is(err, bpftcp.ErrTimeout) {
				r.log.Printf("eBPF TCP read: %v", err)
				return
			}
			if len(batch) == 0 {
				continue
			}
			t.mu.Lock()
			t.queue = append(t.queue, batch...)
			for i := range batch {
				t.received[tcpStat[batch[i].Kind]]++
			}
			t.mu.Unlock()
		}
	}()
	return func() { wg.Wait(); src.Close() }, nil
}

// markQueued notes the processes with connection activity in events not yet
// applied (the fd walk runs before them).
func (t *tcpTracker) markQueued() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.queue {
		if e.Owner.PID != 0 {
			t.fdActive[e.Owner.PID] = true
		} else if c := t.conns[e.SK]; c != nil && c.row.PID != 0 {
			t.fdActive[c.row.PID] = true
		}
	}
}

func (t *tcpTracker) take() []bpftcp.Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	// The previous batch has been applied by now: its array takes the
	// next events.
	q := t.queue
	t.queue, t.spare = t.spare[:0], q
	return q
}

func (t *tcpTracker) stats(ts int64) []store.StatRow {
	drops := map[string]int64{}
	for k, n := range t.src.Drops() {
		if n > 0 || k != 0 {
			drops["tcp_"+k.String()] = int64(n)
		}
	}
	if n := t.src.MissedRuns(); n > 0 {
		drops["tcp_missed_runs"] = int64(n)
	}
	progs := t.src.ProgStats()
	t.mu.Lock()
	defer t.mu.Unlock()
	for name, v := range progs { // cumulative, like the event counts
		t.received[statBPFRuns+name], t.received[statBPFNS+name] = int64(v[0]), int64(v[1])
	}
	var out []store.StatRow
	seen := map[string]bool{}
	for _, m := range []map[string]int64{t.received, drops} {
		for src := range m {
			if seen[src] {
				continue
			}
			seen[src] = true
			now := [2]int64{t.received[src], drops[src]}
			prev := t.reported[src]
			out = append(out, store.StatRow{TS: ts, Source: src, Events: now[0] - prev[0], Dropped: now[1] - prev[1]})
			t.reported[src] = now
		}
	}
	return out
}

func family(f int) int {
	if f == 10 {
		return 6
	}
	return 4
}

// procKeyOf converts an owner's start time (ns since boot) to the process key.
func (r *Recorder) procKeyOf(o bpftcp.Owner) procKey {
	ticks := o.StartNS / uint64(1e9/procfs.ClockTicks)
	return procKey{pid: o.PID, start: r.boot + int64(ticks)*1000/procfs.ClockTicks}
}

func (t *tcpTracker) newConn(r *Recorder, ts int64, source string) *tconn {
	c := &tconn{row: store.TCPConn{ID: r.nextID("tcp_conns"), FD: -1, OpenTS: ts, Direction: "unknown", Source: source}}
	return c
}

func (c *tconn) setOwner(r *Recorder, o bpftcp.Owner) {
	if o.PID == 0 {
		return
	}
	k := r.procKeyOf(o)
	if c.row.PID != k.pid || c.row.StartTime != k.start {
		c.row.PID, c.row.StartTime, c.row.FD = k.pid, k.start, -1
		c.dirty = true
	}
	if o.FD >= 0 && c.row.FD != o.FD {
		c.row.FD, c.dirty = o.FD, true
	}
	if o.Inode != 0 && c.row.Inode != o.Inode {
		c.row.Inode, c.dirty = o.Inode, true
	}
}

// setTuple records the connection's addresses; it reports whether they
// changed (a connect gets its source port after its first event). A
// listening socket has a local port only.
func (c *tconn) setTuple(e bpftcp.Event) bool {
	if e.SPort == 0 || e.DPort == 0 && e.New != bpftcp.Listen {
		return false
	}
	l, rr := e.SAddr.String(), e.DAddr.String()
	if c.row.LAddr != l || c.row.LPort != e.SPort || c.row.RAddr != rr || c.row.RPort != e.DPort {
		c.row.Family, c.row.LAddr, c.row.LPort, c.row.RAddr, c.row.RPort = family(e.Family), l, e.SPort, rr, e.DPort
		c.dirty = true
		return true
	}
	return false
}

// tcpDrainEvery: between samples the queued events are folded into the
// connection state this often, so that the queue holds seconds of events and
// not a whole sample interval (30 s of a busy server's events were the
// recorder's largest single use of memory).
const tcpDrainEvery = 5 * time.Second

// applyTCP folds the queued events into the connection state and hands the
// sample's rows to b.
func (r *Recorder) applyTCP(b *store.Batch) {
	r.drainTCP()
	t := r.tcp
	b.TCPTrans = append(b.TCPTrans, t.rows.TCPTrans...)
	b.Guard = append(b.Guard, t.rows.Guard...)
	t.rows.TCPTrans, t.rows.Guard = t.rows.TCPTrans[:0], nil
}

// drainTCP folds the queued events into the connection state; the rows they
// produce wait in t.rows for the next sample. Called from the sampling
// goroutine only.
func (r *Recorder) drainTCP() {
	t := r.tcp
	b := &t.rows
	for _, e := range t.take() {
		ts := wallMS(e.MonoNS)
		c := t.conns[e.SK]
		if e.Owner.PID != 0 {
			t.fdActive[e.Owner.PID] = true
		}
		if e.Kind == bpftcp.AppClose && c != nil && c.row.PID != 0 {
			t.fdActive[c.row.PID] = true
		}
		switch e.Kind {
		case bpftcp.State:
			if c != nil && (e.Old == bpftcp.Close || e.Old == bpftcp.Listen && e.New != bpftcp.Close) {
				// A new socket at the address of one still tracked: that
				// one's TCP_CLOSE was not reported (see bpftcp MissedRuns).
				// It ended when its time-wait began if that was seen, else
				// at some moment before now.
				end := ts
				if c.lingerState != 0 {
					end = c.lingerTS
				}
				t.finish(c, e.SK, end, c.state)
				b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "tcp_close_missed",
					Detail: "close not reported, found when its socket address was reused: " + c.row.LAddr + ":" + strconv.Itoa(c.row.LPort) + " -> " + c.row.RAddr + ":" + strconv.Itoa(c.row.RPort)})
				c = nil
			}
			if c == nil {
				c = t.adopt(r, e, ts)
			}
			if c.setTuple(e) {
				// Addresses still lingering in time-wait were reused (the
				// kernel's tw_reuse): that ended the time-wait socket.
				if old := t.lingering[c.tuple()]; old != nil && old != c && !old.lingerDone {
					old.row.LingerUntil, old.dirty, old.lingerDone = &ts, true, true
				}
			}
			c.setOwner(r, e.Owner)
			if e.New == bpftcp.Listen && c.row.V6Only != e.V6Only {
				c.row.V6Only, c.dirty = e.V6Only, true
			}
			if c.row.Inode != 0 {
				t.byInode[c.row.Inode] = c
			}
			c.seq++
			b.TCPTrans = append(b.TCPTrans, store.TCPTransition{ConnID: c.row.ID, TS: ts, Seq: c.seq, Old: e.Old, New: e.New})
			c.state, c.lastEvent, c.dirty = e.New, ts, true
			if e.New == bpftcp.Close {
				c.row.Retransmits += int(e.Retransmits)
				c.row.ResetsSent += int(e.ResetsSent)
				c.row.ResetsReceived += int(e.ResetsReceived)
				t.finish(c, e.SK, ts, e.Old)
			}
		case bpftcp.Accept, bpftcp.AcceptFD:
			if c == nil {
				continue // its state changes were not seen (dropped); the next keyframe adopts it
			}
			c.row.Direction = "passive"
			c.setOwner(r, e.Owner)
			if c.row.Inode != 0 {
				t.byInode[c.row.Inode] = c
			}
		case bpftcp.AppClose:
			if c == nil {
				c = t.recentClosed[e.SK]
			}
			if c != nil && c.row.OwnerUntil == nil {
				c.row.OwnerUntil, c.dirty = &ts, true
			}
		case bpftcp.TimeWaitStart:
			if c != nil {
				c.lingerState, c.lingerTS = e.New, ts
			}
		case bpftcp.TimeWaitEnd:
			tp := tuple{family(e.Family), e.SAddr, e.DAddr, e.SPort, e.DPort}
			if c := t.lingering[tp]; c != nil && !c.lingerDone {
				c.row.LingerUntil, c.dirty, c.lingerDone = &ts, true, true // exact
			}
		case bpftcp.ActiveReset:
			if c == nil {
				c = t.recentClosed[e.SK]
			}
			if c != nil {
				c.row.ResetsSent++
				c.dirty = true
			}
		}
	}
}

// finish closes a connection at ts; final is its last state before TCP_CLOSE.
func (t *tcpTracker) finish(c *tconn, sk uint64, ts int64, final int) {
	c.row.CloseTS, c.row.FinalState, c.dirty = &ts, final, true
	if c.lingerState != 0 {
		until := ts + timeWaitMS
		if c.lingerState == bpftcp.FinWait2 {
			until = ts + t.finTimeout
		}
		c.row.LingerState, c.row.LingerUntil = c.lingerState, &until
		t.lingering[c.tuple()] = c
	}
	delete(t.conns, sk)
	if t.byInode[c.row.Inode] == c {
		delete(t.byInode, c.row.Inode)
	}
	t.recentClosed[sk] = c
	t.closedNow = append(t.closedNow, c)
}

// adopt starts tracking a connection at its first event: a new connection,
// or one first seen in a keyframe (matched by its addresses).
func (t *tcpTracker) adopt(r *Recorder, e bpftcp.Event, ts int64) *tconn {
	tp := tuple{family(e.Family), e.SAddr, e.DAddr, e.SPort, e.DPort}
	if c := t.unattached[tp]; c != nil && e.Old != bpftcp.Close && e.Old != bpftcp.Listen {
		delete(t.unattached, tp)
		c.sk = e.SK
		t.conns[e.SK] = c
		return c
	}
	c := t.newConn(r, ts, "ebpf")
	c.sk = e.SK
	c.row.FirstState = e.New
	switch {
	case e.Old == bpftcp.Close && e.New == bpftcp.SynSent:
		c.row.Direction = "active"
	case e.Old == bpftcp.Close && e.New == bpftcp.Listen:
		c.row.Direction = "listen"
	case e.Old == bpftcp.Listen: // a child of a listening socket (SYN_RECV)
		c.row.Direction = "passive"
	default:
		c.row.FirstState = e.Old // already open before its first event
	}
	t.conns[e.SK] = c
	// The same addresses lingering in time-wait were reused: that ended it.
	if old := t.lingering[tp]; old != nil && !old.lingerDone {
		old.row.LingerUntil, old.dirty, old.lingerDone = &ts, true, true
	}
	return c
}

// prepareKeyframe dumps all sockets before the fd walk, so the walk knows
// which socket inodes are inet sockets.
func (r *Recorder) prepareKeyframe(ts int64) bool {
	t := r.tcp
	if t.keyframes > 0 && time.Since(t.lastKeyframe) < r.cfg.KeyframeInterval {
		return false
	}
	list, err := r.listSockets()
	if err != nil {
		r.log.Printf("keyframe: list sockets: %v", err)
		return false
	}
	t.pendingDump, t.dumpStart, t.lastKeyframe = list, ts, time.Now()
	t.pendingInode = map[uint64]bool{}
	for _, s := range list {
		if s.Inode != 0 {
			t.pendingInode[s.Inode] = true
		}
	}
	return true
}

// isInetInode reports whether a socket inode is a TCP or UDP socket known
// from events or keyframes (the fd walk leaves those to tcp_conns).
func (t *tcpTracker) isInetInode(ino uint64) bool {
	return t.byInode[ino] != nil || t.udpInodes[ino] || t.pendingInode[ino]
}

// keyframe writes the dump, reconciles it with the event state, adopts
// what events missed and closes what the dump no longer has. Connections
// with events since the dump started are left out of the comparison: the
// dump is not atomic.
func (r *Recorder) keyframe(b *store.Batch) {
	t := r.tcp
	list, start := t.pendingDump, t.dumpStart
	t.pendingDump, t.pendingInode = nil, nil
	if list == nil {
		return
	}
	initial := t.keyframes == 0
	t.keyframes++
	open := map[tuple]*tconn{}
	for _, c := range t.conns {
		open[c.tuple()] = c
	}
	for tp, c := range t.unattached {
		open[tp] = c
	}
	// Connections the dump may show that events of this sample already
	// closed (the events are applied after the dump): match, don't adopt.
	known := map[tuple]*tconn{}
	for _, c := range t.closedNow {
		known[c.tuple()] = c
	}
	for tp, c := range t.lingering {
		known[tp] = c
	}
	for tp, c := range open {
		known[tp] = c
	}
	inDump := map[tuple]bool{}
	t.udpInodes = map[uint64]bool{}
	rec := store.ReconcileRow{TS: start, Kind: "tcp", Initial: initial}
	for _, s := range list {
		kf := store.KeyframeRow{TS: start, Proto: s.Proto, Family: s.Family, LAddr: s.LAddr.String(), LPort: s.LPort,
			RAddr: s.RAddr.String(), RPort: s.RPort, Inode: s.Inode, State: s.State, RecvQ: int64(s.RxQ),
			SendQ: int64(s.TxQ), UID: int(s.UID), FD: -1, V6Only: s.V6Only}
		if h, ok := t.holders[s.Inode]; ok && s.Inode != 0 {
			kf.PID, kf.StartTime, kf.FD = h.key.pid, h.key.start, h.fd
		}
		if s.Proto != "tcp" {
			t.udpInodes[s.Inode] = true
			b.Keyframes = append(b.Keyframes, kf)
			continue
		}
		rec.DumpRows++
		tp := tuple{s.Family, s.LAddr, s.RAddr, s.LPort, s.RPort}
		inDump[tp] = true
		c := known[tp]
		if c != nil && c.row.OpenTS > start && c.row.FirstState != bpftcp.SynSent && c.row.Direction != "listen" &&
			c.row.Direction != "passive" {
			// First seen through an event after the dump, but it was already open.
			c.row.OpenTS, c.dirty = start, true
		}
		if c == nil {
			if !initial {
				rec.MissingFromEvents++
			}
			c = t.newConn(r, start, "keyframe")
			c.row.Family, c.row.LAddr, c.row.LPort, c.row.RAddr, c.row.RPort = s.Family, kf.LAddr, s.LPort, kf.RAddr, s.RPort
			c.row.Inode, c.row.FirstState, c.state, c.row.IfName = s.Inode, s.State, s.State, ifName(s.IfIndex)
			c.row.V6Only = s.V6Only
			if s.State == bpftcp.Listen {
				c.row.Direction = "listen"
			}
			if s.State == bpftcp.TimeWait || s.State == bpftcp.FinWait2 && s.Inode == 0 {
				// A time-wait socket: its connection closed before this run
				// (or its close was missed).
				// sock_diag reports how long it still has (idiag_expires).
				until := start + int64(s.Expires)
				c.row.CloseTS, c.row.FinalState, c.row.LingerState, c.row.LingerUntil = &start, s.State, s.State, &until
				t.lingering[tp] = c
			} else {
				t.unattached[tp] = c
				if s.Inode != 0 {
					t.byInode[s.Inode] = c
				}
			}
			c.dirty = true
		}
		if c.row.CloseTS != nil && !c.lingerDone && s.Inode == 0 && (s.State == bpftcp.TimeWait || s.State == bpftcp.FinWait2) {
			// Still a time-wait socket: the kernel says how long it has left
			// (a FIN_WAIT2 one restarts as TIME_WAIT when the peer's FIN comes).
			until := start + int64(s.Expires)
			if c.row.LingerUntil == nil || until > *c.row.LingerUntil || c.row.LingerState != s.State {
				c.row.LingerState, c.row.LingerUntil, c.dirty = s.State, &until, true
				t.lingering[tp] = c
			}
		}
		if c.row.PID == 0 && kf.PID != 0 {
			c.row.PID, c.row.StartTime, c.row.FD, c.dirty = kf.PID, kf.StartTime, kf.FD, true
		}
		kf.ConnID = c.row.ID
		if kf.PID == 0 && c.row.PID != 0 && c.row.OwnerUntil == nil {
			kf.PID, kf.StartTime, kf.FD = c.row.PID, c.row.StartTime, c.row.FD
		}
		b.Keyframes = append(b.Keyframes, kf)
	}
	// Open in events but gone from the dump: their close was missed.
	for tp, c := range open {
		if inDump[tp] || c.lastEvent >= start || c.row.OpenTS >= start || c.row.LPort == 0 {
			continue
		}
		if !initial {
			rec.ExtraInEvents++
		}
		c.row.CloseTS, c.row.FinalState, c.dirty = &start, c.state, true
		delete(t.conns, c.sk)
		delete(t.unattached, tp)
		if t.byInode[c.row.Inode] == c {
			delete(t.byInode, c.row.Inode)
		}
		b.Guard = append(b.Guard, store.GuardEvent{TS: start, Kind: "tcp_reconciled",
			Detail: "connection open in events but not in the keyframe: " + c.row.LAddr + ":" + strconv.Itoa(c.row.LPort) + " -> " + c.row.RAddr + ":" + strconv.Itoa(c.row.RPort)})
	}
	b.Reconcile = append(b.Reconcile, rec)
}

// flushTCP writes the connections that changed, and forgets time-wait
// continuations that have ended.
func (r *Recorder) flushTCP(ts int64, b *store.Batch) {
	t := r.tcp
	emit := func(c *tconn) {
		if c.dirty {
			c.row.LastSeen = max(ts, c.row.OpenTS)
			b.TCPConns = append(b.TCPConns, c.row)
			c.dirty = false
		}
	}
	for _, c := range t.conns {
		emit(c)
	}
	for _, c := range t.unattached {
		emit(c)
	}
	for _, c := range t.closedNow {
		emit(c)
	}
	// With time-wait end events the estimate is a lower bound: keep the
	// entry a little longer so that the exact end can still arrive.
	grace := int64(0)
	if t.src != nil && t.src.TWEnd {
		grace = 10_000
	}
	for tp, c := range t.lingering {
		emit(c)
		if c.lingerDone || c.row.LingerUntil != nil && *c.row.LingerUntil+grace < ts {
			delete(t.lingering, tp)
		}
	}
	// The sample is written: what closed during it is no longer needed.
	t.recentClosed, t.closedNow = map[uint64]*tconn{}, nil
}

// closeAllTCP ends every open connection at shutdown (seen until ts).
func (r *Recorder) closeAllTCP(ts int64, b *store.Batch) {
	t := r.tcp
	for _, c := range t.conns {
		c.row.LastSeen = ts
		b.TCPConns = append(b.TCPConns, c.row)
	}
	for _, c := range t.unattached {
		c.row.LastSeen = ts
		b.TCPConns = append(b.TCPConns, c.row)
	}
	for _, c := range t.lingering {
		if c.dirty {
			c.row.LastSeen = ts
			b.TCPConns = append(b.TCPConns, c.row)
		}
	}
}
