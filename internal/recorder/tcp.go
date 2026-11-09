package recorder

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"clifr/internal/bpftcp"
	"clifr/internal/procfs"
	"clifr/internal/sockdiag"
	"clifr/internal/store"
)

// TCP from events: eBPF reports every connection's state changes, owner and
// close; a full sock_diag dump every KeyframeInterval records queues and
// UDP, and is reconciled with the event state. This replaces v1's socket
// dump and socket-owner walk at every sample.

type tuple struct {
	laddr, raddr store.Addr
	lport, rport uint16
	family       uint8
	netns        uint32 // 0: the host's (containers and pods reuse addresses)
}

// tconn is a tracked connection. It holds no pointers (row is compact, see
// store.TCPConn), so the tens of thousands of them are not scanned by the
// garbage collector.
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
	return tuple{c.row.LAddr, c.row.RAddr, c.row.LPort, c.row.RPort, c.row.Family, c.row.NetNS}
}

// eventTuple: e.NetNS is already the written form (0 for the host's).
func eventTuple(e *bpftcp.Event) tuple {
	return tuple{store.AddrOf(e.SAddr), store.AddrOf(e.DAddr), uint16(e.SPort), uint16(e.DPort), family(e.Family), e.NetNS}
}

// text is the connection's addresses for guard event details.
func (c *tconn) text() string {
	f := int(c.row.Family)
	return c.row.LAddr.String(f) + ":" + strconv.Itoa(int(c.row.LPort)) + " -> " + c.row.RAddr.String(f) + ":" + strconv.Itoa(int(c.row.RPort))
}

// add16 adds to a counter that stops at its maximum.
func add16(c *uint16, n uint32) {
	*c = uint16(min(uint32(*c)+n, 0xffff))
}

// holder is a process holding a socket fd, from the last full fd walk.
type holder struct {
	key procKey
	fd  int
}

type tcpTracker struct {
	src            *bpftcp.Source
	deferred       []deferredRow       // keyframe rows to decide after the next sample's events
	pendingRec     *store.ReconcileRow // their keyframe's comparison, written then
	missedReported uint64              // recursion misses already reported as a guard event

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
	// connRows backs the batch's connection rows, reused at every sample:
	// the backends copy the rows in Write, before the next sample.
	connRows  []store.TCPConn
	byInode   map[uint64]*tconn
	udpInodes map[uint64]bool // from the last keyframe
	holders   map[uint64]holder
	// fdActive: processes that opened, accepted or closed a connection since
	// the last fd walk; their fds changed even if their fd count did not.
	fdActive map[int]bool

	lastKeyframe time.Time
	keyframes    int
	finTimeout   int64 // ms, the FIN_WAIT2 time-wait length
	twInferred   int64 // time-wait starts inferred from the close (cumulative)
	pendingDump  []sockdiag.Socket
	pendingInode map[uint64]bool
	dumpStart    int64
	netnsRead    int64 // other network namespaces read at keyframes (cumulative)
	// pendingNS: the namespaces the pending dump lists (0: the host's); a
	// connection elsewhere is not judged by that keyframe.
	pendingNS map[uint32]bool
	// nsTCPRead: the keyframe (dumpSeq) at which each other namespace's TCP
	// files were last read (netns.go); dumpSeq counts keyframes.
	nsTCPRead map[uint32]int64
	dumpSeq   int64
	// nsInitial: namespaces present at the run's first keyframe whose TCP
	// files were not read yet (the budget): read at the next keyframes.
	nsInitial map[uint32]bool
	// pendingFirst: namespaces whose TCP files the pending dump read for the
	// first time: their connections are adopted as at a run's first
	// keyframe (they may predate the run), not counted as missed events.
	pendingFirst map[uint32]bool
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
				r.log.Errorf("eBPF TCP read: %v", err)
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
			t.fdActive[int(c.row.PID)] = true
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

// missedGuard reports, when the count grew, which programs the kernel
// skipped (a BPF program already running on that CPU) and how often since
// the start; the state programs' counts include misses the second one
// reported anyway.
func (t *tcpTracker) missedGuard(ts int64) []store.GuardEvent {
	n := t.src.MissedRuns()
	if n <= t.missedReported {
		return nil
	}
	t.missedReported = n
	var parts []string
	for name, m := range t.src.MissedByProgram() {
		parts = append(parts, fmt.Sprintf("%s %d", name, m))
	}
	sort.Strings(parts)
	return []store.GuardEvent{{TS: ts, Kind: "tcp_missed_runs",
		Detail: fmt.Sprintf("%d runs of TCP programs not taken by the kernel: %s", n, strings.Join(parts, ", "))}}
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
	if t.twInferred > 0 {
		t.received["tcp_time_wait_inferred"] = t.twInferred
	}
	if t.netnsRead > 0 { // other network namespaces read at keyframes
		t.received["tcp_netns_keyframe_reads"] = t.netnsRead
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

func family(f int) uint8 {
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

func (t *tcpTracker) newConn(r *Recorder, ts int64, source store.ConnSource) *tconn {
	c := &tconn{row: store.TCPConn{ID: r.nextID("tcp_conns"), FD: -1, OpenTS: ts, Direction: store.DirUnknown, Source: source}}
	return c
}

func (c *tconn) setOwner(r *Recorder, o bpftcp.Owner) {
	if o.PID == 0 {
		return
	}
	k := r.procKeyOf(o)
	if int(c.row.PID) != k.pid || c.row.StartTime != k.start {
		c.row.PID, c.row.StartTime, c.row.FD = int32(k.pid), k.start, -1
		c.dirty = true
	}
	if o.FD >= 0 && int(c.row.FD) != o.FD {
		c.row.FD, c.dirty = int32(o.FD), true
	}
	if o.Inode != 0 && uint64(c.row.Inode) != o.Inode {
		c.row.Inode, c.dirty = uint32(o.Inode), true
	}
}

// setTuple records the connection's addresses; it reports whether they
// changed (a connect gets its source port after its first event). A
// listening socket has a local port only.
func (c *tconn) setTuple(e bpftcp.Event) bool {
	if e.SPort == 0 || e.DPort == 0 && e.New != bpftcp.Listen {
		return false
	}
	tp := eventTuple(&e)
	if c.tuple() != tp {
		c.row.Family, c.row.LAddr, c.row.LPort, c.row.RAddr, c.row.RPort = tp.family, tp.laddr, tp.lport, tp.raddr, tp.rport
		c.row.NetNS = tp.netns
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
	clock := newClockRef()
	for _, e := range t.take() {
		ts := clock.at(e.MonoNS)
		e.NetNS = r.netnsID(e.NetNS)
		c := t.conns[e.SK]
		if e.Owner.PID != 0 {
			t.fdActive[e.Owner.PID] = true
		}
		if e.Kind == bpftcp.AppClose && c != nil && c.row.PID != 0 {
			t.fdActive[int(c.row.PID)] = true
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
					Detail: "close not reported, found when its socket address was reused: " + c.text()})
				c = nil
			}
			if c == nil {
				c = t.adopt(r, e, ts)
			}
			if c.setTuple(e) {
				// Addresses still lingering in time-wait were reused (the
				// kernel's tw_reuse): that ended the time-wait socket.
				if old := t.lingering[c.tuple()]; old != nil && old != c && !old.lingerDone {
					old.row.LingerUntil, old.dirty, old.lingerDone = ts, true, true
				}
			}
			c.setOwner(r, e.Owner)
			if e.New == bpftcp.Listen && c.row.V6Only != e.V6Only {
				c.row.V6Only, c.dirty = e.V6Only, true
			}
			if c.row.Inode != 0 {
				t.byInode[uint64(c.row.Inode)] = c
			}
			c.seq++
			b.TCPTrans = append(b.TCPTrans, store.TCPTransition{ConnID: c.row.ID, TS: ts, Seq: c.seq, Old: e.Old, New: e.New})
			c.state, c.lastEvent, c.dirty = e.New, ts, true
			if e.New == bpftcp.Close {
				c.row.Retransmits += uint32(e.Retransmits)
				add16(&c.row.ResetsSent, uint32(e.ResetsSent))
				add16(&c.row.ResetsReceived, uint32(e.ResetsReceived))
				t.inferTimeWait(c, e.Old, ts)
				t.finish(c, e.SK, ts, e.Old)
			}
		case bpftcp.Accept, bpftcp.AcceptFD:
			if c == nil {
				continue // its state changes were not seen (dropped); the next keyframe adopts it
			}
			c.row.Direction = store.DirPassive
			c.setOwner(r, e.Owner)
			if c.row.Inode != 0 {
				t.byInode[uint64(c.row.Inode)] = c
			}
		case bpftcp.AppClose:
			if c == nil {
				c = t.recentClosed[e.SK]
			}
			if c != nil && c.row.OwnerUntil == 0 {
				c.row.OwnerUntil, c.dirty = ts, true
			}
		case bpftcp.TimeWaitStart:
			if c != nil {
				c.lingerState, c.lingerTS = e.New, ts
			}
		case bpftcp.TimeWaitEnd:
			if c := t.lingering[eventTuple(&e)]; c != nil && !c.lingerDone {
				c.row.LingerUntil, c.dirty, c.lingerDone = ts, true, true // exact
			}
		case bpftcp.ActiveReset:
			if c == nil {
				c = t.recentClosed[e.SK]
			}
			if c != nil {
				add16(&c.row.ResetsSent, 1)
				c.dirty = true
			}
		case bpftcp.LateCount: // counted after its TCP_CLOSE: the connection just closed there
			if c == nil {
				c = t.recentClosed[e.SK]
			}
			if c != nil {
				c.row.Retransmits += e.Retransmits
				add16(&c.row.ResetsSent, e.ResetsSent)
				add16(&c.row.ResetsReceived, e.ResetsReceived)
				c.dirty = true
			}
		case bpftcp.LocalPort: // connect() picked its port after SYN_SENT: the addresses are known now
			if c != nil && c.row.LPort == 0 {
				e.New = int(c.state)
				c.setTuple(e)
			}
		}
	}
}

// inferTimeWait: a close from FIN_WAIT2 or CLOSING without a reset is the
// kernel's tcp_time_wait (it closes the socket right after it made the
// time-wait one), so the time-wait start was missed: RHEL 8 sometimes skips
// that kprobe (another tracing program was running on the CPU). The state
// taken is TIME_WAIT, what such closes show here; a keyframe corrects it.
func (t *tcpTracker) inferTimeWait(c *tconn, old int, ts int64) {
	if c.lingerState != 0 || old != bpftcp.FinWait2 && old != bpftcp.Closing ||
		c.row.ResetsSent != 0 || c.row.ResetsReceived != 0 {
		return
	}
	c.lingerState, c.lingerTS = bpftcp.TimeWait, ts
	t.twInferred++
}

// finish closes a connection at ts; final is its last state before TCP_CLOSE.
func (t *tcpTracker) finish(c *tconn, sk uint64, ts int64, final int) {
	c.row.CloseTS, c.row.FinalState, c.dirty = ts, uint8(final), true
	if c.lingerState != 0 {
		until := ts + timeWaitMS
		if c.lingerState == bpftcp.FinWait2 {
			until = ts + t.finTimeout
		}
		c.row.LingerState, c.row.LingerUntil = uint8(c.lingerState), until
		t.lingering[c.tuple()] = c
	}
	delete(t.conns, sk)
	if t.byInode[uint64(c.row.Inode)] == c {
		delete(t.byInode, uint64(c.row.Inode))
	}
	t.recentClosed[sk] = c
	t.closedNow = append(t.closedNow, c)
}

// adopt starts tracking a connection at its first event: a new connection,
// or one first seen in a keyframe (matched by its addresses).
func (t *tcpTracker) adopt(r *Recorder, e bpftcp.Event, ts int64) *tconn {
	tp := eventTuple(&e)
	// A socket the keyframe adopted (known by its addresses only) takes its
	// first event: not a new socket (from TCP_CLOSE) nor a listener's child
	// (LISTEN to SYN_RECV), but a listener's own close (LISTEN to TCP_CLOSE).
	if c := t.unattached[tp]; c != nil && e.Old != bpftcp.Close && (e.Old != bpftcp.Listen || e.New == bpftcp.Close) {
		delete(t.unattached, tp)
		c.sk = e.SK
		t.conns[e.SK] = c
		return c
	}
	c := t.newConn(r, ts, store.SrcEBPF)
	c.sk, c.row.NetNS = e.SK, e.NetNS
	c.row.FirstState = uint8(e.New)
	switch {
	case e.Old == bpftcp.Close && e.New == bpftcp.SynSent:
		c.row.Direction = store.DirActive
	case e.Old == bpftcp.Close && e.New == bpftcp.Listen:
		c.row.Direction = store.DirListen
	case e.Old == bpftcp.Listen: // a child of a listening socket (SYN_RECV)
		c.row.Direction = store.DirPassive
	default:
		c.row.FirstState = uint8(e.Old) // already open before its first event
	}
	t.conns[e.SK] = c
	// The same addresses lingering in time-wait were reused: that ended it.
	if old := t.lingering[tp]; old != nil && !old.lingerDone {
		old.row.LingerUntil, old.dirty, old.lingerDone = ts, true, true
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
		r.log.Errorf("keyframe: list sockets: %v", err)
		return false
	}
	list, t.pendingNS = r.otherNetNSSockets(list)
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
// dumpRow applies one TCP row of a keyframe dump: c is the connection the
// events know at its addresses, or nil (then one is adopted from the dump).
func (t *tcpTracker) dumpRow(r *Recorder, b *store.Batch, s sockdiag.Socket, kf store.KeyframeRow, tp tuple, c *tconn, start int64) {
	if c == nil {
		c = t.newConn(r, start, store.SrcKeyframe)
		c.row.Family, c.row.LAddr, c.row.LPort, c.row.RAddr, c.row.RPort = kf.Family, kf.LAddr, kf.LPort, kf.RAddr, kf.RPort
		c.row.NetNS = kf.NetNS
		c.row.Inode, c.row.FirstState, c.state, c.row.IfName = uint32(s.Inode), kf.State, s.State, store.NameOf(ifName(s.IfIndex))
		c.row.V6Only = s.V6Only
		if s.State == bpftcp.Listen {
			c.row.Direction = store.DirListen
		}
		if s.State == bpftcp.TimeWait || s.State == bpftcp.FinWait2 && s.Inode == 0 {
			// A time-wait socket: its connection closed before this run
			// (or its close was missed).
			// sock_diag reports how long it still has (idiag_expires).
			until := start + int64(s.Expires)
			c.row.CloseTS, c.row.FinalState, c.row.LingerState, c.row.LingerUntil = start, kf.State, kf.State, until
			t.lingering[tp] = c
		} else {
			t.unattached[tp] = c
			if s.Inode != 0 {
				t.byInode[s.Inode] = c
			}
		}
		c.dirty = true
	}
	if c.row.CloseTS != 0 && !c.lingerDone && s.Inode == 0 && (s.State == bpftcp.TimeWait || s.State == bpftcp.FinWait2) {
		// Still a time-wait socket: the kernel says how long it has left
		// (a FIN_WAIT2 one restarts as TIME_WAIT when the peer's FIN comes).
		until := start + int64(s.Expires)
		if c.row.LingerUntil == 0 || until > c.row.LingerUntil || c.row.LingerState != kf.State {
			c.row.LingerState, c.row.LingerUntil, c.dirty = kf.State, until, true
			t.lingering[tp] = c
		}
	}
	if c.row.PID == 0 && kf.PID != 0 {
		c.row.PID, c.row.StartTime, c.row.FD, c.dirty = kf.PID, kf.StartTime, kf.FD, true
	}
	kf.ConnID = c.row.ID
	if kf.PID == 0 && c.row.PID != 0 && c.row.OwnerUntil == 0 {
		kf.PID, kf.StartTime, kf.FD = c.row.PID, c.row.StartTime, c.row.FD
	}
	b.Keyframes = append(b.Keyframes, kf)
}

// dump is not atomic.
func (r *Recorder) keyframe(b *store.Batch) {
	t := r.tcp
	list, start, covered, first := t.pendingDump, t.dumpStart, t.pendingNS, t.pendingFirst
	t.pendingDump, t.pendingInode, t.pendingNS, t.pendingFirst = nil, nil, nil, nil
	if covered == nil { // a dump set directly (tests): the host's only
		covered = map[uint32]bool{0: true}
	}
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
		kf := store.KeyframeRow{TS: start, Proto: store.ProtoOf(s.Proto), Family: uint8(s.Family), LAddr: store.AddrOf(s.LAddr),
			LPort: uint16(s.LPort), RAddr: store.AddrOf(s.RAddr), RPort: uint16(s.RPort), Inode: s.Inode, State: uint8(s.State),
			RecvQ: int64(s.RxQ), SendQ: int64(s.TxQ), UID: int32(s.UID), FD: -1, V6Only: s.V6Only, NetNS: s.NetNS}
		if h, ok := t.holders[s.Inode]; ok && s.Inode != 0 {
			kf.PID, kf.StartTime, kf.FD = int32(h.key.pid), h.key.start, int32(h.fd)
		}
		if s.Proto != "tcp" {
			t.udpInodes[s.Inode] = true
			b.Keyframes = append(b.Keyframes, kf)
			continue
		}
		rec.DumpRows++
		tp := tuple{kf.LAddr, kf.RAddr, kf.LPort, kf.RPort, kf.Family, kf.NetNS}
		inDump[tp] = true
		c := known[tp]
		if c != nil && c.row.OpenTS > start && int(c.row.FirstState) != bpftcp.SynSent && c.row.Direction != store.DirListen &&
			c.row.Direction != store.DirPassive {
			// First seen through an event after the dump, but it was already open.
			c.row.OpenTS, c.dirty = start, true
		}
		if c == nil && !initial && !first[kf.NetNS] {
			// Not known to the events yet: its connect or accept may have
			// come just before the dump, its event still on its way. Decided
			// after the next sample's events (resolveDeferred).
			t.deferred = append(t.deferred, deferredRow{s, kf, tp, start})
			continue
		}
		t.dumpRow(r, b, s, kf, tp, c, start)
	}
	// Open in events but gone from the dump: their close was missed.
	for tp, c := range open {
		if inDump[tp] || c.lastEvent >= start || c.row.OpenTS >= start || c.row.LPort == 0 || !covered[c.row.NetNS] {
			continue
		}
		if !initial {
			rec.ExtraInEvents++
		}
		c.row.CloseTS, c.row.FinalState, c.dirty = start, uint8(c.state), true
		t.closedNow = append(t.closedNow, c) // written by flushTCP
		delete(t.conns, c.sk)
		delete(t.unattached, tp)
		if t.byInode[uint64(c.row.Inode)] == c {
			delete(t.byInode, uint64(c.row.Inode))
		}
		b.Guard = append(b.Guard, store.GuardEvent{TS: start, Kind: "tcp_reconciled",
			Detail: "connection open in events but not in the keyframe: " + c.text()})
	}
	if len(t.deferred) > 0 {
		t.pendingRec = &rec // written when the deferred rows are decided
		return
	}
	b.Reconcile = append(b.Reconcile, rec)
}

// deferredRow is a dump row no event explained when the keyframe was read.
type deferredRow struct {
	s     sockdiag.Socket
	kf    store.KeyframeRow
	tp    tuple
	start int64
}

// resolveDeferred decides the dump rows the events did not know at the
// keyframe, now that the events of the next sample are applied: matched by
// their addresses, or adopted from the dump and counted as missed by the
// events.
func (r *Recorder) resolveDeferred(b *store.Batch) {
	t := r.tcp
	if len(t.deferred) == 0 {
		return
	}
	known := map[tuple]*tconn{}
	for _, c := range t.recentClosed {
		known[c.tuple()] = c
	}
	for _, c := range t.closedNow {
		known[c.tuple()] = c
	}
	for tp, c := range t.lingering {
		known[tp] = c
	}
	for tp, c := range t.unattached {
		known[tp] = c
	}
	for _, c := range t.conns {
		known[c.tuple()] = c
	}
	for _, d := range t.deferred {
		c := known[d.tp]
		if c == nil && t.pendingRec != nil {
			t.pendingRec.MissingFromEvents++
		}
		t.dumpRow(r, b, d.s, d.kf, d.tp, c, d.start)
	}
	t.deferred = nil
	if t.pendingRec != nil {
		b.Reconcile = append(b.Reconcile, *t.pendingRec)
		t.pendingRec = nil
	}
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
	// Size the batch's rows once and reuse them: appending tens of
	// thousands of rows one by one regrew the slice many times, and a new
	// slice per sample was still 9% of all allocation at the busy load.
	n := 0
	count := func(c *tconn) {
		if c.dirty {
			n++
		}
	}
	for _, c := range t.conns {
		count(c)
	}
	for _, c := range t.unattached {
		count(c)
	}
	for _, c := range t.closedNow {
		count(c)
	}
	for _, c := range t.lingering {
		count(c)
	}
	if len(b.TCPConns) == 0 {
		if cap(t.connRows) > 4*max(n, 1024) {
			t.connRows = nil // after a peak: do not keep it forever
		}
		b.TCPConns = t.connRows[:0]
	}
	b.TCPConns = slices.Grow(b.TCPConns, n)
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
		if c.lingerDone || c.row.LingerUntil != 0 && c.row.LingerUntil+grace < ts {
			delete(t.lingering, tp)
		}
	}
	t.connRows = b.TCPConns
	// The sample is written: what closed during it is no longer needed.
	t.recentClosed, t.closedNow = map[uint64]*tconn{}, nil
}

// closeAllTCP ends every open connection at shutdown (seen until ts).
func (r *Recorder) closeAllTCP(ts int64, b *store.Batch) {
	r.resolveDeferred(b)
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
