package recorder

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"clifr/internal/bpftcp"
	"clifr/internal/procfs"
	"clifr/internal/sockdiag"
	"clifr/internal/store"
)

func tcpEvent(sk uint64, old, new int, l string, lp int, r string, rp int) bpftcp.Event {
	return bpftcp.Event{Kind: bpftcp.State, SK: sk, Old: old, New: new, Family: 2,
		SAddr: netip.MustParseAddr(l), SPort: lp, DAddr: netip.MustParseAddr(r), DPort: rp}
}

// A connection first seen in a keyframe, then closed by events, must be
// written closed and not reopened at shutdown.
func TestKeyframeThenClose(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	r.tcp = newTCPTracker(nil)
	tr := r.tcp
	tr.pendingDump = []sockdiag.Socket{{Proto: "tcp", Family: 4, State: 1, LAddr: netip.MustParseAddr("127.0.0.1"), LPort: 30000,
		RAddr: netip.MustParseAddr("127.0.0.3"), RPort: 54761, Inode: 99}}
	tr.dumpStart = 1000
	var b store.Batch
	r.applyTCP(&b)
	r.keyframe(&b)
	r.flushTCP(1000, &b)
	if len(b.TCPConns) != 1 || b.TCPConns[0].Source != store.SrcKeyframe {
		t.Fatalf("keyframe adoption: %+v", b.TCPConns)
	}
	id := b.TCPConns[0].ID

	tr.queue = []bpftcp.Event{
		tcpEvent(7, 1, 8, "127.0.0.1", 30000, "127.0.0.3", 54761),
		tcpEvent(7, 8, 9, "127.0.0.1", 30000, "127.0.0.3", 54761),
		tcpEvent(7, 9, 7, "127.0.0.1", 30000, "127.0.0.3", 54761),
	}
	b = store.Batch{}
	r.applyTCP(&b)
	r.flushTCP(2000, &b)
	closed := false
	for _, c := range b.TCPConns {
		if c.ID == id && c.CloseTS != 0 {
			closed = true
		}
	}
	if !closed || len(b.TCPTrans) != 3 {
		t.Errorf("close by events: conns %+v, transitions %d", b.TCPConns, len(b.TCPTrans))
	}
	b = store.Batch{}
	r.closeAllTCP(3000, &b)
	if len(b.TCPConns) != 0 {
		t.Errorf("reopened at shutdown: %+v", b.TCPConns)
	}
}

// Two connections on the same sock pointer, both closed within one sample:
// both must be written closed.
func TestSockPointerReuse(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	r.tcp = newTCPTracker(nil)
	r.tcp.queue = []bpftcp.Event{
		tcpEvent(7, 7, 2, "127.0.0.1", 0, "127.0.0.2", 80),
		tcpEvent(7, 2, 1, "127.0.0.1", 40000, "127.0.0.2", 80),
		tcpEvent(7, 1, 7, "127.0.0.1", 40000, "127.0.0.2", 80),
		tcpEvent(7, 7, 2, "127.0.0.1", 0, "127.0.0.2", 80),
		tcpEvent(7, 2, 1, "127.0.0.1", 40001, "127.0.0.2", 80),
		tcpEvent(7, 1, 7, "127.0.0.1", 40001, "127.0.0.2", 80),
	}
	var b store.Batch
	r.applyTCP(&b)
	r.flushTCP(1000, &b)
	closed := 0
	for _, c := range b.TCPConns {
		if c.CloseTS != 0 {
			closed++
		}
	}
	if len(b.TCPConns) != 2 || closed != 2 {
		t.Errorf("want 2 closed connections, got %+v", b.TCPConns)
	}
}

func TestMountDiff(t *testing.T) {
	w := &mountWatch{known: map[int]procfs.MountInfo{}}
	root := procfs.MountInfo{ID: 1, Point: "/", Source: "/dev/sda", FSType: "ext4", Options: "rw"}
	nfs := procfs.MountInfo{ID: 9, Point: "/srv", Source: "srv:/x", FSType: "nfs4", Options: "rw"}
	w.diff([]procfs.MountInfo{root}, 1000, "present")
	w.diff([]procfs.MountInfo{root, nfs}, 2000, "mount")
	nfs.Options = "ro"
	w.diff([]procfs.MountInfo{root, nfs}, 3000, "mount")
	w.diff([]procfs.MountInfo{root}, 4000, "mount")
	var got []string
	for _, e := range w.take() {
		got = append(got, fmt.Sprintf("%d %s %s", e.TS, e.Action, e.Point))
	}
	want := "[1000 present / 2000 mount /srv 3000 remount /srv 4000 unmount /srv]"
	if fmt.Sprint(got) != want {
		t.Errorf("got %v", got)
	}
}

// The whole table again as "present" rows once the last snapshot is old.
func TestMountRefresh(t *testing.T) {
	w := &mountWatch{known: map[int]procfs.MountInfo{}, snapAt: time.Now().UnixMilli()}
	root := procfs.MountInfo{ID: 1, Point: "/", Source: "/dev/sda", FSType: "ext4", Options: "rw"}
	nfs := procfs.MountInfo{ID: 9, Point: "/srv", Source: "srv:/x", FSType: "nfs4", Options: "rw"}
	w.diff([]procfs.MountInfo{root, nfs}, w.snapAt, "present")
	w.take()
	w.refresh(time.Hour.Milliseconds())
	if p := w.take(); len(p) != 0 {
		t.Fatalf("snapshot within the hour: %+v", p)
	}
	w.refresh(0)
	var got []string
	for _, e := range w.take() {
		got = append(got, fmt.Sprintf("%s %s %d", e.Action, e.Point, e.Seq))
	}
	if fmt.Sprint(got) != "[present / 0 present /srv 1]" {
		t.Errorf("got %v", got)
	}
}

// The exact end of a time-wait socket replaces the 60 s estimate.
func TestTimeWaitEnd(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	r.tcp = newTCPTracker(nil)
	end := tcpEvent(0x99, 0, 0, "127.0.0.1", 40000, "127.0.0.2", 80)
	end.Kind = bpftcp.TimeWaitEnd
	r.tcp.queue = []bpftcp.Event{
		tcpEvent(7, 7, 2, "127.0.0.1", 0, "127.0.0.2", 80),
		tcpEvent(7, 2, 1, "127.0.0.1", 40000, "127.0.0.2", 80),
		{Kind: bpftcp.TimeWaitStart, SK: 7, New: bpftcp.TimeWait},
		tcpEvent(7, 5, 7, "127.0.0.1", 40000, "127.0.0.2", 80),
	}
	var b store.Batch
	r.applyTCP(&b)
	r.flushTCP(1000, &b)
	r.tcp.queue = []bpftcp.Event{end}
	b = store.Batch{}
	r.applyTCP(&b)
	r.flushTCP(2000, &b)
	if len(b.TCPConns) != 1 || b.TCPConns[0].LingerUntil == 0 || b.TCPConns[0].LingerUntil-b.TCPConns[0].CloseTS >= 60_000 {
		t.Fatalf("exact end not applied: %+v", b.TCPConns)
	}
}

// A connection whose TCP_CLOSE was not reported, then a new socket at the
// same address (an accepted connection): two connections, the first closed,
// each with its own addresses.
func TestMissedClose(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	r.tcp = newTCPTracker(nil)
	r.tcp.queue = []bpftcp.Event{
		tcpEvent(7, 7, 2, "127.0.0.1", 0, "127.0.0.2", 80),
		tcpEvent(7, 2, 1, "127.0.0.1", 40000, "127.0.0.2", 80),
		tcpEvent(7, 1, 4, "127.0.0.1", 40000, "127.0.0.2", 80),
		tcpEvent(7, 10, 3, "127.0.0.2", 80, "127.0.0.1", 40001),
		tcpEvent(7, 3, 1, "127.0.0.2", 80, "127.0.0.1", 40001),
	}
	var b store.Batch
	r.applyTCP(&b)
	r.flushTCP(1000, &b)
	if len(b.TCPConns) != 2 || len(b.Guard) != 1 || b.Guard[0].Kind != "tcp_close_missed" {
		t.Fatalf("want 2 connections and a tcp_close_missed event, got %+v, %+v", b.TCPConns, b.Guard)
	}
	for _, c := range b.TCPConns {
		switch c.LPort {
		case 40000:
			if c.CloseTS == 0 || c.Direction != store.DirActive || c.FinalState != 4 {
				t.Errorf("first connection not closed: %+v", c)
			}
		case 80:
			if c.CloseTS != 0 || c.Direction != store.DirPassive || c.RPort != 40001 {
				t.Errorf("second connection: %+v", c)
			}
		default:
			t.Errorf("unexpected connection %+v", c)
		}
	}
}

// A connection open in events but gone from a keyframe (its close was
// missed) must be written closed.
func TestReconciledClose(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	r.tcp = newTCPTracker(nil)
	r.tcp.queue = []bpftcp.Event{
		tcpEvent(7, 7, 2, "127.0.0.1", 0, "127.0.0.2", 80),
		tcpEvent(7, 2, 1, "127.0.0.1", 40000, "127.0.0.2", 80),
	}
	var b store.Batch
	r.applyTCP(&b)
	r.flushTCP(1000, &b)
	if len(b.TCPConns) != 1 || b.TCPConns[0].CloseTS != 0 {
		t.Fatalf("want 1 open connection, got %+v", b.TCPConns)
	}
	start := b.TCPConns[0].OpenTS + 60_000
	r.tcp.keyframes = 1 // not the initial keyframe
	r.tcp.pendingDump, r.tcp.dumpStart = []sockdiag.Socket{}, start
	b = store.Batch{}
	r.applyTCP(&b)
	r.keyframe(&b)
	r.flushTCP(start, &b)
	if len(b.Guard) != 1 || b.Guard[0].Kind != "tcp_reconciled" {
		t.Fatalf("want a tcp_reconciled event, got %+v", b.Guard)
	}
	if len(b.TCPConns) != 1 || b.TCPConns[0].CloseTS != start {
		t.Errorf("reconciled connection not written closed: %+v", b.TCPConns)
	}
}

// A reset counted after a connection's TCP_CLOSE belongs to it, not to the
// next connection at the same sock pointer.
func TestLateCount(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	r.tcp = newTCPTracker(nil)
	r.tcp.queue = []bpftcp.Event{
		tcpEvent(7, 10, 3, "127.0.0.2", 80, "127.0.0.1", 40000),
		tcpEvent(7, 3, 1, "127.0.0.2", 80, "127.0.0.1", 40000),
		tcpEvent(7, 1, 7, "127.0.0.2", 80, "127.0.0.1", 40000),
		{Kind: bpftcp.ActiveReset, SK: 7},
		{Kind: bpftcp.LateCount, SK: 7, ResetsSent: 1},
		tcpEvent(7, 10, 3, "127.0.0.2", 80, "127.0.0.1", 40001), // the pointer reused
		tcpEvent(7, 3, 1, "127.0.0.2", 80, "127.0.0.1", 40001),
	}
	var b store.Batch
	r.applyTCP(&b)
	r.flushTCP(1000, &b)
	for _, c := range b.TCPConns {
		switch {
		case c.RPort == 40000 && c.ResetsSent != 2:
			t.Errorf("aborted connection: %d resets sent, want 2", c.ResetsSent)
		case c.RPort == 40001 && c.ResetsSent != 0:
			t.Errorf("next connection at the pointer: %d resets sent, want 0", c.ResetsSent)
		}
	}
	if len(b.TCPConns) != 2 {
		t.Errorf("want 2 connections, got %d", len(b.TCPConns))
	}
}

// A listener first seen in a keyframe, then closed: the close event (from
// a sock pointer the tracker has not seen) must close it.
func TestKeyframeListenerClose(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	r.tcp = newTCPTracker(nil)
	tr := r.tcp
	tr.pendingDump = []sockdiag.Socket{{Proto: "tcp", Family: 4, State: bpftcp.Listen, LAddr: netip.MustParseAddr("0.0.0.0"), LPort: 1739,
		RAddr: netip.MustParseAddr("0.0.0.0"), Inode: 99}}
	tr.dumpStart = 1000
	var b store.Batch
	r.applyTCP(&b)
	r.keyframe(&b)
	r.flushTCP(1000, &b)
	tr.queue = []bpftcp.Event{tcpEvent(9, bpftcp.Listen, bpftcp.Close, "0.0.0.0", 1739, "0.0.0.0", 0)}
	b = store.Batch{}
	r.applyTCP(&b)
	r.flushTCP(2000, &b)
	closed := 0
	for _, c := range b.TCPConns {
		if c.Source == store.SrcKeyframe && c.CloseTS != 0 {
			closed++
		}
	}
	if closed != 1 || len(b.TCPConns) != 1 {
		t.Errorf("the listener from the keyframe was not closed by its close event: %+v", b.TCPConns)
	}
}

// A connection in a later keyframe whose connect event is applied only in
// the next sample (it came just before the dump): one connection, not
// counted as missed by the events.
func TestDeferredDumpRow(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	r.tcp = newTCPTracker(nil)
	tr := r.tcp
	tr.keyframes = 1 // not the initial keyframe
	tr.pendingDump = []sockdiag.Socket{{Proto: "tcp", Family: 4, State: bpftcp.SynSent, LAddr: netip.MustParseAddr("127.0.0.1"),
		LPort: 40000, RAddr: netip.MustParseAddr("127.0.0.2"), RPort: 443, Inode: 77}}
	tr.dumpStart = 1000
	var b store.Batch
	r.applyTCP(&b)
	r.resolveDeferred(&b)
	r.keyframe(&b)
	r.flushTCP(1000, &b)
	if len(b.Reconcile) != 0 || len(tr.deferred) != 1 {
		t.Fatalf("the row should wait: %d reconcile rows, %d deferred", len(b.Reconcile), len(tr.deferred))
	}
	tr.queue = []bpftcp.Event{tcpEvent(5, bpftcp.Close, bpftcp.SynSent, "127.0.0.1", 40000, "127.0.0.2", 443)}
	b = store.Batch{}
	r.applyTCP(&b)
	r.resolveDeferred(&b)
	r.flushTCP(2000, &b)
	if len(b.Reconcile) != 1 || b.Reconcile[0].MissingFromEvents != 0 {
		t.Errorf("reconcile: %+v", b.Reconcile)
	}
	if len(b.TCPConns) != 1 || b.TCPConns[0].Source != store.SrcEBPF {
		t.Errorf("want one connection from the event, got %+v", b.TCPConns)
	}
	if len(b.Keyframes) != 1 || b.Keyframes[0].ConnID != b.TCPConns[0].ID {
		t.Errorf("keyframe row not linked to the connection: %+v", b.Keyframes)
	}
	// Still unknown after the next sample: adopted from the dump, counted.
	tr.keyframes = 2
	tr.pendingDump = []sockdiag.Socket{{Proto: "tcp", Family: 4, State: 1, LAddr: netip.MustParseAddr("127.0.0.1"),
		LPort: 40001, RAddr: netip.MustParseAddr("127.0.0.2"), RPort: 443, Inode: 78}}
	tr.dumpStart = 3000
	b = store.Batch{}
	r.applyTCP(&b)
	r.resolveDeferred(&b)
	r.keyframe(&b)
	r.applyTCP(&b)
	r.resolveDeferred(&b)
	if len(b.Reconcile) != 1 || b.Reconcile[0].MissingFromEvents != 1 {
		t.Errorf("unexplained row: reconcile %+v", b.Reconcile)
	}
}

// A connect stuck in SYN_SENT: its state event has no local port (the
// kernel picks it after), the connect's return reports it, and a later
// keyframe matches the connection instead of adopting a second one.
func TestLocalPort(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	r.tcp = newTCPTracker(nil)
	tr := r.tcp
	tr.keyframes = 1
	tr.queue = []bpftcp.Event{tcpEvent(5, bpftcp.Close, bpftcp.SynSent, "10.0.0.1", 0, "10.0.0.9", 443),
		{Kind: bpftcp.LocalPort, SK: 5, Family: 2, SAddr: netip.MustParseAddr("10.0.0.1"), SPort: 50900,
			DAddr: netip.MustParseAddr("10.0.0.9"), DPort: 443}}
	var b store.Batch
	r.applyTCP(&b)
	r.flushTCP(1000, &b)
	tr.pendingDump = []sockdiag.Socket{{Proto: "tcp", Family: 4, State: bpftcp.SynSent, LAddr: netip.MustParseAddr("10.0.0.1"),
		LPort: 50900, RAddr: netip.MustParseAddr("10.0.0.9"), RPort: 443, Inode: 77}}
	tr.dumpStart = 2000
	b = store.Batch{}
	r.applyTCP(&b)
	r.resolveDeferred(&b)
	r.keyframe(&b)
	r.applyTCP(&b)
	r.resolveDeferred(&b)
	r.flushTCP(3000, &b)
	if len(b.Reconcile) != 1 || b.Reconcile[0].MissingFromEvents != 0 {
		t.Errorf("reconcile: %+v", b.Reconcile)
	}
	for _, c := range b.TCPConns {
		if c.Source != store.SrcEBPF || c.LPort != 50900 {
			t.Errorf("connection %+v", c)
		}
	}
}

// A close from FIN_WAIT2 or CLOSING without a time-wait start (the kernel
// skipped that program) still leaves a time-wait socket; with a reset it
// does not, and a reported start is kept as it is.
func TestTimeWaitInferred(t *testing.T) {
	fp := newFakeProc(t)
	r, _ := newTestRecorder(t, fp.root)
	r.tcp = newTCPTracker(nil)
	conn := func(sk uint64, port int, last int) []bpftcp.Event {
		return []bpftcp.Event{
			tcpEvent(sk, 7, 2, "127.0.0.1", 0, "127.0.0.2", 80),
			tcpEvent(sk, 2, 1, "127.0.0.1", port, "127.0.0.2", 80),
			tcpEvent(sk, 1, 4, "127.0.0.1", port, "127.0.0.2", 80),
			tcpEvent(sk, 4, last, "127.0.0.1", port, "127.0.0.2", 80),
		}
	}
	closeEv := func(sk uint64, port, old int) bpftcp.Event {
		return tcpEvent(sk, old, 7, "127.0.0.1", port, "127.0.0.2", 80)
	}
	reset := closeEv(3, 40002, bpftcp.FinWait2)
	reset.ResetsReceived = 1
	var q []bpftcp.Event
	q = append(append(q, conn(1, 40000, bpftcp.FinWait2)...), closeEv(1, 40000, bpftcp.FinWait2))
	q = append(append(q, conn(2, 40001, bpftcp.Closing)...), closeEv(2, 40001, bpftcp.Closing))
	q = append(append(q, conn(3, 40002, bpftcp.FinWait2)...), reset)
	q = append(append(q, conn(4, 40003, bpftcp.FinWait2)...),
		bpftcp.Event{Kind: bpftcp.TimeWaitStart, SK: 4, New: bpftcp.FinWait2}, closeEv(4, 40003, bpftcp.FinWait2))
	r.tcp.queue = q
	var b store.Batch
	r.applyTCP(&b)
	r.flushTCP(1000, &b)
	if len(b.TCPConns) != 4 {
		t.Fatalf("want 4 connections, got %+v", b.TCPConns)
	}
	for _, c := range b.TCPConns {
		want := map[uint16]uint8{40000: bpftcp.TimeWait, 40001: bpftcp.TimeWait, 40002: 0, 40003: bpftcp.FinWait2}[c.LPort]
		if c.CloseTS == 0 || c.LingerState != want || (want == 0) != (c.LingerUntil == 0) {
			t.Errorf("port %d: linger state %d until %d, want state %d", c.LPort, c.LingerState, c.LingerUntil, want)
		}
		if want == bpftcp.TimeWait && c.LingerUntil-c.CloseTS != timeWaitMS {
			t.Errorf("port %d: time-wait until %d, closed %d", c.LPort, c.LingerUntil, c.CloseTS)
		}
	}
	if r.tcp.twInferred != 2 {
		t.Errorf("%d time-wait starts inferred, want 2", r.tcp.twInferred)
	}
}
