package recorder

import (
	"fmt"
	"net/netip"
	"testing"

	"sosv/internal/bpftcp"
	"sosv/internal/procfs"
	"sosv/internal/sockdiag"
	"sosv/internal/store"
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
