package recorder

import (
	"net/netip"
	"testing"

	"sosv/internal/bpftcp"
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
	if len(b.TCPConns) != 1 || b.TCPConns[0].Source != "keyframe" {
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
		if c.ID == id && c.CloseTS != nil {
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
		if c.CloseTS != nil {
			closed++
		}
	}
	if len(b.TCPConns) != 2 || closed != 2 {
		t.Errorf("want 2 closed connections, got %+v", b.TCPConns)
	}
}
