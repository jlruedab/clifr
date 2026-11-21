package query

import (
	"net/netip"
	"slices"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// TestConnsAtSameAddresses: rows that share addresses at a moment give one
// row, the same whatever order they are loaded in (2026-11-21: a busy
// recording gave a different ss and netstat at every run). A connection
// whose close was missed is still open in the data when a newer one reuses
// its addresses: the newer one is shown.
func TestConnsAtSameAddresses(t *testing.T) {
	ip := func(s string) store.Addr { return store.AddrOf(netip.MustParseAddr(s)) }
	conn := func(id int64, pid int32, rport uint16, open, closeTS int64) store.TCPConn {
		return store.TCPConn{ID: id, PID: pid, StartTime: 900, FD: 5, Family: 4, LAddr: ip("127.0.0.1"), LPort: 30000,
			RAddr: ip("127.0.0.2"), RPort: rport, OpenTS: open, CloseTS: closeTS, LastSeen: 9000, FirstState: 1,
			Source: store.SrcEBPF}
	}
	lingering := conn(5, 11, 4003, 1000, 2000)
	lingering.LingerState, lingering.LingerUntil = 6, 9000 // TIME-WAIT until 9000
	rows := []store.TCPConn{
		conn(1, 10, 4001, 1000, 8000), // close missed, seen gone at 8000
		conn(2, 11, 4001, 3000, 0),    // the addresses reused: the live one
		conn(3, 10, 4002, 1000, 8000),
		conn(4, 11, 4002, 1000, 0), // same open time: the higher id
		lingering,
		conn(6, 12, 4003, 4000, 0), // reuses the time-wait's addresses
	}
	want := []string{"4001 11 ESTAB", "4002 11 ESTAB", "4003 12 ESTAB"}
	for _, order := range [][]int{{0, 1, 2, 3, 4, 5}, {5, 4, 3, 2, 1, 0}, {1, 0, 3, 2, 5, 4}} {
		var b store.Batch
		b.Sample.TS = 1000
		for _, i := range order {
			b.TCPConns = append(b.TCPConns, rows[i])
		}
		db := testrec.Open(t, nil, &b, &store.Batch{Sample: store.Sample{TS: 9000}})
		for range 3 {
			got, _, err := ConnsAt(db, 5000, "tcp", SockFilter{})
			if err != nil {
				t.Fatal(err)
			}
			var s []string
			for _, r := range got {
				pid := 0
				if len(r.Owners) > 0 {
					pid = r.Owners[0].PID
				}
				s = append(s, fmtPort(int(r.RPort))+" "+fmtPort(pid)+" "+r.State)
			}
			if !slices.Equal(s, want) {
				t.Fatalf("order %v: got %v, want %v", order, s, want)
			}
		}
	}
}
