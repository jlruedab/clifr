package query

import (
	"net/netip"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// TestZeroStoredAsValue: parquet-go stores the third of owner_until 0, T, 0
// as a 0 value instead of NULL (pqstore.ZeroNull). Read as a value, ss
// took it for "the application closed the socket at 0" and showed the
// connection without its owner.
func TestZeroStoredAsValue(t *testing.T) {
	ip := func(s string) store.Addr { return store.AddrOf(netip.MustParseAddr(s)) }
	conn := func(id int64, rport uint16, ownerUntil int64) store.TCPConn {
		return store.TCPConn{ID: id, PID: 10, StartTime: 900, FD: int32(id), Family: 4, LAddr: ip("127.0.0.1"),
			LPort: 30000, RAddr: ip("127.0.0.2"), RPort: rport, OpenTS: 1000, OwnerUntil: ownerUntil, LastSeen: 9000,
			FirstState: 1, Source: store.SrcEBPF}
	}
	db := testrec.Open(t, nil, &store.Batch{Sample: store.Sample{TS: 1000},
		ProcInserts: []store.ProcRow{{ID: 101, PID: 10, StartTime: 900, PPID: 1, Comm: "srv", FirstSeen: 400, Source: "sample"}},
		TCPConns:    []store.TCPConn{conn(1, 4001, 0), conn(2, 4002, 2000), conn(3, 4003, 0)},
	}, &store.Batch{Sample: store.Sample{TS: 9000}})
	var stored int
	if err := db.QueryRow(`SELECT count(*) FROM tcp_conns WHERE owner_until = 0`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Errorf("%d owner_until loaded as 0, want NULL", stored)
	}
	rows, _, err := ConnsAt(db, 5000, "tcp", SockFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if hasOwner := len(r.Owners) > 0; hasOwner != (r.RPort != 4002) {
			t.Errorf("port %d: owners %v", r.RPort, r.Owners)
		}
	}
}
