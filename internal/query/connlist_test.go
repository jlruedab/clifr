package query

import (
	"net/netip"
	"strings"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// TestConnList: every connection that existed in the range, in the order
// they opened, with its last state in the range (before TCP_CLOSE if it
// closed), and netstat's and ss's selection on that state.
func TestConnList(t *testing.T) {
	ip := func(s string) store.Addr { return store.AddrOf(netip.MustParseAddr(s)) }
	conn := func(id int64, lport uint16, open, closeTS, last int64, first, final uint8) store.TCPConn {
		return store.TCPConn{ID: id, PID: 10, StartTime: 900, FD: -1, Family: 4, LAddr: ip("10.0.0.1"), LPort: lport,
			RAddr: ip("10.0.0.2"), RPort: 443, OpenTS: open, CloseTS: closeTS, LastSeen: last, FirstState: first,
			FinalState: final, Retransmits: 3, Source: store.SrcEBPF}
	}
	listener := conn(3, 22, 500, 0, 5000, 10, 0)
	listener.RAddr, listener.RPort = store.Addr{}, 0
	db := testrec.Open(t, nil, &store.Batch{Sample: store.Sample{TS: 1000},
		ProcInserts: []store.ProcRow{{ID: 101, PID: 10, StartTime: 900, PPID: 1, Comm: "srv-worker",
			Cmdline: "/usr/bin/srv -x", Argv0Len: 12, FirstSeen: 400, Source: "sample"}},
		TCPConns: []store.TCPConn{
			conn(1, 4001, 1000, 0, 5000, 2, 0),    // open through the range: ESTAB
			conn(2, 4002, 2000, 2500, 2500, 2, 4), // closed in the range from FIN-WAIT-1
			listener,                              // LISTEN
			conn(4, 4004, 100, 200, 200, 2, 1),    // closed before the range
			conn(5, 4005, 3000, 0, 5000, 2, 0),    // CLOSE-WAIT only after the range
		},
		TCPTrans: []store.TCPTransition{
			{ConnID: 1, TS: 1001, Seq: 0, Old: 2, New: 1},
			{ConnID: 2, TS: 2001, Seq: 0, Old: 2, New: 1},
			{ConnID: 2, TS: 2400, Seq: 1, Old: 1, New: 4},
			{ConnID: 5, TS: 3001, Seq: 0, Old: 2, New: 1},
			{ConnID: 5, TS: 4500, Seq: 1, Old: 1, New: 8},
		},
	}, &store.Batch{Sample: store.Sample{TS: 5000}}) // open connections: seen until the last sample
	conns, err := ConnList(db, 1500, 4000, SockFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range conns {
		got = append(got, c.State+" "+fmtPort(c.LPort)+" "+closedCol(c.Closed)+" "+c.Program)
	}
	want := []string{"LISTEN 22 - srv", "ESTAB 4001 - srv", "FIN-WAIT-1 4002 " + FormatMS(2500) + " srv", "ESTAB 4005 - srv"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("connections:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	var b strings.Builder
	keep := conns[:0:0]
	for i := range conns {
		if (NetstatView{}).Keep(conns[i].Row()) {
			keep = append(keep, conns[i])
		}
	}
	PrintNetstatList(&b, keep, NetstatView{Program: true})
	out := b.String()
	for _, s := range []string{"Opened", "Closed", "10.0.0.1:4002", "FIN_WAIT1", FormatMS(2000) + " " + FormatMS(2500), "10/srv"} {
		if !strings.Contains(out, s) {
			t.Errorf("netstat list lacks %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "LISTEN") || strings.Contains(out, "Recv-Q") {
		t.Errorf("netstat list without -a shows a listener or queues:\n%s", out)
	}

	b.Reset()
	PrintSSList(&b, conns, SSView{All: true, Numeric: true, Process: true})
	if out := b.String(); !strings.Contains(out, `users:(("srv-worker",pid=10))`) || !strings.Contains(out, "LISTEN") {
		t.Errorf("ss list:\n%s", out)
	}
}
