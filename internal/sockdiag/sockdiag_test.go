package sockdiag

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// diagMsg builds one netlink message carrying an inet_diag_msg.
func diagMsg(seq uint32, fam uint8, state uint8, laddr, raddr netip.Addr, lport, rport uint16, rq, wq, uid, inode uint32) []byte {
	ne := binary.NativeEndian
	m := make([]byte, 16+msgLen+8) // +8: a trailing attribute we must skip
	ne.PutUint32(m[0:], uint32(len(m)))
	ne.PutUint16(m[4:], sockDiagByFamily)
	ne.PutUint32(m[8:], seq)
	d := m[16:]
	d[0], d[1] = fam, state
	binary.BigEndian.PutUint16(d[4:], lport)
	binary.BigEndian.PutUint16(d[6:], rport)
	la, ra := laddr.As16(), raddr.As16()
	if fam == unix.AF_INET {
		l4, r4 := laddr.As4(), raddr.As4()
		copy(d[8:], l4[:])
		copy(d[24:], r4[:])
	} else {
		copy(d[8:], la[:])
		copy(d[24:], ra[:])
	}
	ne.PutUint32(d[40:], 1) // ifindex
	ne.PutUint32(d[56:], rq)
	ne.PutUint32(d[60:], wq)
	ne.PutUint32(d[64:], uid)
	ne.PutUint32(d[68:], inode)
	return m
}

func doneMsg(seq uint32) []byte {
	m := make([]byte, 20)
	binary.NativeEndian.PutUint32(m[0:], 20)
	binary.NativeEndian.PutUint16(m[4:], unix.NLMSG_DONE)
	binary.NativeEndian.PutUint32(m[8:], seq)
	return m
}

func TestParseMessages(t *testing.T) {
	lo := netip.MustParseAddr("127.0.0.1")
	v6 := netip.MustParseAddr("2001:db8::1")
	var buf []byte
	buf = append(buf, diagMsg(7, unix.AF_INET, 10, lo, netip.IPv4Unspecified(), 7777, 0, 3, 128, 1000, 98765)...)
	buf = append(buf, diagMsg(6, unix.AF_INET, 1, lo, lo, 1, 2, 0, 0, 0, 1)...) // other seq: ignored
	buf = append(buf, diagMsg(7, unix.AF_INET6, 1, v6, v6, 443, 50000, 1, 2, 0, 555)...)
	out, done, err := ParseMessages(buf, 7, unix.IPPROTO_TCP, nil)
	if err != nil || done || len(out) != 2 {
		t.Fatalf("out=%v done=%v err=%v", out, done, err)
	}
	want := Socket{Proto: "tcp", Family: 4, State: 10, LAddr: lo, LPort: 7777, RAddr: netip.IPv4Unspecified(),
		IfIndex: 1, RxQ: 3, TxQ: 128, UID: 1000, Inode: 98765}
	if out[0] != want {
		t.Errorf("got  %+v\nwant %+v", out[0], want)
	}
	if out[1].Family != 6 || out[1].LAddr != v6 || out[1].RPort != 50000 || out[1].Inode != 555 {
		t.Errorf("v6: %+v", out[1])
	}
	_, done, err = ParseMessages(doneMsg(7), 7, unix.IPPROTO_TCP, nil)
	if !done || err != nil {
		t.Errorf("done=%v err=%v", done, err)
	}
}

func TestParseProcNet(t *testing.T) {
	socks, err := ReadProcNet("../procfs/testdata/proc")
	if err != nil {
		t.Fatal(err)
	}
	if len(socks) != 5 {
		t.Fatalf("got %d sockets: %+v", len(socks), socks)
	}
	l := socks[0]
	if l.State != 10 || l.LAddr.String() != "127.0.0.1" || l.LPort != 7777 || l.RxQ != 3 || l.TxQ != 0 || l.Inode != 98765 || l.UID != 1000 {
		t.Errorf("listen: %+v", l)
	}
	e := socks[1]
	if e.State != 1 || e.RPort != 59844 || e.TxQ != 16 || e.RxQ != 32 {
		t.Errorf("estab: %+v", e)
	}
	if tw := socks[2]; tw.State != 6 || tw.Inode != 0 {
		t.Errorf("time-wait: %+v", tw)
	}
	if m := socks[4]; m.LAddr.String() != "::ffff:127.0.0.1" || m.LPort != 5432 || m.Family != 6 {
		t.Errorf("v4-mapped: %+v", m)
	}
}

// TestDumpMatchesProcNet checks the live sock_diag dump against /proc/net on
// the listening sockets, which are stable between the two reads.
func TestDumpMatchesProcNet(t *testing.T) {
	dump, err := Dump()
	if err != nil {
		t.Skipf("sock_diag unavailable: %v", err)
	}
	pn, err := ReadProcNet("/proc")
	if err != nil {
		t.Fatal(err)
	}
	listening := func(ss []Socket) map[uint64]Socket {
		m := map[uint64]Socket{}
		for _, s := range ss {
			if s.Proto == "tcp" && s.State == 10 {
				m[s.Inode] = s
			}
		}
		return m
	}
	a, b := listening(dump), listening(pn)
	if len(a) != len(b) {
		t.Fatalf("sock_diag %d listeners, /proc/net %d", len(a), len(b))
	}
	for ino, s := range a {
		p, ok := b[ino]
		if !ok || p.LAddr != s.LAddr || p.LPort != s.LPort {
			t.Errorf("inode %d: diag %+v procnet %+v", ino, s, p)
		}
	}
}
