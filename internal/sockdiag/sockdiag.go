// Package sockdiag lists TCP and UDP sockets through NETLINK_SOCK_DIAG
// (inet_diag), the interface `ss` uses. It only sees the recorder's own
// network namespace.
package sockdiag

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// Socket is one inet socket as reported by the kernel.
type Socket struct {
	Proto   string // "tcp" or "udp"
	Family  int    // 4 or 6
	State   int    // TCP state number (see StateName)
	LAddr   netip.Addr
	LPort   int
	RAddr   netip.Addr
	RPort   int
	IfIndex uint32 // bound device, 0 if none
	RxQ     uint32 // for LISTEN: current accept queue
	TxQ     uint32 // for LISTEN: backlog
	UID     uint32
	Inode   uint64 // 0 for TIME-WAIT and request sockets
	Timer   int    // idiag_timer: 3 = time-wait timer
	Expires uint32 // ms until the timer fires (for TIME-WAIT: until it ends)
}

const (
	sockDiagByFamily = 20
	reqLen           = 16 + 56 // nlmsghdr + inet_diag_req_v2
	msgLen           = 72      // inet_diag_msg without attributes
	allStates        = 0xffffffff
)

var stateNames = map[int]string{
	1: "ESTAB", 2: "SYN-SENT", 3: "SYN-RECV", 4: "FIN-WAIT-1", 5: "FIN-WAIT-2", 6: "TIME-WAIT",
	7: "UNCONN", 8: "CLOSE-WAIT", 9: "LAST-ACK", 10: "LISTEN", 11: "CLOSING", 12: "SYN-RECV",
}

// StateName returns the state as `ss` prints it. UDP sockets in state 7
// (TCP_CLOSE) print as UNCONN, connected UDP sockets as ESTAB.
func StateName(state int) string {
	if s, ok := stateNames[state]; ok {
		return s
	}
	return fmt.Sprintf("UNKNOWN-%d", state)
}

// Dump returns all TCP and UDP sockets, IPv4 and IPv6.
func Dump() ([]Socket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	buf := make([]byte, 1<<16)
	var out []Socket
	seq := uint32(0)
	for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
			seq++
			if err := unix.Sendto(fd, request(fam, proto, seq), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
				return nil, fmt.Errorf("netlink send: %w", err)
			}
			out, err = receive(fd, buf, seq, proto, out)
			if err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// request builds an inet_diag dump request for one family and protocol.
func request(family, proto uint8, seq uint32) []byte {
	b := make([]byte, reqLen)
	ne := binary.NativeEndian
	ne.PutUint32(b[0:], reqLen)
	ne.PutUint16(b[4:], sockDiagByFamily)
	ne.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	ne.PutUint32(b[8:], seq)
	b[16] = family
	b[17] = proto
	ne.PutUint32(b[20:], allStates)
	return b
}

func receive(fd int, buf []byte, seq uint32, proto uint8, out []Socket) ([]Socket, error) {
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return out, fmt.Errorf("netlink recv: %w", err)
		}
		var done bool
		out, done, err = ParseMessages(buf[:n], seq, proto, out)
		if err != nil || done {
			return out, err
		}
	}
}

// ParseMessages parses one netlink datagram of inet_diag replies. It reports
// done when NLMSG_DONE is seen.
func ParseMessages(b []byte, seq uint32, proto uint8, out []Socket) ([]Socket, bool, error) {
	ne := binary.NativeEndian
	for len(b) >= 16 {
		l := int(ne.Uint32(b[0:]))
		typ := ne.Uint16(b[4:])
		if l < 16 || l > len(b) {
			return out, false, errors.New("netlink: truncated message")
		}
		if ne.Uint32(b[8:]) == seq {
			switch typ {
			case unix.NLMSG_DONE:
				return out, true, nil
			case unix.NLMSG_ERROR:
				code := int32(ne.Uint32(b[16:]))
				if code == 0 {
					return out, true, nil
				}
				return out, false, fmt.Errorf("netlink: %w", unix.Errno(-code))
			case sockDiagByFamily:
				if s, ok := parseDiagMsg(b[16:l], proto); ok {
					out = append(out, s)
				}
			}
		}
		b = b[(l+3)&^3:]
	}
	return out, false, nil
}

// parseDiagMsg decodes struct inet_diag_msg. Ports and addresses are in
// network byte order; the rest is host order.
func parseDiagMsg(m []byte, proto uint8) (Socket, bool) {
	if len(m) < msgLen {
		return Socket{}, false
	}
	ne := binary.NativeEndian
	s := Socket{State: int(m[1])}
	s.Proto = "tcp"
	if proto == unix.IPPROTO_UDP {
		s.Proto = "udp"
	}
	id := m[4:52]
	s.LPort = int(binary.BigEndian.Uint16(id[0:]))
	s.RPort = int(binary.BigEndian.Uint16(id[2:]))
	switch m[0] {
	case unix.AF_INET:
		s.Family = 4
		s.LAddr = netip.AddrFrom4([4]byte(id[4:8]))
		s.RAddr = netip.AddrFrom4([4]byte(id[20:24]))
	case unix.AF_INET6:
		s.Family = 6
		s.LAddr = netip.AddrFrom16([16]byte(id[4:20]))
		s.RAddr = netip.AddrFrom16([16]byte(id[20:36]))
	default:
		return Socket{}, false
	}
	s.IfIndex = ne.Uint32(id[36:])
	s.Timer = int(m[2])
	s.Expires = ne.Uint32(m[52:])
	s.RxQ = ne.Uint32(m[56:])
	s.TxQ = ne.Uint32(m[60:])
	s.UID = ne.Uint32(m[64:])
	s.Inode = uint64(ne.Uint32(m[68:]))
	return s, true
}
