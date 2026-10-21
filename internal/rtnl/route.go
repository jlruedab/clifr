package rtnl

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Route and rule message types (linux/rtnetlink.h).
const (
	RTMNewRoute = 24
	RTMDelRoute = 25
	rtmGetRoute = 26
	RTMNewRule  = 32
	RTMDelRule  = 33
	rtmGetRule  = 34
	rtmsgLen    = 12 // struct rtmsg and struct fib_rule_hdr
)

// Message is one rtnetlink message: its type and the body after the
// netlink header (struct rtmsg or fib_rule_hdr, then attributes).
type Message struct {
	Type uint16
	Body []byte
}

// DumpRoutes returns every route of the family (unix.AF_INET or AF_INET6),
// all tables, in the kernel's order; DumpRules likewise the rules.
func DumpRoutes(family int) ([]Message, error) { return dumpRaw(rtmGetRoute, family) }

// DumpRules returns the policy routing rules of the family.
func DumpRules(family int) ([]Message, error) { return dumpRaw(rtmGetRule, family) }

func dumpRaw(typ uint16, family int) ([]Message, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("rtnetlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	req := make([]byte, nlmsghdrLen+rtmsgLen)
	ne := binary.NativeEndian
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], typ)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	ne.PutUint32(req[8:], 1)
	req[nlmsghdrLen] = byte(family)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("rtnetlink send: %w", err)
	}
	buf := make([]byte, 1<<20)
	var out []Message
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return out, fmt.Errorf("rtnetlink recv: %w", err)
		}
		done, err := messages(buf[:n], func(t uint16, b []byte) {
			if t == RTMNewRoute || t == RTMNewRule {
				out = append(out, Message{Type: t, Body: append([]byte(nil), b...)})
			}
		})
		if err != nil || done {
			return out, err
		}
	}
}

// ReadMessages returns the notifications waiting, without blocking: the
// addresses parsed, routes and rules raw.
func (m *Monitor) ReadMessages(buf []byte) (addrs []Addr, routing []Message, err error) {
	n, _, err := unix.Recvfrom(m.fd, buf, unix.MSG_DONTWAIT)
	switch {
	case errors.Is(err, unix.EAGAIN):
		return nil, nil, nil
	case errors.Is(err, unix.ENOBUFS):
		return nil, nil, ErrOverflow
	case err != nil:
		return nil, nil, err
	}
	_, err = messages(buf[:n], func(t uint16, b []byte) {
		switch t {
		case rtmNewAddr, rtmDelAddr:
			if a, ok := parseAddr(t, b); ok {
				addrs = append(addrs, a)
			}
		case RTMNewRoute, RTMDelRoute, RTMNewRule, RTMDelRule:
			routing = append(routing, Message{Type: t, Body: append([]byte(nil), b...)})
		}
	})
	return addrs, routing, err
}

// RTA_* attribute numbers (linux/rtnetlink.h).
const (
	RTADst          = 1
	RTASrc          = 2
	RTAIif          = 3
	RTAOif          = 4
	RTAGateway      = 5
	RTAPriority     = 6
	RTAPrefsrc      = 7
	RTAMetrics      = 8
	RTAMultipath    = 9
	RTAFlow         = 11
	RTACacheinfo    = 12
	RTATable        = 15
	RTAMark         = 16
	RTAVia          = 18
	RTANewdst       = 19
	RTAPref         = 20
	RTAEncap        = 22
	RTAExpires      = 23
	RTAUID          = 25
	RTATTLPropagate = 26
	RTANHID         = 30
)

// Attrs calls f for each attribute after a fixed header of hdrLen bytes.
func Attrs(body []byte, hdrLen int, f func(typ int, v []byte)) {
	if len(body) >= hdrLen {
		attrs(body[hdrLen:], f)
	}
}

// RouteTable is a route's table: RTA_TABLE, or rtm_table without it.
func RouteTable(body []byte) int {
	if len(body) < rtmsgLen {
		return 0
	}
	t := int(body[4])
	Attrs(body, rtmsgLen, func(typ int, v []byte) {
		if typ == RTATable && len(v) >= 4 {
			t = int(binary.NativeEndian.Uint32(v))
		}
	})
	return t
}

// RouteKey identifies a route across its changes: the family, table, type,
// destination, source, TOS, metric, outgoing interface and gateway.
func RouteKey(body []byte) string {
	if len(body) < rtmsgLen {
		return ""
	}
	var dst, src, gw []byte
	var prio, oif uint32
	Attrs(body, rtmsgLen, func(typ int, v []byte) {
		switch typ {
		case RTADst:
			dst = v
		case RTASrc:
			src = v
		case RTAGateway:
			gw = v
		case RTAPriority:
			if len(v) >= 4 {
				prio = binary.NativeEndian.Uint32(v)
			}
		case RTAOif:
			if len(v) >= 4 {
				oif = binary.NativeEndian.Uint32(v)
			}
		}
	})
	return fmt.Sprintf("%d|%d|%d|%x/%d|%x/%d|%d|%d|%d|%x", body[0], RouteTable(body), body[7], dst, body[1], src, body[2],
		body[3], prio, oif, gw)
}

// RuleKey identifies a rule: all of it (a change is a new rule).
func RuleKey(body []byte) string { return fmt.Sprintf("%x", body) }
