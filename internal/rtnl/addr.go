package rtnl

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// IFA_* attribute numbers (linux/if_addr.h) and message types.
const (
	ifaAddress    = 1
	ifaLocal      = 2
	ifaLabel      = 3
	ifaBroadcast  = 4
	ifaAnycast    = 5
	ifaCacheinfo  = 6
	ifaMulticast  = 7
	ifaFlags      = 8
	ifaRtPriority = 9
	ifaProto      = 11
	rtmNewAddr    = 20
	rtmDelAddr    = 21
	rtmGetAddr    = 22
	ifaddrmsgLen  = 8
)

// Addr is one interface address. Numbers are -1 when the kernel did not
// send them; Valid and Preferred are the lifetimes left when it was read,
// in seconds (0xffffffff: forever).
type Addr struct {
	Family, PrefixLen, Scope, Index int
	Flags                           uint32 // IFA_FLAGS, or ifa_flags without it
	Local, Address                  []byte
	Broadcast, Anycast, Multicast   []byte
	Label                           string
	Metric, Proto                   int64
	Valid, Preferred                int64
	Deleted                         bool // from an RTM_DELADDR notification
}

// DumpAddrs returns every address of every interface.
func DumpAddrs() ([]Addr, error) {
	var out []Addr
	err := dump(rtmGetAddr, ifaddrmsgLen, func(typ uint16, m []byte) {
		if a, ok := parseAddr(typ, m); ok {
			out = append(out, a)
		}
	})
	return out, err
}

// dump sends one RTM_GET* dump request and calls f for each reply.
func dump(typ uint16, hdrLen int, f func(typ uint16, m []byte)) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("rtnetlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	req := make([]byte, nlmsghdrLen+hdrLen)
	ne := binary.NativeEndian
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], typ)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	ne.PutUint32(req[8:], 1)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("rtnetlink send: %w", err)
	}
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("rtnetlink recv: %w", err)
		}
		done, err := messages(buf[:n], f)
		if err != nil || done {
			return err
		}
	}
}

// messages walks one datagram; done at NLMSG_DONE or a final error.
func messages(b []byte, f func(typ uint16, m []byte)) (bool, error) {
	ne := binary.NativeEndian
	for len(b) >= nlmsghdrLen {
		l := int(ne.Uint32(b[0:]))
		if l < nlmsghdrLen || l > len(b) {
			return false, errors.New("rtnetlink: truncated message")
		}
		switch typ := ne.Uint16(b[4:]); typ {
		case unix.NLMSG_DONE:
			return true, nil
		case unix.NLMSG_ERROR:
			if code := int32(ne.Uint32(b[16:])); code != 0 {
				return false, fmt.Errorf("rtnetlink: %w", unix.Errno(-code))
			}
			return true, nil
		default:
			f(typ, b[nlmsghdrLen:l])
		}
		b = b[(l+3)&^3:]
	}
	return false, nil
}

func parseAddr(typ uint16, m []byte) (Addr, bool) {
	if (typ != rtmNewAddr && typ != rtmDelAddr) || len(m) < ifaddrmsgLen {
		return Addr{}, false
	}
	ne := binary.NativeEndian
	a := Addr{Family: int(m[0]), PrefixLen: int(m[1]), Flags: uint32(m[2]), Scope: int(m[3]),
		Index: int(ne.Uint32(m[4:])), Metric: absent, Proto: absent, Valid: absent, Preferred: absent,
		Deleted: typ == rtmDelAddr}
	attrs(m[ifaddrmsgLen:], func(t int, v []byte) {
		cp := func() []byte { return append([]byte(nil), v...) }
		switch t {
		case ifaAddress:
			a.Address = cp()
		case ifaLocal:
			a.Local = cp()
		case ifaLabel:
			a.Label = cstring(v)
		case ifaBroadcast:
			a.Broadcast = cp()
		case ifaAnycast:
			a.Anycast = cp()
		case ifaMulticast:
			a.Multicast = cp()
		case ifaFlags:
			if len(v) >= 4 {
				a.Flags = ne.Uint32(v)
			}
		case ifaRtPriority:
			if len(v) >= 4 {
				a.Metric = int64(ne.Uint32(v))
			}
		case ifaProto:
			if len(v) >= 1 {
				a.Proto = int64(v[0])
			}
		case ifaCacheinfo: // ifa_prefered, ifa_valid, cstamp, tstamp
			if len(v) >= 8 {
				a.Preferred, a.Valid = int64(ne.Uint32(v[0:])), int64(ne.Uint32(v[4:]))
			}
		}
	})
	// As ip does: each of IFA_LOCAL and IFA_ADDRESS stands in for the other.
	if a.Local == nil {
		a.Local = a.Address
	}
	if a.Address == nil {
		a.Address = a.Local
	}
	return a, true
}

// Multicast groups for Monitor (RTMGRP_*).
const (
	GroupIPv4Addr  = 0x10
	GroupIPv6Addr  = 0x100
	GroupIPv4Route = 0x40
	GroupIPv6Route = 0x400
	GroupIPv4Rule  = 0x80
	GroupIPv6Rule  = 0x80000
)

// Monitor is a socket subscribed to rtnetlink change notifications.
type Monitor struct{ fd int }

// NewMonitor subscribes to the groups (Group* ORed).
func NewMonitor(groups uint32) (*Monitor, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("rtnetlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// A large buffer: a burst of route changes must not overflow it.
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	return &Monitor{fd: fd}, nil
}

// ErrOverflow: the kernel dropped notifications (ENOBUFS); dump again.
var ErrOverflow = errors.New("rtnetlink: notifications lost")

// Fd is the socket, to poll for notifications.
func (m *Monitor) Fd() int { return m.fd }

// Read returns the addresses among the notifications waiting, without
// blocking (none: nil).
func (m *Monitor) Read(buf []byte) (addrs []Addr, err error) {
	n, _, err := unix.Recvfrom(m.fd, buf, unix.MSG_DONTWAIT)
	switch {
	case errors.Is(err, unix.EAGAIN):
		return nil, nil
	case errors.Is(err, unix.ENOBUFS):
		return nil, ErrOverflow
	case err != nil:
		return nil, err
	}
	_, err = messages(buf[:n], func(typ uint16, b []byte) {
		if a, ok := parseAddr(typ, b); ok {
			addrs = append(addrs, a)
		}
	})
	return addrs, err
}

// Close ends the subscription.
func (m *Monitor) Close() error { return unix.Close(m.fd) }
