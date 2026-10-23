package rtnl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// NDA_* attribute numbers (linux/neighbour.h) and message types.
const (
	ndaDst       = 1
	ndaLLAddr    = 2
	ndaCacheinfo = 3
	ndaProbes    = 4
	ndaProtocol  = 12
	ndaFlagsExt  = 15
	rtmNewNeigh  = 28
	rtmGetNeigh  = 30
	ndmsgLen     = 12
	rtmNewNSID   = 88
	rtmGetNSID   = 90
	netnsaNSID   = 1
	netnsaFD     = 3
)

// Neigh is one neighbour (ARP or NDISC) entry. Ages are in USER_HZ ticks
// before the dump (nda_cacheinfo); HasCache is false when the kernel sent
// none. Probes and Protocol are -1 when not sent.
type Neigh struct {
	Family, Index           int
	State                   uint16
	Flags, Type             uint8
	ExtFlags                uint32
	Dst, LLAddr             []byte
	HasLLAddr               bool
	Probes, Protocol        int64
	HasCache                bool
	Confirmed, Used, Update uint32
	RefCnt                  uint32
}

// DumpNeighs returns every IPv4 and IPv6 neighbour, in the kernel's order
// (ip neigh lists them in it).
func DumpNeighs() ([]Neigh, error) {
	var out []Neigh
	err := dump(rtmGetNeigh, ndmsgLen, func(typ uint16, m []byte) {
		if typ != rtmNewNeigh || len(m) < ndmsgLen {
			return
		}
		ne := binary.NativeEndian
		n := Neigh{Family: int(m[0]), Index: int(int32(ne.Uint32(m[4:]))), State: ne.Uint16(m[8:]), Flags: m[10], Type: m[11],
			Probes: -1, Protocol: -1}
		Attrs(m, ndmsgLen, func(t int, v []byte) {
			switch t {
			case ndaDst:
				n.Dst = append([]byte(nil), v...)
			case ndaLLAddr:
				n.LLAddr, n.HasLLAddr = append([]byte(nil), v...), true
			case ndaCacheinfo:
				if len(v) >= 16 {
					n.HasCache = true
					n.Confirmed, n.Used, n.Update, n.RefCnt = ne.Uint32(v), ne.Uint32(v[4:]), ne.Uint32(v[8:]), ne.Uint32(v[12:])
				}
			case ndaProbes:
				if len(v) >= 4 {
					n.Probes = int64(ne.Uint32(v))
				}
			case ndaProtocol:
				if len(v) >= 1 {
					n.Protocol = int64(v[0])
				}
			case ndaFlagsExt:
				if len(v) >= 4 {
					n.ExtFlags = ne.Uint32(v)
				}
			}
		})
		out = append(out, n)
	})
	return out, err
}

// NSID returns the id this network namespace gives the namespace of the
// file (a bind mount in /run/netns), or -1 when it has none: ip netns
// prints it as "(id: N)".
func NSID(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return -1, err
	}
	defer f.Close()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, fmt.Errorf("rtnetlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return -1, err
	}
	// nlmsghdr, rtgenmsg (padded to 4), NETNSA_FD
	req := make([]byte, nlmsghdrLen+4+8)
	ne := binary.NativeEndian
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], rtmGetNSID)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST)
	ne.PutUint32(req[8:], 1)
	req[nlmsghdrLen] = unix.AF_UNSPEC
	ne.PutUint16(req[nlmsghdrLen+4:], 8)
	ne.PutUint16(req[nlmsghdrLen+6:], netnsaFD)
	ne.PutUint32(req[nlmsghdrLen+8:], uint32(f.Fd()))
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return -1, fmt.Errorf("rtnetlink send: %w", err)
	}
	buf := make([]byte, 4096)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return -1, fmt.Errorf("rtnetlink recv: %w", err)
		}
		id := -1
		_, err = messages(buf[:n], func(t uint16, m []byte) {
			if t == rtmNewNSID {
				Attrs(m, 4, func(t int, v []byte) {
					if t == netnsaNSID && len(v) >= 4 {
						id = int(int32(ne.Uint32(v)))
					}
				})
			}
		})
		return id, err
	}
}
