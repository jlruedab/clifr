// Package rtnl reads network interfaces over rtnetlink (RTM_GETLINK): the
// attributes and statistics ip -s -d link prints.
package rtnl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// IFLA_* attribute numbers (linux/if_link.h).
const (
	iflaAddress                = 1
	iflaBroadcast              = 2
	iflaIfname                 = 3
	iflaMTU                    = 4
	iflaLink                   = 5
	iflaQdisc                  = 6
	iflaMaster                 = 10
	iflaTxQLen                 = 13
	iflaOperState              = 16
	iflaLinkMode               = 17
	iflaLinkInfo               = 18
	iflaIfAlias                = 20
	iflaStats64                = 23
	iflaAFSpec                 = 26
	iflaGroup                  = 27
	iflaPromiscuity            = 30
	iflaNumTxQueues            = 31
	iflaNumRxQueues            = 32
	iflaPhysPortID             = 34
	iflaCarrierChanges         = 35
	iflaPhysSwitchID           = 36
	iflaLinkNetnsID            = 37
	iflaPhysPortName           = 38
	iflaProtoDown              = 39
	iflaGSOMaxSegs             = 40
	iflaGSOMaxSize             = 41
	iflaXDP                    = 43
	iflaMinMTU                 = 50
	iflaMaxMTU                 = 51
	iflaPropList               = 52
	iflaAltIfname              = 53
	iflaPermAddress            = 54
	iflaParentDevName          = 56
	iflaParentDevBusName       = 57
	iflaGROMaxSize             = 58
	iflaTSOMaxSize             = 59
	iflaTSOMaxSegs             = 60
	iflaAllmulti               = 61
	iflaGSOIPv4MaxSize         = 63
	iflaGROIPv4MaxSize         = 64
	iflaNetnsImmutable         = 67
	iflaInfoKind               = 1
	iflaInfoData               = 2
	iflaInfoSlaveKind          = 4
	iflaInfoSlaveData          = 5
	iflaInet6AddrGenMode       = 8
	rtmNewLink                 = 16
	rtmGetLink                 = 18
	nlaTypeMask                = 0x3fff
	statsFields                = 24 // struct rtnl_link_stats64 up to rx_nohandler
	statsWithOtherhost         = 25
	ifinfomsgLen               = 16
	nlmsghdrLen                = 16
	rtaHdrLen                  = 4
	linkRequestLen             = nlmsghdrLen + ifinfomsgLen
	absent               int64 = -1
)

// Link is one interface. Numbers are -1 and byte slices nil when the kernel
// did not send the attribute (ip prints only the ones present).
type Link struct {
	Index, Type     int    // ifinfomsg: ifindex, ARPHRD_* link type
	Flags           uint32 // IFF_*
	Name            string
	MTU, Master     int64
	Link            int64 // IFLA_LINK: the lower device (name@lower)
	LinkNetnsID     int64
	OperState       int64
	LinkMode        int64
	Group           int64
	TxQLen          int64
	Promiscuity     int64
	Allmulti        int64
	MinMTU, MaxMTU  int64
	NetnsImmutable  int64
	AddrGenMode     int64 // IPv6 address generation mode (AF_SPEC)
	NumTxQueues     int64
	NumRxQueues     int64
	GSOMaxSize      int64
	GSOMaxSegs      int64
	TSOMaxSize      int64
	TSOMaxSegs      int64
	GROMaxSize      int64
	GSOIPv4MaxSize  int64
	GROIPv4MaxSize  int64
	ProtoDown       int64
	CarrierChanges  int64
	Qdisc, Alias    string
	Kind, SlaveKind string // IFLA_LINKINFO
	PhysPortName    string
	ParentBus       string
	ParentDev       string
	AltNames        []string
	Address         []byte
	Broadcast       []byte
	PermAddress     []byte
	PhysPortID      []byte
	PhysSwitchID    []byte
	InfoData        []byte // the kind's own attributes, raw (not printed yet)
	SlaveData       []byte
	XDP             bool
	// Stats are struct rtnl_link_stats64 (rx_packets, tx_packets, rx_bytes,
	// tx_bytes, rx_errors, ... rx_nohandler, rx_otherhost_dropped); Stats
	// is nil without IFLA_STATS64.
	Stats []uint64
}

// Dump returns every interface of the current network namespace.
func Dump() ([]Link, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("rtnetlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	req := make([]byte, linkRequestLen)
	ne := binary.NativeEndian
	ne.PutUint32(req[0:], linkRequestLen)
	ne.PutUint16(req[4:], rtmGetLink)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	ne.PutUint32(req[8:], 1)
	req[nlmsghdrLen] = unix.AF_UNSPEC
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("rtnetlink send: %w", err)
	}
	buf := make([]byte, 1<<16)
	var out []Link
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return out, fmt.Errorf("rtnetlink recv: %w", err)
		}
		var done bool
		if out, done, err = ParseLinks(buf[:n], out); err != nil || done {
			return out, err
		}
	}
}

// ParseLinks parses one datagram of RTM_NEWLINK replies; done at NLMSG_DONE.
func ParseLinks(b []byte, out []Link) ([]Link, bool, error) {
	ne := binary.NativeEndian
	for len(b) >= nlmsghdrLen {
		l := int(ne.Uint32(b[0:]))
		if l < nlmsghdrLen || l > len(b) {
			return out, false, errors.New("rtnetlink: truncated message")
		}
		switch ne.Uint16(b[4:]) {
		case unix.NLMSG_DONE:
			return out, true, nil
		case unix.NLMSG_ERROR:
			if code := int32(ne.Uint32(b[16:])); code != 0 {
				return out, false, fmt.Errorf("rtnetlink: %w", unix.Errno(-code))
			}
			return out, true, nil
		case rtmNewLink:
			if lk, ok := parseLink(b[nlmsghdrLen:l]); ok {
				out = append(out, lk)
			}
		}
		b = b[(l+3)&^3:]
	}
	return out, false, nil
}

// attrs calls f for each rtattr in b.
func attrs(b []byte, f func(typ int, v []byte)) {
	ne := binary.NativeEndian
	for len(b) >= rtaHdrLen {
		l := int(ne.Uint16(b[0:]))
		if l < rtaHdrLen || l > len(b) {
			return
		}
		f(int(ne.Uint16(b[2:]))&nlaTypeMask, b[rtaHdrLen:l])
		b = b[(l+3)&^3:]
	}
}

func cstring(v []byte) string { return strings.TrimRight(string(v), "\x00") }

func parseLink(m []byte) (Link, bool) {
	if len(m) < ifinfomsgLen {
		return Link{}, false
	}
	ne := binary.NativeEndian
	lk := Link{Type: int(ne.Uint16(m[2:])), Index: int(int32(ne.Uint32(m[4:]))), Flags: ne.Uint32(m[8:])}
	for _, p := range []*int64{&lk.MTU, &lk.Master, &lk.Link, &lk.LinkNetnsID, &lk.OperState, &lk.LinkMode, &lk.Group,
		&lk.TxQLen, &lk.Promiscuity, &lk.Allmulti, &lk.MinMTU, &lk.MaxMTU, &lk.NetnsImmutable, &lk.AddrGenMode,
		&lk.NumTxQueues, &lk.NumRxQueues, &lk.GSOMaxSize, &lk.GSOMaxSegs, &lk.TSOMaxSize, &lk.TSOMaxSegs,
		&lk.GROMaxSize, &lk.GSOIPv4MaxSize, &lk.GROIPv4MaxSize, &lk.ProtoDown, &lk.CarrierChanges} {
		*p = absent
	}
	u32 := func(v []byte) int64 {
		if len(v) < 4 {
			return absent
		}
		return int64(ne.Uint32(v))
	}
	u8 := func(v []byte) int64 {
		if len(v) < 1 {
			return absent
		}
		return int64(v[0])
	}
	attrs(m[ifinfomsgLen:], func(typ int, v []byte) {
		switch typ {
		case iflaIfname:
			lk.Name = cstring(v)
		case iflaAddress:
			lk.Address = append([]byte(nil), v...)
		case iflaBroadcast:
			lk.Broadcast = append([]byte(nil), v...)
		case iflaPermAddress:
			lk.PermAddress = append([]byte(nil), v...)
		case iflaMTU:
			lk.MTU = u32(v)
		case iflaLink:
			lk.Link = u32(v)
		case iflaQdisc:
			lk.Qdisc = cstring(v)
		case iflaMaster:
			lk.Master = u32(v)
		case iflaTxQLen:
			lk.TxQLen = u32(v)
		case iflaOperState:
			lk.OperState = u8(v)
		case iflaLinkMode:
			lk.LinkMode = u8(v)
		case iflaIfAlias:
			lk.Alias = cstring(v)
		case iflaGroup:
			lk.Group = u32(v)
		case iflaPromiscuity:
			lk.Promiscuity = u32(v)
		case iflaAllmulti:
			lk.Allmulti = u32(v)
		case iflaNumTxQueues:
			lk.NumTxQueues = u32(v)
		case iflaNumRxQueues:
			lk.NumRxQueues = u32(v)
		case iflaPhysPortID:
			lk.PhysPortID = append([]byte(nil), v...)
		case iflaPhysSwitchID:
			lk.PhysSwitchID = append([]byte(nil), v...)
		case iflaPhysPortName:
			lk.PhysPortName = cstring(v)
		case iflaCarrierChanges:
			lk.CarrierChanges = u32(v)
		case iflaLinkNetnsID:
			if len(v) >= 4 {
				lk.LinkNetnsID = int64(int32(ne.Uint32(v)))
			}
		case iflaProtoDown:
			lk.ProtoDown = u8(v)
		case iflaGSOMaxSegs:
			lk.GSOMaxSegs = u32(v)
		case iflaGSOMaxSize:
			lk.GSOMaxSize = u32(v)
		case iflaTSOMaxSize:
			lk.TSOMaxSize = u32(v)
		case iflaTSOMaxSegs:
			lk.TSOMaxSegs = u32(v)
		case iflaGROMaxSize:
			lk.GROMaxSize = u32(v)
		case iflaGSOIPv4MaxSize:
			lk.GSOIPv4MaxSize = u32(v)
		case iflaGROIPv4MaxSize:
			lk.GROIPv4MaxSize = u32(v)
		case iflaMinMTU:
			lk.MinMTU = u32(v)
		case iflaMaxMTU:
			lk.MaxMTU = u32(v)
		case iflaNetnsImmutable:
			lk.NetnsImmutable = u8(v)
		case iflaParentDevName:
			lk.ParentDev = cstring(v)
		case iflaParentDevBusName:
			lk.ParentBus = cstring(v)
		case iflaXDP:
			lk.XDP = true
		case iflaPropList:
			attrs(v, func(t int, a []byte) {
				if t == iflaAltIfname {
					lk.AltNames = append(lk.AltNames, cstring(a))
				}
			})
		case iflaLinkInfo:
			attrs(v, func(t int, a []byte) {
				switch t {
				case iflaInfoKind:
					lk.Kind = cstring(a)
				case iflaInfoSlaveKind:
					lk.SlaveKind = cstring(a)
				case iflaInfoData:
					lk.InfoData = append([]byte(nil), a...)
				case iflaInfoSlaveData:
					lk.SlaveData = append([]byte(nil), a...)
				}
			})
		case iflaAFSpec:
			attrs(v, func(t int, a []byte) {
				if t == unix.AF_INET6 {
					attrs(a, func(t6 int, x []byte) {
						if t6 == iflaInet6AddrGenMode {
							lk.AddrGenMode = u8(x)
						}
					})
				}
			})
		case iflaStats64:
			n := len(v) / 8
			lk.Stats = make([]uint64, statsWithOtherhost)
			for i := 0; i < n && i < statsWithOtherhost; i++ {
				lk.Stats[i] = ne.Uint64(v[i*8:])
			}
		}
	})
	return lk, lk.Name != ""
}
