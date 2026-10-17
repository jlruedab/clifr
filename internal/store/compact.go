package store

import (
	"net/netip"
	"sync"
)

// Compact field types for the rows the recorder keeps in memory by the tens
// of thousands (TCP connections, keyframe sockets). A row without strings or
// pointers is never scanned by the garbage collector, and costs no separate
// allocations for its text: at the busy load, scanning and holding those was
// most of the recorder's memory.

// Addr is an IP address in 16 bytes (IPv4 as IPv4-mapped IPv6). With the
// row's family (4 or 6) it prints exactly as the netip.Addr it came from.
type Addr [16]byte

func AddrOf(a netip.Addr) Addr { return a.As16() }

// IP is the address as netip.Addr: 4 bytes for family 4, the zero Addr for
// family 0 (not set).
func (a Addr) IP(family int) netip.Addr {
	switch family {
	case 4:
		return netip.AddrFrom16(a).Unmap()
	case 6:
		return netip.AddrFrom16(a)
	}
	return netip.Addr{}
}

// String is the address as text; "" when family is 0 (not set).
func (a Addr) String(family int) string {
	if family != 4 && family != 6 {
		return ""
	}
	return a.IP(family).String()
}

// Direction of a TCP connection; the zero value prints as "".
type Direction uint8

const (
	DirNone Direction = iota
	DirUnknown
	DirActive
	DirPassive
	DirListen
)

var dirNames = [...]string{"", "unknown", "active", "passive", "listen"}

func (d Direction) String() string {
	if int(d) < len(dirNames) {
		return dirNames[d]
	}
	return ""
}

// ConnSource is where a TCP connection was first seen; the zero value
// prints as "".
type ConnSource uint8

const (
	SrcNone ConnSource = iota
	SrcEBPF
	SrcKeyframe
)

var srcNames = [...]string{"", "ebpf", "keyframe"}

func (s ConnSource) String() string {
	if int(s) < len(srcNames) {
		return srcNames[s]
	}
	return ""
}

// Proto of a keyframe socket.
type Proto uint8

const (
	ProtoNone Proto = iota
	ProtoTCP
	ProtoUDP
)

func ProtoOf(s string) Proto {
	switch s {
	case "tcp":
		return ProtoTCP
	case "udp":
		return ProtoUDP
	}
	return ProtoNone
}

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	}
	return ""
}

// Name is an interned string of a small set that only grows (interface
// names): 0 is "". The table lives as long as the process.
type Name uint32

var names struct {
	sync.Mutex
	list []string
	idx  map[string]Name
}

func NameOf(s string) Name {
	if s == "" {
		return 0
	}
	names.Lock()
	defer names.Unlock()
	if n, ok := names.idx[s]; ok {
		return n
	}
	if names.idx == nil {
		names.idx, names.list = map[string]Name{}, []string{""}
	}
	n := Name(len(names.list))
	names.list = append(names.list, s)
	names.idx[s] = n
	return n
}

func (n Name) String() string {
	if n == 0 {
		return ""
	}
	names.Lock()
	defer names.Unlock()
	return names.list[n]
}
