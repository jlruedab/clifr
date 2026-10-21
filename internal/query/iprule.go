package query

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"clifr/internal/rtnl"
	"clifr/internal/store"
)

// FRA_* attributes of a fib rule (linux/fib_rules.h).
const (
	fraDst              = 1
	fraSrc              = 2
	fraIifname          = 3
	fraGoto             = 4
	fraPriority         = 6
	fraFwmark           = 10
	fraFlow             = 11
	fraTunID            = 12
	fraSuppressIfgroup  = 13
	fraSuppressPrefixln = 14
	fraTable            = 15
	fraFwmask           = 16
	fraOifname          = 17
	fraL3mdev           = 19
	fraUIDRange         = 20
	fraProtocol         = 21
	fraIPProto          = 22
	fraSportRange       = 23
	fraDportRange       = 24
)

// PrintIPRule prints the rules of a family like iproute2's ip rule list.
func PrintIPRule(w io.Writer, rules []store.RoutingRow, family int, details bool) {
	ne := binary.NativeEndian
	for _, r := range rules {
		m := r.Msg
		if len(m) < 12 || int(m[0]) != family {
			continue
		}
		dstLen, srcLen, tos, action := int(m[1]), int(m[2]), int(m[3]), int(m[7])
		flags := ne.Uint32(m[8:])
		hostLen := 32
		if family == 10 {
			hostLen = 128
		}
		attr := map[int][]byte{}
		rtnl.Attrs(m, 12, func(t int, v []byte) { attr[t] = v })
		u32 := func(t int) (uint32, bool) {
			v, ok := attr[t]
			if !ok || len(v) < 4 {
				return 0, false
			}
			return ne.Uint32(v), true
		}
		var b strings.Builder
		prio, _ := u32(fraPriority)
		fmt.Fprintf(&b, "%d:\t", prio)
		if flags&2 != 0 { // FIB_RULE_INVERT
			b.WriteString("not ")
		}
		switch src, ok := attr[fraSrc]; {
		case ok:
			b.WriteString("from " + ipString(family, src))
			if srcLen != hostLen {
				fmt.Fprintf(&b, "/%d", srcLen)
			}
		case srcLen != 0:
			fmt.Fprintf(&b, "from 0/%d", srcLen)
		default:
			b.WriteString("from all")
		}
		switch dst, ok := attr[fraDst]; {
		case ok:
			b.WriteString(" to " + ipString(family, dst))
			if dstLen != hostLen {
				fmt.Fprintf(&b, "/%d", dstLen)
			}
		case dstLen != 0:
			fmt.Fprintf(&b, " to 0/%d", dstLen)
		}
		if tos != 0 {
			fmt.Fprintf(&b, " tos 0x%02x", tos)
		}
		mark, hasMark := u32(fraFwmark)
		mask, hasMask := u32(fraFwmask)
		if hasMark || hasMask {
			fmt.Fprintf(&b, " fwmark %#x", mark)
			if hasMask && mask != 0xffffffff {
				fmt.Fprintf(&b, "/%#x", mask)
			}
		}
		if v, ok := attr[fraIifname]; ok {
			b.WriteString(" iif " + strings.TrimRight(string(v), "\x00"))
			if flags&8 != 0 {
				b.WriteString(" [detached]")
			}
		}
		if v, ok := attr[fraOifname]; ok {
			b.WriteString(" oif " + strings.TrimRight(string(v), "\x00"))
			if flags&16 != 0 {
				b.WriteString(" [detached]")
			}
		}
		if v, ok := attr[fraL3mdev]; ok && len(v) >= 1 && v[0] != 0 {
			b.WriteString(" lookup [l3mdev-table]")
		}
		if v, ok := attr[fraUIDRange]; ok && len(v) >= 8 {
			fmt.Fprintf(&b, " uidrange %d-%d", ne.Uint32(v), ne.Uint32(v[4:]))
		}
		if v, ok := attr[fraIPProto]; ok && len(v) >= 1 {
			b.WriteString(" ipproto " + map[byte]string{6: "tcp", 17: "udp", 1: "icmp", 58: "ipv6-icmp", 132: "sctp"}[v[0]])
		}
		for _, p := range []struct {
			typ  int
			name string
		}{{fraSportRange, "sport"}, {fraDportRange, "dport"}} {
			if v, ok := attr[p.typ]; ok && len(v) >= 4 {
				lo, hi := ne.Uint16(v), ne.Uint16(v[2:])
				if lo == hi {
					fmt.Fprintf(&b, " %s %d", p.name, lo)
				} else {
					fmt.Fprintf(&b, " %s %d-%d", p.name, lo, hi)
				}
			}
		}
		if v, ok := attr[fraTunID]; ok && len(v) >= 8 {
			fmt.Fprintf(&b, " tun_id %d", binary.BigEndian.Uint64(v))
		}
		table := int(m[4])
		if v, ok := u32(fraTable); ok {
			table = int(v)
		}
		if table != 0 {
			b.WriteString(" lookup " + tableName(table))
			if v, ok := u32(fraSuppressPrefixln); ok && int32(v) != -1 {
				fmt.Fprintf(&b, " suppress_prefixlength %d", int32(v))
			}
			if v, ok := u32(fraSuppressIfgroup); ok && int32(v) != -1 {
				g := fmt.Sprint(v)
				if v == 0 {
					g = "default"
				}
				b.WriteString(" suppress_ifgroup " + g)
			}
		}
		if v, ok := u32(fraFlow); ok {
			to, from := v&0xffff, v>>16
			if from != 0 {
				fmt.Fprintf(&b, " realms %d/%d", from, to)
			} else {
				fmt.Fprintf(&b, " realms %d", to)
			}
		}
		switch {
		case action == 10: // RTN_NAT
			if gw, ok := attr[5]; ok {
				b.WriteString(" map-to " + ipString(family, gw))
			} else {
				b.WriteString(" masquerade")
			}
		case action == 2: // FR_ACT_GOTO
			if v, ok := u32(fraGoto); ok {
				fmt.Fprintf(&b, " goto %d", v)
			} else {
				b.WriteString(" goto none")
			}
			if flags&4 != 0 {
				b.WriteString(" [unresolved]")
			}
		case action == 3:
			b.WriteString(" nop")
		case action != 1:
			b.WriteString(" " + routeType(action))
		}
		if v, ok := attr[fraProtocol]; ok && len(v) >= 1 && (v[0] != 0 && v[0] != 2 || details) {
			b.WriteString(" proto " + protoName(int(v[0])))
		}
		b.WriteString("\n")
		io.WriteString(w, b.String())
	}
}
