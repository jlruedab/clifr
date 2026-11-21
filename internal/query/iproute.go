// Parts of this file follow iproute2's ip/iproute.c (GPL-2.0-or-later), used under the
// GPL-3.0: see LICENSING.md and packaging/notices/iproute2.txt.

package query

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"clifr/internal/rtnl"
	"clifr/internal/store"
)

// RoutingAt is every route (kind "route") or rule ("rule") at t, in the
// kernel's order: the snapshot at or before t with the changes after it
// applied (a new one goes at the end until the next dump, which clifrd takes
// about a second after changes).
func RoutingAt(db *store.DB, t int64, kind string) ([]store.RoutingRow, error) {
	var snap sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM routing WHERE kind = ? AND action = 'present' AND ts <= ?`, kind, t).Scan(&snap); err != nil || !snap.Valid {
		return nil, fmt.Errorf("%ss are not recorded at or before %s (recorded since 2026-10-21)", kind, FormatMS(t))
	}
	rows, err := db.Query(`SELECT ts, action, key, seq, family, msg FROM routing
		WHERE kind = ?3 AND ((ts = ?1 AND action = 'present') OR (ts > ?1 AND ts <= ?2 AND action != 'present'))
		ORDER BY ts, action = 'present' DESC, seq`, snap.Int64, t, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []store.RoutingRow
	at := map[string]int{}
	for rows.Next() {
		r := store.RoutingRow{Kind: kind}
		if err := rows.Scan(&r.TS, &r.Action, &r.Key, &r.Seq, &r.Family, &r.Msg); err != nil {
			return nil, err
		}
		i, ok := at[r.Key]
		switch {
		case r.Action == "del" && ok:
			list = append(list[:i], list[i+1:]...)
			at = map[string]int{}
			for j := range list {
				at[list[j].Key] = j
			}
		case r.Action == "del":
		case ok:
			list[i] = r
		default:
			at[r.Key] = len(list)
			list = append(list, r)
		}
	}
	return list, rows.Err()
}

// IPRouteOptions: ip route's family (2, 10, or 0 for both), table
// (0: all, else its number; ip's default is main) and -d.
type IPRouteOptions struct {
	Family, Table int
	Details       bool
}

var routeTypes = []string{"none", "unicast", "local", "broadcast", "anycast", "multicast", "blackhole",
	"unreachable", "prohibit", "throw", "nat", "xresolve"}

func routeType(t int) string {
	if t < len(routeTypes) {
		return routeTypes[t]
	}
	return fmt.Sprint(t)
}

func tableName(t int) string {
	switch t {
	case 0:
		return "unspec"
	case 253:
		return "default"
	case 254:
		return "main"
	case 255:
		return "local"
	}
	return fmt.Sprint(t)
}

var routeProtos = map[int]string{0: "unspec", 1: "redirect", 2: "kernel", 3: "boot", 4: "static", 8: "gated", 9: "ra",
	10: "mrt", 11: "zebra", 12: "bird", 13: "dnrouted", 14: "xorp", 15: "ntk", 16: "dhcp", 18: "keepalived",
	42: "babel", 186: "bgp", 187: "isis", 188: "ospf", 189: "rip", 192: "eigrp"}

func protoName(p int) string {
	if n, ok := routeProtos[p]; ok {
		return n
	}
	return fmt.Sprint(p)
}

var metricNames = map[int]string{2: "mtu", 3: "window", 4: "rtt", 5: "rttvar", 6: "ssthresh", 7: "cwnd", 8: "advmss",
	9: "reordering", 10: "hoplimit", 11: "initcwnd", 12: "features", 13: "rto_min", 14: "initrwnd", 15: "quickack",
	16: "congctl", 17: "fastopen_no_cookie"}

// routeFlags prints RTNH_F_* and RTM_F_* as iproute2's print_rt_flags.
func routeFlags(b *strings.Builder, flags uint32) {
	for _, f := range []struct {
		bit  uint32
		name string
	}{{1, "dead"}, {4, "onlink"}, {2, "pervasive"}, {8, "offload"}, {0x40, "trap"}, {0x100, "notify"},
		{0x10, "linkdown"}, {0x20, "unresolved"}, {0x2000, "rt_offload"}, {0x4000, "rt_trap"}, {0x20000, "rt_offload_failed"}} {
		if flags&f.bit != 0 {
			b.WriteString(f.name + " ")
		}
	}
}

// PrintIPRoute prints routes like iproute2 6.19's ip [-4|-6] [-d] route show
// [table ID|all] at the moment atMS (an expiring route's time left counts
// down to it). ifname names interfaces.
func PrintIPRoute(w io.Writer, routes []store.RoutingRow, o IPRouteOptions, ifname func(int) string, atMS int64) {
	ne := binary.NativeEndian
	multipleV6Tables := false
	for _, rt := range routes {
		m := rt.Msg
		if len(m) < 12 || o.Family != 0 && int(m[0]) != o.Family {
			continue
		}
		family, dstLen, srcLen, tos := int(m[0]), int(m[1]), int(m[2]), int(m[3])
		proto, scope, typ := int(m[5]), int(m[6]), int(m[7])
		flags := ne.Uint32(m[8:])
		table := rtnl.RouteTable(m)
		hostLen := 32
		if family == 10 {
			hostLen = 128
		}
		if flags&0x200 != 0 { // RTM_F_CLONED: cache entries are not shown
			continue
		}
		// iproute2's filter_nlmsg: IPv6 routes of a single main table are
		// told apart by type (local ones belong to "local").
		if family == 10 && table != 254 {
			multipleV6Tables = true
		}
		if family == 10 && !multipleV6Tables {
			switch {
			case o.Table == 255 && typ != 2, o.Table == 254 && typ == 2, o.Table != 0 && o.Table != 254 && o.Table != 255:
				continue
			}
		} else if o.Table > 0 && o.Table != table {
			continue
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
		if typ != 1 || o.Details {
			b.WriteString(routeType(typ) + " ")
		}
		switch dst, ok := attr[rtnl.RTADst]; {
		case ok && dstLen != hostLen:
			fmt.Fprintf(&b, "%s/%d ", ipString(family, dst), dstLen)
		case ok:
			b.WriteString(ipString(family, dst) + " ")
		case dstLen != 0:
			fmt.Fprintf(&b, "0/%d  ", dstLen)
		default:
			b.WriteString("default ")
		}
		switch src, ok := attr[rtnl.RTASrc]; {
		case ok && srcLen != hostLen:
			fmt.Fprintf(&b, "from %s/%d ", ipString(family, src), srcLen)
		case ok:
			fmt.Fprintf(&b, "from %s ", ipString(family, src))
		case srcLen != 0:
			fmt.Fprintf(&b, "from 0/%d ", srcLen)
		}
		if v, ok := u32(rtnl.RTANHID); ok {
			fmt.Fprintf(&b, "nhid %d ", v)
		}
		if tos != 0 {
			fmt.Fprintf(&b, "tos 0x%02x ", tos)
		}
		if gw, ok := attr[rtnl.RTAGateway]; ok {
			fmt.Fprintf(&b, "via %s ", ipString(family, gw))
		}
		if v, ok := attr[rtnl.RTAVia]; ok && len(v) > 2 {
			vf := int(ne.Uint16(v))
			fmt.Fprintf(&b, "via %s %s ", map[int]string{2: "inet", 10: "inet6"}[vf], ipString(vf, v[2:]))
		}
		if v, ok := u32(rtnl.RTAOif); ok {
			fmt.Fprintf(&b, "dev %s ", ifname(int(v)))
		}
		if table != 0 && (table != 254 || o.Details) && o.Table == 0 {
			fmt.Fprintf(&b, "table %s ", tableName(table))
		}
		if proto != 3 || o.Details {
			fmt.Fprintf(&b, "proto %s ", protoName(proto))
		}
		if scope != 0 || o.Details {
			fmt.Fprintf(&b, "scope %s ", scopeName(scope))
		}
		if v, ok := attr[rtnl.RTAPrefsrc]; ok {
			fmt.Fprintf(&b, "src %s ", ipString(family, v))
		}
		if v, ok := u32(rtnl.RTAPriority); ok {
			fmt.Fprintf(&b, "metric %d ", v)
		}
		routeFlags(&b, flags)
		if v, ok := u32(rtnl.RTAMark); ok && v != 0 {
			if v >= 16 {
				fmt.Fprintf(&b, "mark 0x%x ", v)
			} else {
				fmt.Fprintf(&b, "mark %d ", v)
			}
		}
		if v, ok := u32(rtnl.RTAUID); ok {
			fmt.Fprintf(&b, "uid %d ", v)
		}
		if ci, ok := attr[rtnl.RTACacheinfo]; ok && len(ci) >= 20 {
			// rta_clntref, rta_lastuse, rta_expires (USER_HZ ticks), rta_error, rta_used
			if exp := int32(ne.Uint32(ci[8:])); exp != 0 {
				left := int64(exp)/100 - (atMS-rt.TS)/1000
				fmt.Fprintf(&b, "expires %dsec ", max(left, 0))
			}
			if e := ne.Uint32(ci[12:]); e != 0 {
				fmt.Fprintf(&b, "error %d ", e)
			}
		}
		if mx, ok := attr[rtnl.RTAMetrics]; ok {
			printRouteMetrics(&b, mx)
		}
		if v, ok := u32(rtnl.RTAIif); ok {
			fmt.Fprintf(&b, "iif %s ", ifname(int(v)))
		}
		if v, ok := attr[rtnl.RTAPref]; ok && len(v) >= 1 {
			switch v[0] {
			case 3:
				b.WriteString("pref low")
			case 0:
				b.WriteString("pref medium")
			case 1:
				b.WriteString("pref high")
			default:
				fmt.Fprintf(&b, "%d", v[0])
			}
		}
		if v, ok := attr[rtnl.RTATTLPropagate]; ok && len(v) >= 1 {
			b.WriteString(map[bool]string{true: "ttl-propogate enabled", false: "ttl-propogate disabled"}[v[0] != 0])
		}
		if mp, ok := attr[rtnl.RTAMultipath]; ok {
			for len(mp) >= 8 { // struct rtnexthop: len u16, flags u8, hops u8, ifindex i32
				l := int(ne.Uint16(mp[0:]))
				if l < 8 || l > len(mp) {
					break
				}
				b.WriteString("\n\tnexthop ")
				rtnl.Attrs(mp[:l], 8, func(t int, v []byte) {
					if t == rtnl.RTAGateway {
						fmt.Fprintf(&b, "via %s ", ipString(family, v))
					}
				})
				fmt.Fprintf(&b, "dev %s weight %d ", ifname(int(int32(ne.Uint32(mp[4:])))), int(mp[3])+1)
				routeFlags(&b, uint32(mp[2]))
				mp = mp[(l+3)&^3:]
			}
		}
		b.WriteString("\n")
		io.WriteString(w, b.String())
	}
}

func printRouteMetrics(b *strings.Builder, mx []byte) {
	ne := binary.NativeEndian
	vals := map[int][]byte{}
	rtnl.Attrs(mx, 0, func(t int, v []byte) { vals[t] = v })
	var lock uint32
	if v, ok := vals[1]; ok && len(v) >= 4 {
		lock = ne.Uint32(v)
	}
	for i := 2; i <= 17; i++ {
		v, ok := vals[i]
		if !ok && lock&(1<<i) == 0 {
			continue
		}
		var val uint32
		if ok && i != 16 && len(v) >= 4 {
			val = ne.Uint32(v)
		}
		if i == 10 && int32(val) == -1 {
			continue
		}
		if n, known := metricNames[i]; known {
			b.WriteString(n + " ")
		} else {
			fmt.Fprintf(b, "metric %d ", i)
		}
		if lock&(1<<i) != 0 {
			b.WriteString("lock ")
		}
		switch i {
		case 12: // features
			if val&1 != 0 {
				b.WriteString("ecn ")
				val &^= 1
			}
			if val != 0 {
				fmt.Fprintf(b, "%#x ", val)
			}
		case 4, 5, 13: // rtt, rttvar, rto_min
			if i == 4 {
				val /= 8
			} else if i == 5 {
				val /= 4
			}
			if val >= 1000 {
				fmt.Fprintf(b, "%gs ", float64(val)/1e3)
			} else {
				fmt.Fprintf(b, "%dms ", val)
			}
		case 16: // congctl
			b.WriteString(strings.TrimRight(string(v), "\x00") + " ")
		default:
			fmt.Fprintf(b, "%d ", val)
		}
	}
}
