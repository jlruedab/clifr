package query

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"clifr/internal/rtnl"
	"clifr/internal/store"
	"clifr/internal/testrec"
)

// rtmsg builds a route message: the header and attributes.
func rtmsg(family, dstLen byte, table, proto, scope, typ byte, flags uint32, attrs ...[]byte) []byte {
	m := []byte{family, dstLen, 0, 0, table, proto, scope, typ, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(m[8:], flags)
	for _, a := range attrs {
		m = append(m, a...)
	}
	return m
}

func rta(typ int, v []byte) []byte {
	b := make([]byte, 4, 4+len(v)+3)
	binary.NativeEndian.PutUint16(b, uint16(4+len(v)))
	binary.NativeEndian.PutUint16(b[2:], uint16(typ))
	b = append(b, v...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func u32b(v uint32) []byte { b := make([]byte, 4); binary.NativeEndian.PutUint32(b, v); return b }
func ipb(s string) []byte  { return netip.MustParseAddr(s).AsSlice() }

func TestIPRouteAndRule(t *testing.T) {
	base := int64(1_790_000_000_000)
	def := rtmsg(2, 0, 254, 16, 0, 1, 0, rta(rtnl.RTATable, u32b(254)), rta(rtnl.RTAPriority, u32b(600)),
		rta(rtnl.RTAGateway, ipb("192.168.1.1")), rta(rtnl.RTAOif, u32b(4)), rta(rtnl.RTAPrefsrc, ipb("192.168.1.12")))
	docker := rtmsg(2, 16, 254, 2, 253, 1, 0x10, rta(rtnl.RTATable, u32b(254)), rta(rtnl.RTADst, ipb("172.17.0.0")),
		rta(rtnl.RTAPrefsrc, ipb("172.17.0.1")), rta(rtnl.RTAOif, u32b(5)))
	loc := rtmsg(2, 32, 255, 2, 254, 2, 0, rta(rtnl.RTATable, u32b(255)), rta(rtnl.RTADst, ipb("127.0.0.1")),
		rta(rtnl.RTAPrefsrc, ipb("127.0.0.1")), rta(rtnl.RTAOif, u32b(1)))
	v6 := rtmsg(10, 64, 254, 9, 0, 1, 0, rta(rtnl.RTATable, u32b(254)), rta(rtnl.RTADst, ipb("fd30:7496:5b55:9900::")),
		rta(rtnl.RTAOif, u32b(4)), rta(rtnl.RTAPriority, u32b(600)), rta(rtnl.RTAPref, []byte{0}))
	newer := rtmsg(2, 16, 254, 3, 0, 1, 0, rta(rtnl.RTATable, u32b(254)), rta(rtnl.RTADst, ipb("10.77.0.0")),
		rta(rtnl.RTAGateway, ipb("192.168.1.1")), rta(rtnl.RTAOif, u32b(4)))
	row := func(ts int64, action string, seq int, m []byte) store.RoutingRow {
		return store.RoutingRow{TS: ts, Kind: "route", Action: action, Seq: seq, Family: int(m[0]), Key: rtnl.RouteKey(m), Msg: m}
	}
	db := testrec.Open(t, nil,
		&store.Batch{Sample: store.Sample{TS: base}, Routing: []store.RoutingRow{
			row(base, "present", 0, def), row(base, "present", 1, docker), row(base, "present", 2, loc), row(base, "present", 3, v6)}},
		&store.Batch{Sample: store.Sample{TS: base + 10_000}, Routing: []store.RoutingRow{
			row(base+2_000, "add", 1, newer), row(base+4_000, "del", 2, docker)}})
	names := map[int]string{1: "lo", 4: "wlp0s20f3", 5: "docker0"}
	ifname := func(i int) string { return names[i] }
	show := func(at int64, o IPRouteOptions) string {
		rows, err := RoutingAt(db, at, "route")
		if err != nil {
			t.Fatal(err)
		}
		var sb strings.Builder
		PrintIPRoute(&sb, rows, o, ifname, at)
		return sb.String()
	}
	if got, want := show(base+1_000, IPRouteOptions{Family: 2, Table: 254}),
		"default via 192.168.1.1 dev wlp0s20f3 proto dhcp src 192.168.1.12 metric 600 \n"+
			"172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown \n"; got != want {
		t.Errorf("ip route:\n%s\nwant\n%s", got, want)
	}
	if got, want := show(base+5_000, IPRouteOptions{}),
		"default via 192.168.1.1 dev wlp0s20f3 proto dhcp src 192.168.1.12 metric 600 \n"+
			"local 127.0.0.1 dev lo table local proto kernel scope host src 127.0.0.1 \n"+
			"fd30:7496:5b55:9900::/64 dev wlp0s20f3 proto ra metric 600 pref medium\n"+
			"10.77.0.0/16 via 192.168.1.1 dev wlp0s20f3 \n"; got != want {
		t.Errorf("ip route show table all, after the changes:\n%s\nwant\n%s", got, want)
	}

	rule := []byte{2, 0, 0, 0, 254, 0, 0, 1, 0, 0, 0, 0}
	rule = append(rule, rta(fraPriority, u32b(32766))...)
	var sb strings.Builder
	PrintIPRule(&sb, []store.RoutingRow{{Msg: rule}}, 2, false)
	if sb.String() != "32766:\tfrom all lookup main\n" {
		t.Errorf("ip rule: %q", sb.String())
	}
}
