package query

import (
	"database/sql"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"

	"clifr/internal/store"
)

// LinksAt is every network interface at the system sample at or before t
// (each interface's newest row in the 5 minutes that hold a full set; those
// gone left out), by ifindex, and that sample's time.
func LinksAt(db *store.DB, t int64) ([]store.LinkRow, int64, error) {
	var ts sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM links WHERE ts <= ?`, t).Scan(&ts); err != nil || !ts.Valid {
		return nil, 0, fmt.Errorf("network interfaces are not recorded at or before %s (recorded since 2026-10-21)", FormatMS(t))
	}
	rows, err := db.Query(`SELECT ts, ifindex, type, gone, flags, xdp, has_stats, name, qdisc, alias, kind, slave_kind,
		phys_port_name, parent_bus, parent_dev, alt_names, mtu, master, link, link_netnsid, operstate, linkmode, grp,
		txqlen, promiscuity, allmulti, min_mtu, max_mtu, netns_immutable, addr_gen_mode, num_tx_queues, num_rx_queues,
		gso_max_size, gso_max_segs, tso_max_size, tso_max_segs, gro_max_size, gso_ipv4_max_size, gro_ipv4_max_size,
		proto_down, carrier_changes, address, broadcast, perm_address, phys_port_id, phys_switch_id, info_data, slave_data,
		rx_packets, tx_packets, rx_bytes, tx_bytes, rx_errors, tx_errors, rx_dropped, tx_dropped, multicast, collisions,
		rx_length_errors, rx_over_errors, rx_crc_errors, rx_frame_errors, rx_fifo_errors, rx_missed_errors,
		tx_aborted_errors, tx_carrier_errors, tx_fifo_errors, tx_heartbeat_errors, tx_window_errors, rx_compressed,
		tx_compressed, rx_nohandler, rx_otherhost_dropped
		FROM links WHERE ts <= ? AND ts >= ? ORDER BY ts`, ts.Int64, ts.Int64-store.NetCountersFullMS-60_000)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	latest := map[int]store.LinkRow{}
	for rows.Next() {
		var l store.LinkRow
		var gone, xdp, hasStats int
		dst := []any{&l.TS, &l.Index, &l.Type, &gone, &l.Flags, &xdp, &hasStats, &l.Name, &l.Qdisc, &l.Alias, &l.Kind,
			&l.SlaveKind, &l.PhysPortName, &l.ParentBus, &l.ParentDev, &l.AltNames, &l.MTU, &l.Master, &l.Link,
			&l.LinkNetnsID, &l.OperState, &l.LinkMode, &l.Group, &l.TxQLen, &l.Promiscuity, &l.Allmulti, &l.MinMTU,
			&l.MaxMTU, &l.NetnsImmutable, &l.AddrGenMode, &l.NumTxQueues, &l.NumRxQueues, &l.GSOMaxSize, &l.GSOMaxSegs,
			&l.TSOMaxSize, &l.TSOMaxSegs, &l.GROMaxSize, &l.GSOIPv4MaxSize, &l.GROIPv4MaxSize, &l.ProtoDown,
			&l.CarrierChanges, &l.Address, &l.Broadcast, &l.PermAddress, &l.PhysPortID, &l.PhysSwitchID, &l.InfoData,
			&l.SlaveData}
		for i := range l.Stats {
			dst = append(dst, &l.Stats[i])
		}
		if err := rows.Scan(dst...); err != nil {
			return nil, 0, err
		}
		l.Gone, l.XDP, l.HasStats = gone == 1, xdp == 1, hasStats == 1
		latest[l.Index] = l
	}
	var out []store.LinkRow
	for _, l := range latest {
		if !l.Gone {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, ts.Int64, rows.Err()
}

// IPLinkOptions: ip's -s (count), -d, and the device asked for ("" all).
// Addr: the link part of ip address, which leaves out what only ip link
// shows (mode, addrgenmode, statistics).
type IPLinkOptions struct {
	Stats   int
	Details bool
	Dev     string
	Addr    bool
	family  bool                           // ip -4/-6 address: no link/ line unless -d
	inet6   bool                           // ip -6 address: the kernel's IPv6 view of a link (name, flags, mtu, state, address)
	after   func(io.Writer, store.LinkRow) // ip address: the link's addresses
}

// IFF_* flags in the order iproute2 prints them.
var linkFlags = []struct {
	bit  int64
	name string
}{{0x8, "LOOPBACK"}, {0x2, "BROADCAST"}, {0x10, "POINTOPOINT"}, {0x1000, "MULTICAST"}, {0x80, "NOARP"},
	{0x200, "ALLMULTI"}, {0x100, "PROMISC"}, {0x400, "MASTER"}, {0x800, "SLAVE"}, {0x4, "DEBUG"},
	{0x8000, "DYNAMIC"}, {0x4000, "AUTOMEDIA"}, {0x2000, "PORTSEL"}, {0x20, "NOTRAILERS"}, {0x1, "UP"},
	{0x10000, "LOWER_UP"}, {0x20000, "DORMANT"}, {0x40000, "ECHO"}}

const (
	iffUp      = 0x1
	iffRunning = 0x40
	iffPtP     = 0x10
)

var operStates = []string{"UNKNOWN", "NOTPRESENT", "DOWN", "LOWERLAYERDOWN", "TESTING", "DORMANT", "UP"}

// arphrd maps link types to ip's names (ll_types.c); others print as [N].
var arphrd = map[int]string{0: "netrom", 1: "ether", 2: "eether", 3: "ax25", 4: "pronet", 5: "chaos", 6: "ieee802",
	7: "arcnet", 8: "atalk", 15: "dlci", 19: "atm", 23: "metricom", 24: "ieee1394", 32: "infiniband", 256: "slip",
	257: "cslip", 258: "slip6", 259: "cslip6", 260: "rsrvd", 264: "adapt", 270: "rose", 271: "x25", 272: "hwx25",
	280: "can", 512: "ppp", 513: "hdlc", 516: "lapb", 517: "ddcmp", 518: "rawhdlc", 768: "ipip", 769: "tunnel6",
	770: "frad", 771: "skip", 772: "loopback", 773: "ltalk", 774: "fddi", 775: "bif", 776: "sit", 777: "ip/ddp",
	778: "gre", 779: "pimreg", 780: "hippi", 781: "ash", 782: "econet", 783: "irda", 784: "fcpp", 785: "fcal",
	786: "fcpl", 787: "fcfb0", 800: "tr", 801: "ieee802.11", 802: "ieee802.11/prism", 803: "ieee802.11/radiotap",
	804: "ieee802.15.4", 805: "ieee802.15.4/monitor", 820: "phonet", 821: "phonet_pipe", 822: "caif", 823: "gre6",
	824: "netlink", 825: "6lowpan", 0xfffe: "none", 0xffff: "void"}

// llAddr formats a link-layer address as ip does: IPv4 or IPv6 for tunnels,
// else colon-separated hex.
func llAddr(b []byte, typ int) string {
	if len(b) == 4 && (typ == 768 || typ == 776 || typ == 778) {
		return netip.AddrFrom4([4]byte(b)).String()
	}
	if len(b) == 16 && (typ == 769 || typ == 823) {
		return netip.AddrFrom16([16]byte(b)).String()
	}
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02x", c)
	}
	return strings.Join(parts, ":")
}

// PrintIPLink prints the links like iproute2 6.19's ip [-s [-s]] [-d] link.
// The parameters of each interface type (bridge, bond, vlan, ...) are not
// reconstructed: -d prints the type's name only.
func PrintIPLink(w io.Writer, links []store.LinkRow, o IPLinkOptions) {
	byIndex := map[int64]store.LinkRow{}
	for _, l := range links {
		byIndex[int64(l.Index)] = l
	}
	for _, l := range links {
		if o.Dev != "" && l.Name != o.Dev {
			continue
		}
		var b strings.Builder
		name, mdown := l.Name, false
		if l.Link >= 0 {
			switch p, ok := byIndex[l.Link]; {
			case l.Link == 0:
				name += "@NONE"
			case l.LinkNetnsID >= 0 || !ok:
				name += fmt.Sprintf("@if%d", l.Link)
			default:
				name += "@" + p.Name
				mdown = p.Flags&iffUp == 0
			}
		}
		fmt.Fprintf(&b, "%d: %s: ", l.Index, name)
		flags := l.Flags
		var fl []string
		if flags&iffUp != 0 && flags&iffRunning == 0 {
			fl = append(fl, "NO-CARRIER")
		}
		flags &^= iffRunning
		for _, f := range linkFlags {
			if flags&f.bit != 0 {
				flags &^= f.bit
				fl = append(fl, f.name)
			}
		}
		if flags != 0 {
			fl = append(fl, fmt.Sprintf("%x", flags))
		}
		s := strings.Join(fl, ",")
		if mdown {
			s += ",M-DOWN"
		}
		fmt.Fprintf(&b, "<%s> ", s)
		if l.MTU >= 0 {
			fmt.Fprintf(&b, "mtu %d ", l.MTU)
		}
		if o.inet6 {
			// The AF_INET6 link dump has no qdisc, master, mode, group, queue
			// length (ip asks with an ioctl) or broadcast address.
			if l.OperState >= 0 && int(l.OperState) < len(operStates) {
				fmt.Fprintf(&b, "state %s ", operStates[l.OperState])
			}
			if l.TxQLen > 0 {
				fmt.Fprintf(&b, "qlen %d", l.TxQLen)
			}
			if o.Details {
				t, ok := arphrd[l.Type]
				if !ok {
					t = fmt.Sprintf("[%d]", l.Type)
				}
				fmt.Fprintf(&b, "\n    link/%s ", t)
				if len(l.Address) > 0 {
					b.WriteString(llAddr(l.Address, l.Type))
				}
			}
			b.WriteString("\n")
			io.WriteString(w, b.String())
			if o.after != nil {
				o.after(w, l)
			}
			continue
		}
		if l.Qdisc != "" {
			fmt.Fprintf(&b, "qdisc %s ", l.Qdisc)
		}
		if l.Master >= 0 {
			m := fmt.Sprintf("if%d", l.Master)
			if p, ok := byIndex[l.Master]; ok {
				m = p.Name
			}
			fmt.Fprintf(&b, "master %s ", m)
		}
		if l.OperState >= 0 {
			if int(l.OperState) < len(operStates) {
				fmt.Fprintf(&b, "state %s ", operStates[l.OperState])
			} else {
				fmt.Fprintf(&b, "state %#x ", l.OperState)
			}
		}
		if l.LinkMode >= 0 && !o.Addr {
			if m := []string{"DEFAULT", "DORMANT"}; int(l.LinkMode) < len(m) {
				fmt.Fprintf(&b, "mode %s ", m[l.LinkMode])
			} else {
				fmt.Fprintf(&b, "mode %d ", l.LinkMode)
			}
		}
		if l.Group >= 0 {
			g := fmt.Sprint(l.Group)
			if l.Group == 0 {
				g = "default"
			}
			fmt.Fprintf(&b, "group %s ", g)
		}
		if l.TxQLen > 0 {
			fmt.Fprintf(&b, "qlen %d", l.TxQLen)
		}
		if !o.family || o.Details {
			t, ok := arphrd[l.Type]
			if !ok {
				t = fmt.Sprintf("[%d]", l.Type)
			}
			fmt.Fprintf(&b, "\n    link/%s ", t)
			if len(l.Address) > 0 {
				b.WriteString(llAddr(l.Address, l.Type))
			}
			if len(l.Broadcast) > 0 {
				if l.Flags&iffPtP != 0 {
					b.WriteString(" peer ")
				} else {
					b.WriteString(" brd ")
				}
				b.WriteString(llAddr(l.Broadcast, l.Type))
			}
			if len(l.PermAddress) > 0 && string(l.PermAddress) != string(l.Address) {
				b.WriteString(" permaddr " + llAddr(l.PermAddress, l.Type))
			}
		}
		if l.LinkNetnsID >= 0 {
			fmt.Fprintf(&b, " link-netnsid %d", l.LinkNetnsID)
		}
		if l.ProtoDown == 1 {
			b.WriteString(" protodown on ")
		}
		if o.Details {
			opt := func(v int64, f string) {
				if v >= 0 {
					fmt.Fprintf(&b, f, v)
				}
			}
			opt(l.Promiscuity, " promiscuity %d ")
			opt(l.Allmulti, "allmulti %d ")
			opt(l.MinMTU, "minmtu %d ")
			opt(l.MaxMTU, "maxmtu %d ")
			if l.NetnsImmutable == 1 {
				b.WriteString("netns-immutable ")
			}
			if l.Kind != "" {
				fmt.Fprintf(&b, "\n    %s ", l.Kind)
			}
			if l.SlaveKind != "" {
				fmt.Fprintf(&b, "\n    %s_slave ", l.SlaveKind)
			}
			if l.AddrGenMode >= 0 && !o.Addr {
				modes := []string{"eui64", "none", "stable_secret", "random"}
				if int(l.AddrGenMode) < len(modes) {
					fmt.Fprintf(&b, "addrgenmode %s ", modes[l.AddrGenMode])
				} else {
					fmt.Fprintf(&b, "addrgenmode %#.2x ", l.AddrGenMode)
				}
			}
			opt(l.NumTxQueues, "numtxqueues %d ")
			opt(l.NumRxQueues, "numrxqueues %d ")
			opt(l.GSOMaxSize, "gso_max_size %d ")
			opt(l.GSOMaxSegs, "gso_max_segs %d ")
			opt(l.TSOMaxSize, "tso_max_size %d ")
			opt(l.TSOMaxSegs, "tso_max_segs %d ")
			opt(l.GROMaxSize, "gro_max_size %d ")
			opt(l.GSOIPv4MaxSize, "gso_ipv4_max_size %d ")
			opt(l.GROIPv4MaxSize, "gro_ipv4_max_size %d ")
			if l.PhysPortName != "" {
				fmt.Fprintf(&b, "portname %s ", l.PhysPortName)
			}
			if len(l.PhysPortID) > 0 {
				fmt.Fprintf(&b, "portid %x ", l.PhysPortID)
			}
			if len(l.PhysSwitchID) > 0 {
				fmt.Fprintf(&b, "switchid %x ", l.PhysSwitchID)
			}
			if l.ParentBus != "" {
				fmt.Fprintf(&b, "parentbus %s ", l.ParentBus)
			}
			if l.ParentDev != "" {
				fmt.Fprintf(&b, "parentdev %s ", l.ParentDev)
			}
		}
		if l.Alias != "" && (!o.Addr || o.Details) {
			fmt.Fprintf(&b, "\n    alias %s", l.Alias)
		}
		if o.Stats > 0 && l.HasStats && !o.Addr {
			b.WriteString("\n")
			printLinkStats(&b, l.Stats, l.CarrierChanges, o.Stats)
		}
		if l.AltNames != "" {
			for _, a := range strings.Split(l.AltNames, "\n") {
				fmt.Fprintf(&b, "\n    altname %s", a)
			}
		}
		b.WriteString("\n")
		io.WriteString(w, b.String())
		if o.after != nil {
			o.after(w, l)
		}
	}
}

// Indexes into store.LinkRow.Stats (struct rtnl_link_stats64).
const (
	stRxPackets = iota
	stTxPackets
	stRxBytes
	stTxBytes
	stRxErrors
	stTxErrors
	stRxDropped
	stTxDropped
	stMulticast
	stCollisions
	stRxLength
	stRxOver
	stRxCRC
	stRxFrame
	stRxFIFO
	stRxMissed
	stTxAborted
	stTxCarrier
	stTxFIFO
	stTxHeartbeat
	stTxWindow
	stRxCompressed
	stTxCompressed
	stRxNohandler
	stRxOtherhost
)

// printLinkStats is iproute2's print_stats64 in text: columns as wide as
// their widest number, at least as wide as their heading.
func printLinkStats(b *strings.Builder, s [25]int64, carrier int64, level int) {
	cols := []int{len("*X errors:"), len("packets"), len("errors"), len("dropped"), len("heartbt"), len("overrun"), len("compressed"), len("otherhost")}
	size := func(vals ...int64) {
		for i, v := range vals {
			if n := len(fmt.Sprint(uint64(v))); n > cols[i] {
				cols[i] = n
			}
		}
	}
	size(s[stRxBytes], s[stRxPackets], s[stRxErrors], s[stRxDropped], s[stRxMissed], s[stMulticast], s[stRxCompressed], 0)
	if level > 1 {
		size(0, s[stRxLength], s[stRxCRC], s[stRxFrame], s[stRxFIFO], s[stRxOver], s[stRxNohandler], s[stRxOtherhost])
	}
	size(s[stTxBytes], s[stTxPackets], s[stTxErrors], s[stTxDropped], s[stTxCarrier], s[stCollisions], s[stTxCompressed], 0)
	if level > 1 {
		cc := max(carrier, 0)
		size(0, 0, s[stTxAborted], s[stTxFIFO], s[stTxWindow], s[stTxHeartbeat], cc, 0)
	}
	num := func(width int, v int64) { fmt.Fprintf(b, "%*d ", width, uint64(v)) }
	comp := func(v int64) string {
		if v != 0 {
			return "compressed"
		}
		return ""
	}
	fmt.Fprintf(b, "    RX: %*s %*s %*s %*s %*s %*s %*s\n", cols[0]-4, "bytes", cols[1], "packets", cols[2], "errors",
		cols[3], "dropped", cols[4], "missed", cols[5], "mcast", cols[6], comp(s[stRxCompressed]))
	b.WriteString("    ")
	for i, k := range []int{stRxBytes, stRxPackets, stRxErrors, stRxDropped, stRxMissed, stMulticast} {
		num(cols[i], s[k])
	}
	if s[stRxCompressed] != 0 {
		num(cols[6], s[stRxCompressed])
	}
	if level > 1 {
		nh, oh := 0, 0
		nhs, ohs := "", ""
		if s[stRxNohandler] != 0 {
			nh, nhs = cols[6]+1, " nohandler"
		}
		if s[stRxOtherhost] != 0 {
			oh, ohs = cols[7]+1, " otherhost"
		}
		fmt.Fprintf(b, "\n    RX errors:%*s %*s %*s %*s %*s %*s%*s%*s\n", cols[0]-10, "", cols[1], "length", cols[2], "crc",
			cols[3], "frame", cols[4], "fifo", cols[5], "overrun", nh, nhs, oh, ohs)
		fmt.Fprintf(b, "%*s", cols[0]+5, "")
		for i, k := range []int{stRxLength, stRxCRC, stRxFrame, stRxFIFO, stRxOver} {
			num(cols[i+1], s[k])
		}
		if s[stRxNohandler] != 0 {
			num(cols[6], s[stRxNohandler])
		}
		if s[stRxOtherhost] != 0 {
			num(cols[7], s[stRxOtherhost])
		}
	}
	fmt.Fprintf(b, "\n    TX: %*s %*s %*s %*s %*s %*s %*s\n", cols[0]-4, "bytes", cols[1], "packets", cols[2], "errors",
		cols[3], "dropped", cols[4], "carrier", cols[5], "collsns", cols[6], comp(s[stTxCompressed]))
	b.WriteString("    ")
	for i, k := range []int{stTxBytes, stTxPackets, stTxErrors, stTxDropped, stTxCarrier, stCollisions} {
		num(cols[i], s[k])
	}
	if s[stTxCompressed] != 0 {
		num(cols[6], s[stTxCompressed])
	}
	if level > 1 {
		tr := ""
		if carrier >= 0 {
			tr = "transns"
		}
		fmt.Fprintf(b, "\n    TX errors:%*s %*s %*s %*s %*s %*s\n", cols[0]-10, "", cols[1], "aborted", cols[2], "fifo",
			cols[3], "window", cols[4], "heartbt", cols[5], tr)
		fmt.Fprintf(b, "%*s", cols[0]+5, "")
		for i, k := range []int{stTxAborted, stTxFIFO, stTxWindow, stTxHeartbeat} {
			num(cols[i+1], s[k])
		}
		if carrier >= 0 {
			num(cols[5], carrier)
		}
	}
}
