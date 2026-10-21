package query

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"clifr/internal/store"
)

const lifetimeForever = 0xffffffff

// AddrsAt is every interface address at t: the snapshot at or before t with
// the changes after it applied in order. Lifetimes are what was left at t.
func AddrsAt(db *store.DB, t int64) ([]store.AddrRow, error) {
	var snap sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM addrs WHERE action = 'present' AND ts <= ?`, t).Scan(&snap); err != nil || !snap.Valid {
		return nil, fmt.Errorf("interface addresses are not recorded at or before %s (recorded since 2026-10-21)", FormatMS(t))
	}
	rows, err := db.Query(`SELECT ts, action, seq, family, prefixlen, scope, ifindex, flags, local, address, broadcast,
		anycast, multicast, label, metric, proto, valid_lft, preferred_lft FROM addrs
		WHERE (ts = ?1 AND action = 'present') OR (ts > ?1 AND ts <= ?2 AND action != 'present')
		ORDER BY ts, action = 'present' DESC, seq`, snap.Int64, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []store.AddrRow
	key := func(a *store.AddrRow) string {
		return fmt.Sprintf("%d/%d/%x/%d", a.Index, a.Family, a.Local, a.PrefixLen)
	}
	for rows.Next() {
		var a store.AddrRow
		if err := rows.Scan(&a.TS, &a.Action, &a.Seq, &a.Family, &a.PrefixLen, &a.Scope, &a.Index, &a.Flags, &a.Local,
			&a.Address, &a.Broadcast, &a.Anycast, &a.Multicast, &a.Label, &a.Metric, &a.Proto, &a.Valid, &a.Preferred); err != nil {
			return nil, err
		}
		i := -1
		for j := range list {
			if key(&list[j]) == key(&a) {
				i = j
			}
		}
		switch {
		case a.Action == "del" && i >= 0:
			list = append(list[:i], list[i+1:]...)
		case a.Action == "del":
		case i >= 0: // a change: in its place
			list[i] = a
		default:
			list = append(list, a)
		}
	}
	for i := range list {
		elapsed := (t - list[i].TS) / 1000
		for _, p := range []*int64{&list[i].Valid, &list[i].Preferred} {
			if *p >= 0 && *p != lifetimeForever {
				*p = max(*p-elapsed, 0)
			}
		}
	}
	return list, rows.Err()
}

// IPAddrOptions: ip address's -o, -d, -4/-6 and the device.
type IPAddrOptions struct {
	OneLine, Details bool
	Family           int // 0 all, 2 inet, 10 inet6
	Dev              string
}

// IFA_F_* in the order iproute2 prints them (temporary: secondary of IPv6).
var addrFlags = []struct {
	bit  int64
	name string
}{{0x01, "secondary"}, {0x01, "temporary"}, {0x02, "nodad"}, {0x04, "optimistic"}, {0x08, "dadfailed"},
	{0x10, "home"}, {0x20, "deprecated"}, {0x40, "tentative"}, {0x80, "permanent"}, {0x100, "mngtmpaddr"},
	{0x200, "noprefixroute"}, {0x400, "autojoin"}, {0x800, "stable-privacy"}}

func scopeName(s int) string {
	switch s {
	case 0:
		return "global"
	case 200:
		return "site"
	case 253:
		return "link"
	case 254:
		return "host"
	case 255:
		return "nowhere"
	}
	return fmt.Sprint(s)
}

func ipString(family int, b []byte) string {
	if a, ok := netip.AddrFromSlice(b); ok {
		if family == 2 {
			a = a.Unmap()
		}
		return a.String()
	}
	return hex.EncodeToString(b)
}

// printAddr is iproute2's print_addrinfo in text; nl is its line break
// ("\n", or "\\" with -o).
func printAddr(b *strings.Builder, a store.AddrRow, nl string) {
	fam := map[int]string{2: "inet", 10: "inet6"}[a.Family]
	if fam == "" {
		fmt.Fprintf(b, "    family %d ", a.Family)
	} else {
		fmt.Fprintf(b, "    %s ", fam)
	}
	if len(a.Local) > 0 {
		b.WriteString(ipString(a.Family, a.Local))
		if len(a.Address) > 0 && string(a.Address) != string(a.Local) {
			b.WriteString(" peer " + ipString(a.Family, a.Address))
		}
		fmt.Fprintf(b, "/%d ", a.PrefixLen)
		if a.Metric >= 0 {
			fmt.Fprintf(b, "metric %d ", a.Metric)
		}
	}
	if len(a.Broadcast) > 0 {
		fmt.Fprintf(b, "brd %s ", ipString(a.Family, a.Broadcast))
	}
	if len(a.Anycast) > 0 {
		fmt.Fprintf(b, "any %s ", ipString(a.Family, a.Anycast))
	}
	if len(a.Multicast) > 0 {
		fmt.Fprintf(b, "mcast %s ", ipString(a.Family, a.Multicast))
	}
	fmt.Fprintf(b, "scope %s ", scopeName(a.Scope))
	flags := a.Flags
	for _, f := range addrFlags {
		switch {
		case f.bit == 0x80:
			if flags&f.bit == 0 {
				b.WriteString("dynamic ")
			}
		case flags&f.bit != 0 && f.bit == 0x01 && a.Family == 10:
			b.WriteString("temporary ")
		case flags&f.bit != 0:
			b.WriteString(f.name + " ")
		}
		flags &^= f.bit
	}
	if flags != 0 {
		fmt.Fprintf(b, "flags %02x ", flags)
	}
	if a.Proto > 0 {
		names := []string{"unspec", "kernel_lo", "kernel_ra", "kernel_ll"}
		if int(a.Proto) < len(names) {
			fmt.Fprintf(b, "proto %s ", names[a.Proto])
		} else {
			fmt.Fprintf(b, "proto %d ", a.Proto)
		}
	}
	b.WriteString(a.Label)
	if a.Valid >= 0 {
		b.WriteString(nl + "       valid_lft ")
		if a.Valid == lifetimeForever {
			b.WriteString("forever")
		} else {
			fmt.Fprintf(b, "%dsec", a.Valid)
		}
		b.WriteString(" preferred_lft ")
		switch {
		case a.Preferred == lifetimeForever:
			b.WriteString("forever")
		case a.Flags&0x20 != 0: // deprecated: ip prints it signed
			fmt.Fprintf(b, "%dsec", int32(a.Preferred))
		default:
			fmt.Fprintf(b, "%dsec", a.Preferred)
		}
	}
	b.WriteString("\n")
}

// PrintIPAddr prints ip [-d] [-o] [-4|-6] address [show [dev NAME]] like
// iproute2: each link (as ip link shows it, without mode, addrgenmode and
// statistics) followed by its addresses, IPv4 before IPv6; with -o only the
// addresses, one line each. With -4 or -6, links without such an address
// are left out.
func PrintIPAddr(w io.Writer, links []store.LinkRow, addrs []store.AddrRow, o IPAddrOptions) {
	of := func(l store.LinkRow) []store.AddrRow {
		var out []store.AddrRow
		for _, fam := range []int{2, 10} {
			for _, a := range addrs {
				if a.Index == l.Index && a.Family == fam && (o.Family == 0 || o.Family == fam) {
					out = append(out, a)
				}
			}
		}
		return out
	}
	if o.OneLine {
		for _, l := range links {
			if o.Dev != "" && l.Name != o.Dev {
				continue
			}
			for _, a := range of(l) {
				var b strings.Builder
				fmt.Fprintf(&b, "%d: %s", l.Index, l.Name)
				printAddr(&b, a, "\\")
				io.WriteString(w, b.String())
			}
		}
		return
	}
	var keep []store.LinkRow
	for _, l := range links {
		if o.Family == 0 || len(of(l)) > 0 {
			keep = append(keep, l)
		}
	}
	PrintIPLink(w, keep, IPLinkOptions{Details: o.Details, Dev: o.Dev, Addr: true, family: o.Family != 0, inet6: o.Family == 10, after: func(w io.Writer, l store.LinkRow) {
		for _, a := range of(l) {
			var b strings.Builder
			printAddr(&b, a, "\n")
			io.WriteString(w, b.String())
		}
	}})
}
