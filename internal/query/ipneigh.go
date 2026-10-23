package query

import (
	"database/sql"
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// NeighsAt returns the neighbour table at t in the kernel's dump order: the
// last whole copy at or before t with the entries that changed after it.
// ok is false when it was not recorded (before schema 9).
func NeighsAt(db *store.DB, t int64) (out []store.NeighRow, ok bool, err error) {
	var whole sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM neighs WHERE whole = 1 AND ts <= ?`, t).Scan(&whole); err != nil || !whole.Valid {
		return nil, false, err
	}
	rows, err := db.Query(`SELECT ts, pos, whole, family, ifindex, state, flags, type, ext_flags, dst, lladdr, has_lladdr,
			probes, protocol, confirmed_ms, used_ms, updated_ms, refcnt
		FROM neighs WHERE ts >= ? AND ts <= ? AND (whole = 0 OR ts = ?) ORDER BY ts, pos`, whole.Int64, t, whole.Int64)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	at := map[string]int{}
	for rows.Next() {
		var n store.NeighRow
		var w, has int
		if err := rows.Scan(&n.TS, &n.Pos, &w, &n.Family, &n.Index, &n.State, &n.Flags, &n.Type, &n.ExtFlags, &n.Dst,
			&n.LLAddr, &has, &n.Probes, &n.Protocol, &n.ConfirmedMS, &n.UsedMS, &n.UpdatedMS, &n.RefCnt); err != nil {
			return nil, false, err
		}
		if n.Pos < 0 {
			continue
		}
		n.Whole, n.HasLLAddr = w == 1, has == 1
		key := fmt.Sprintf("%d/%d/%x", n.Family, n.Index, n.Dst)
		if n.Whole {
			at[key] = len(out)
			out = append(out, n)
		} else if i, found := at[key]; found {
			out[i] = n
		}
	}
	return out, true, rows.Err()
}

// IPNeighOptions: -s (the cache timers and probes), -4/-6 (Family 2 or
// 10), dev NAME, and iproute2 5.15's layout (Ubuntu 22.04: a space before
// each field instead of after it).
type IPNeighOptions struct {
	Stats  bool
	Family int
	Dev    string
	Old    bool
}

// NUD_* states in ip's order, and the flags it prints.
var nudNames = []struct {
	bit  int
	name string
}{{0x01, "INCOMPLETE"}, {0x02, "REACHABLE"}, {0x04, "STALE"}, {0x08, "DELAY"}, {0x10, "PROBE"}, {0x20, "FAILED"},
	{0x40, "NOARP"}, {0x80, "PERMANENT"}}

// PrintIPNeigh prints the entries as ip [-s] neigh show does: every state
// but NOARP (and none), ages in seconds at t.
func PrintIPNeigh(w io.Writer, ns []store.NeighRow, links []store.LinkRow, o IPNeighOptions, t int64) {
	name, typ := map[int]string{}, map[int]int{}
	for _, l := range links {
		name[l.Index], typ[l.Index] = l.Name, l.Type
	}
	const ntfProxy, ntfExtLearned, ntfOffloaded, ntfRouter = 0x08, 0x10, 0x20, 0x80
	const extManaged, extValidated = 0x01, 0x02
	for _, n := range ns {
		if o.Family != 0 && n.Family != o.Family || o.Dev != "" && name[n.Index] != o.Dev {
			continue
		}
		if n.State&(0xff&^0x40) == 0 && n.Flags&(ntfProxy|ntfExtLearned) == 0 {
			continue
		}
		var b strings.Builder
		// field writes a field as the version separates them: 6.x ends each
		// in a space, 5.15 starts the later ones with one.
		field := func(s string) {
			if o.Old {
				b.WriteString(" " + s)
			} else {
				b.WriteString(s + " ")
			}
		}
		if n.Dst != nil {
			b.WriteString(ipString(n.Family, n.Dst) + " ")
		}
		if o.Dev == "" && n.Index != 0 {
			b.WriteString("dev " + name[n.Index] + " ")
		}
		if n.HasLLAddr {
			b.WriteString("lladdr " + llAddr(n.LLAddr, typ[n.Index]))
			if !o.Old {
				b.WriteByte(' ')
			}
		}
		if n.Flags&ntfRouter != 0 {
			field("router")
		}
		if n.Flags&ntfProxy != 0 {
			field("proxy")
		}
		if n.ExtFlags&extManaged != 0 && !o.Old {
			field("managed")
		}
		if n.Flags&ntfExtLearned != 0 {
			b.WriteString(map[bool]string{true: " extern_learn ", false: "extern_learn "}[o.Old])
		}
		if n.Flags&ntfOffloaded != 0 {
			field("offload")
		}
		if n.ExtFlags&extValidated != 0 && !o.Old {
			field("extern_valid")
		}
		if o.Stats {
			if n.UsedMS != 0 || n.ConfirmedMS != 0 || n.UpdatedMS != 0 {
				if n.RefCnt != 0 {
					b.WriteString(" ref " + strconv.FormatInt(n.RefCnt, 10))
				}
				age := func(at int64) string { return strconv.FormatInt(max(t-at, 0)/1000, 10) }
				b.WriteString(" used " + age(n.UsedMS) + "/" + age(n.ConfirmedMS) + "/" + age(n.UpdatedMS))
			}
			if n.Probes >= 0 {
				field("probes " + strconv.FormatInt(n.Probes, 10))
			}
		}
		for _, s := range nudNames {
			if n.State&s.bit != 0 {
				field(s.name)
			}
		}
		if n.Protocol > 0 {
			b.WriteString(map[bool]string{true: " proto ", false: "proto "}[o.Old] + protoName(int(n.Protocol)) + " ")
		}
		fmt.Fprintln(w, b.String())
	}
}

// Netns is a named network namespace (/run/netns) and the id this
// namespace gives it (-1: none).
type Netns struct {
	Name string `json:"name"`
	ID   int    `json:"id"`
}

// NetnsAt lists the named network namespaces at t in /run/netns's order.
func NetnsAt(db *store.DB, t int64) ([]Netns, error) {
	lines, _, ok, err := FileAt(db, "netns", t)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("ip netns: not recorded at %s (recorded since schema 9)", FormatMS(t))
	}
	var out []Netns
	for _, l := range lines {
		i := strings.LastIndexByte(l, ' ')
		if i < 0 {
			continue
		}
		id, _ := strconv.Atoi(l[i+1:])
		out = append(out, Netns{Name: l[:i], ID: id})
	}
	return out, nil
}

// PrintIPNetns prints ip netns [list].
func PrintIPNetns(w io.Writer, ns []Netns) {
	for _, n := range ns {
		if n.ID >= 0 {
			fmt.Fprintf(w, "%s (id: %d)\n", n.Name, n.ID)
		} else {
			fmt.Fprintln(w, n.Name)
		}
	}
}
