package query

import (
	"database/sql"
	"fmt"
	"io"
	"slices"
	"strings"

	"clifr/internal/store"
)

// NstatRow is one counter as nstat prints it: the value (since boot with -a,
// otherwise the increase over the range) and its rate per second.
type NstatRow struct {
	Name  string  `json:"name"`
	Value int64   `json:"value"`
	Rate  float64 `json:"rate"`
	pos   int
}

// nstatSkip are the values nstat leaves out: settings and gauges, not
// counters (iproute2's useless_numbers).
var nstatSkip = map[string]bool{"IpForwarding": true, "IpDefaultTTL": true, "TcpRtoAlgorithm": true,
	"TcpRtoMin": true, "TcpRtoMax": true, "TcpMaxConn": true, "TcpCurrEstab": true}

// nstatGroup orders the counters as nstat reads its files: /proc/net/snmp,
// then snmp6, then netstat (clifrd records snmp, netstat, snmp6).
func nstatGroup(name string) int {
	for _, p := range []string{"Ip6", "Icmp6", "Udp6", "UdpLite6"} {
		if strings.HasPrefix(name, p) {
			return 1
		}
	}
	if i := strings.Index(name, "Ext"); i > 0 && i < 8 { // TcpExt, IpExt, MPTcpExt, TlsExt...
		return 2
	}
	return 0
}

// netCountersAt is every protocol counter at the latest system sample at or
// before t (the newest row of each in the 5 minutes that hold a full set),
// and that sample's time.
func netCountersAt(db *store.DB, t int64) (map[string]NstatRow, int64, error) {
	var ts sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(ts) FROM net_counters WHERE ts <= ?`, t).Scan(&ts); err != nil || !ts.Valid {
		return nil, 0, fmt.Errorf("protocol counters (/proc/net/snmp) are not recorded at or before %s (recorded since 2026-10-21)", FormatMS(t))
	}
	rows, err := db.Query(`SELECT name, arg_max(value, ts), arg_max(pos, ts) FROM net_counters
		WHERE ts <= ? AND ts >= ? GROUP BY name`, ts.Int64, ts.Int64-store.NetCountersFullMS-60_000)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := map[string]NstatRow{}
	for rows.Next() {
		var r NstatRow
		if err := rows.Scan(&r.Name, &r.Value, &r.pos); err != nil {
			return nil, 0, err
		}
		out[r.Name] = r
	}
	return out, ts.Int64, rows.Err()
}

// Nstat reconstructs nstat: with w a moment, the values since boot (nstat
// -a); over a range, the increase from its start to its end and the rate
// per second. zeros: -z, keep the counters that are 0.
func Nstat(db *store.DB, w Window, zeros bool) (rows []NstatRow, from, to int64, err error) {
	end := w.At
	if w.IsRange() {
		end = w.To
	}
	cur, to, err := netCountersAt(db, end)
	if err != nil {
		return nil, 0, 0, err
	}
	var prev map[string]NstatRow
	if w.IsRange() {
		if prev, from, err = netCountersAt(db, w.From); err != nil {
			return nil, 0, 0, err
		}
	}
	secs := float64(to-from) / 1000
	for name, r := range cur {
		if nstatSkip[name] {
			continue
		}
		if prev != nil {
			p := prev[name]
			r.Value -= p.Value
			if r.Value < 0 { // a reboot in between: counted from 0
				r.Value = cur[name].Value
			}
			if secs > 0 {
				r.Rate = float64(r.Value) / secs
			}
		}
		if r.Value == 0 && !zeros {
			continue
		}
		rows = append(rows, r)
	}
	slices.SortFunc(rows, func(a, b NstatRow) int {
		if ga, gb := nstatGroup(a.Name), nstatGroup(b.Name); ga != gb {
			return ga - gb
		}
		return a.pos - b.pos
	})
	return rows, from, to, nil
}

// PrintNstat prints the rows like iproute2's nstat.
func PrintNstat(w io.Writer, rows []NstatRow) {
	fmt.Fprintln(w, "#kernel")
	for _, r := range rows {
		fmt.Fprintf(w, "%-32s%-16d%6.1f\n", r.Name, r.Value, r.Rate)
	}
}
