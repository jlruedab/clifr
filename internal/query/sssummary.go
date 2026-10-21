package query

import (
	"database/sql"
	"fmt"
	"io"

	"clifr/internal/store"
)

// SSSummary is ss -s: the socket counts of /proc/net/sockstat and sockstat6
// at the system sample at or before t, and the established connections
// (TCP's CurrEstab: ESTABLISHED and CLOSE-WAIT): recorded with the protocol
// counters, else counted at t from the TCP records.
type SSSummary struct {
	SampleTS                         int64                       `json:"sample_ts_ms"`
	Total                            int64                       `json:"total"`
	TCP, Estab, Closed, Orphaned, TW int64                       `json:"-"`
	Raw4, Raw6, UDP4, UDP6           int64                       `json:"-"`
	TCP4, TCP6, Frag4, Frag6         int64                       `json:"-"`
	TCPLine                          map[string]int64            `json:"tcp"`
	Transport                        map[string]map[string]int64 `json:"transport"`
}

// SSSummaryAt reads the summary; recordings before schema 3 have no sockstat.
func SSSummaryAt(db *store.DB, t int64) (SSSummary, error) {
	var s SSSummary
	var used sql.NullInt64
	err := db.QueryRow(`SELECT ts, sock_used, tcp_inuse, tcp_orphan, tcp_tw, tcp_alloc, udp_inuse, raw_inuse, frag_inuse,
		tcp6_inuse, udp6_inuse, raw6_inuse, frag6_inuse FROM sys_samples WHERE ts = (SELECT MAX(ts) FROM sys_samples WHERE ts <= ?)`, t).
		Scan(&s.SampleTS, &used, &s.TCP4, &s.Orphaned, &s.TW, &s.TCP, &s.UDP4, &s.Raw4, &s.Frag4, &s.TCP6, &s.UDP6, &s.Raw6, &s.Frag6)
	switch {
	case err == sql.ErrNoRows:
		return s, fmt.Errorf("no system counters recorded at or before %s", FormatMS(t))
	case err != nil && !used.Valid:
		return s, fmt.Errorf("socket counts (/proc/net/sockstat) are not in this recording (recorded since schema 3)")
	case err != nil:
		return s, err
	}
	s.Total = used.Int64
	// iproute2 reads estab from /proc/net/snmp (Tcp CurrEstab), recorded
	// since schema 4; before, it is counted from the TCP records.
	if c, _, err := netCountersAt(db, t); err == nil {
		if v, ok := c["TcpCurrEstab"]; ok {
			s.Estab = v.Value
			return s.finish(), nil
		}
	}
	var rows []SSRow
	if TCPFromEvents(db) {
		rows, _, err = ConnsAt(db, t, "tcp", SockFilter{})
	} else {
		var snap int64
		if snap, err = SnapshotAt(db, t, false); err == nil {
			rows, err = SocketsAt(db, snap, "tcp", SockFilter{})
		}
	}
	if err != nil {
		return s, err
	}
	for _, r := range rows {
		if r.State == "ESTAB" || r.State == "CLOSE-WAIT" {
			s.Estab++
		}
	}
	return s.finish(), nil
}

// finish computes the derived counts and the JSON maps.
func (s SSSummary) finish() SSSummary {
	// iproute2: TCP is alloc + tw; closed is alloc minus the hashed (inuse)
	// sockets that are not in time-wait.
	s.Closed = s.TCP - (s.TCP4 + s.TCP6 - s.TW)
	s.TCPLine = map[string]int64{"total": s.TCP + s.TW, "estab": s.Estab, "closed": s.Closed, "orphaned": s.Orphaned, "timewait": s.TW}
	s.Transport = map[string]map[string]int64{}
	for _, l := range s.lines() {
		s.Transport[l.name] = map[string]int64{"total": l.v4 + l.v6, "ip": l.v4, "ipv6": l.v6}
	}
	return s
}

type ssLine struct {
	name   string
	v4, v6 int64
}

func (s SSSummary) lines() []ssLine {
	return []ssLine{{"RAW", s.Raw4, s.Raw6}, {"UDP", s.UDP4, s.UDP6}, {"TCP", s.TCP4, s.TCP6},
		{"INET", s.Raw4 + s.UDP4 + s.TCP4, s.Raw6 + s.UDP6 + s.TCP6}, {"FRAG", s.Frag4, s.Frag6}}
}

// PrintSSSummary prints s like iproute2's ss -s.
func PrintSSSummary(w io.Writer, s SSSummary) {
	fmt.Fprintf(w, "Total: %d\n", s.Total)
	fmt.Fprintf(w, "TCP:   %d (estab %d, closed %d, orphaned %d, timewait %d)\n\n", s.TCP+s.TW, s.Estab, s.Closed, s.Orphaned, s.TW)
	fmt.Fprintf(w, "Transport Total     IP        IPv6\n")
	for _, l := range s.lines() {
		fmt.Fprintf(w, "%s\t  %-9d %-9d %-9d\n", l.name, l.v4+l.v6, l.v4, l.v6)
	}
	fmt.Fprintln(w)
}
