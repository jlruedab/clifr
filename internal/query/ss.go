package query

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/sockdiag"
	"clifr/internal/store"
)

// SockFilter is a subset of the ss filter language: conditions on dst, src,
// dport and sport joined with "and".
type SockFilter struct {
	conds []sockCond
	// NetNS: the network namespace shown (0: the host's, as the real tools
	// on the host; ss -N picks another). Applied in the queries.
	NetNS uint32
}

type sockCond struct {
	field  string // dst, src, dport, sport
	prefix netip.Prefix
	port   int
}

// ParseSockFilter parses e.g. `dst 10.0.0.1 and dport = :443`.
func ParseSockFilter(args []string) (SockFilter, error) {
	var f SockFilter
	// Like ss, accept the filter as separate words or quoted as one argument.
	args = strings.Fields(strings.Join(args, " "))
	for i := 0; i < len(args); {
		tok := args[i]
		if tok == "and" || tok == "&&" {
			i++
			continue
		}
		i++
		next := func() (string, error) {
			for i < len(args) && (args[i] == "=" || args[i] == "==" || args[i] == "eq") {
				i++
			}
			if i >= len(args) {
				return "", fmt.Errorf("filter %q needs a value", tok)
			}
			i++
			return args[i-1], nil
		}
		switch tok {
		case "dst", "src":
			v, err := next()
			if err != nil {
				return f, err
			}
			c := sockCond{field: tok}
			host, port := v, ""
			if h, p, ok := cutPort(v); ok {
				host, port = h, p
			}
			if !strings.Contains(host, "/") {
				a, err := netip.ParseAddr(strings.Trim(host, "[]"))
				if err != nil {
					return f, fmt.Errorf("bad address %q", v)
				}
				c.prefix = netip.PrefixFrom(a, a.BitLen())
			} else if c.prefix, err = netip.ParsePrefix(host); err != nil {
				return f, fmt.Errorf("bad prefix %q", v)
			}
			f.conds = append(f.conds, c)
			if port != "" && port != "*" {
				n, err := strconv.Atoi(port)
				if err != nil {
					return f, fmt.Errorf("bad port in %q", v)
				}
				pf := "dport"
				if tok == "src" {
					pf = "sport"
				}
				f.conds = append(f.conds, sockCond{field: pf, port: n})
			}
		case "dport", "sport":
			v, err := next()
			if err != nil {
				return f, err
			}
			n, err := strconv.Atoi(strings.TrimPrefix(v, ":"))
			if err != nil {
				return f, fmt.Errorf("bad port %q", v)
			}
			f.conds = append(f.conds, sockCond{field: tok, port: n})
		default:
			return f, fmt.Errorf("unsupported filter %q (supported: dst, src, dport, sport, and)", tok)
		}
	}
	return f, nil
}

// cutPort splits "1.2.3.4:80" or "[::1]:80"; a bare IPv6 address has no port.
func cutPort(v string) (string, string, bool) {
	if strings.HasPrefix(v, "[") {
		if i := strings.LastIndex(v, "]:"); i > 0 {
			return v[1:i], v[i+2:], true
		}
		return v, "", false
	}
	if strings.Count(v, ":") == 1 {
		h, p, _ := strings.Cut(v, ":")
		return h, p, true
	}
	return v, "", false
}

func (f SockFilter) Match(s *SSRow) bool {
	for _, c := range f.conds {
		switch c.field {
		case "dst", "src":
			a := s.raddr
			if c.field == "src" {
				a = s.laddr
			}
			if c.prefix.Addr().Is4() && a.Is4In6() {
				a = a.Unmap()
			}
			if !c.prefix.Contains(a) {
				return false
			}
		case "dport":
			if s.RPort != c.port {
				return false
			}
		case "sport":
			if s.LPort != c.port {
				return false
			}
		}
	}
	return true
}

type Owner struct {
	Comm string `json:"comm"`
	PID  int    `json:"pid"`
	FD   int    `json:"fd"`
}

// SSRow is one socket as `ss -tanp` shows it.
type SSRow struct {
	State     string  `json:"state"`
	RecvQ     int64   `json:"recv_q"`
	SendQ     int64   `json:"send_q"`
	Local     string  `json:"local"`
	LPort     int     `json:"lport"`
	Peer      string  `json:"peer"`
	RPort     int     `json:"rport"`
	Proto     string  `json:"proto"`
	Inode     uint64  `json:"inode"`
	Owners    []Owner `json:"owners"`
	id        int64
	appClosed bool // events: the application had closed the socket
	laddr     netip.Addr
	raddr     netip.Addr
}

// SocketsAt returns sockets of proto alive at sample s with their owners.
func SocketsAt(db *store.DB, s int64, proto string, f SockFilter) ([]SSRow, error) {
	rows, err := db.Query(`
		SELECT k.id, k.proto, k.laddr, k.lport, k.raddr, k.rport, COALESCE(k.ifname,''), k.inode,
		       x.state, x.rxq, x.txq
		FROM sockets k
		JOIN sock_samples x ON x.sock_id = k.id
		     AND x.ts = (SELECT MAX(ts) FROM sock_samples WHERE sock_id = k.id AND ts <= ?1)
		WHERE k.proto = ?3 AND k.first_seen <= ?1 AND COALESCE(k.last_seen, ?2) >= ?1`, s, openEnd, proto)
	if err != nil {
		return nil, err
	}
	var out []SSRow
	idx := map[int64]int{}
	for rows.Next() {
		var r SSRow
		var la, ra, ifn string
		var st int
		if err := rows.Scan(&r.id, &r.Proto, &la, &r.LPort, &ra, &r.RPort, &ifn, &r.Inode, &st, &r.RecvQ, &r.SendQ); err != nil {
			rows.Close()
			return nil, err
		}
		r.laddr, _ = netip.ParseAddr(la)
		r.raddr, _ = netip.ParseAddr(ra)
		r.State = sockdiag.StateName(st)
		r.Local = fmtAddr(r.laddr, ifn)
		r.Peer = fmtAddr(r.raddr, "")
		if !f.Match(&r) {
			continue
		}
		idx[r.id] = len(out)
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	orows, err := db.Query(`
		SELECT o.sock_id, p.comm, p.pid, o.fd FROM sock_owners o JOIN processes p ON p.id = o.proc_id
		WHERE o.first_seen <= ?1 AND COALESCE(o.last_seen, ?2) >= ?1`, s, openEnd)
	if err != nil {
		return nil, err
	}
	defer orows.Close()
	for orows.Next() {
		var id int64
		var o Owner
		if err := orows.Scan(&id, &o.Comm, &o.PID, &o.FD); err != nil {
			return nil, err
		}
		if i, ok := idx[id]; ok {
			out[i].Owners = append(out[i].Owners, o)
		}
	}
	for i := range out {
		sort.Slice(out[i].Owners, func(a, b int) bool { return out[i].Owners[a].PID < out[i].Owners[b].PID })
	}
	sort.SliceStable(out, func(a, b int) bool {
		x, y := out[a], out[b]
		if (x.State == "LISTEN") != (y.State == "LISTEN") {
			return x.State == "LISTEN"
		}
		if c := x.laddr.Compare(y.laddr); c != 0 {
			return c < 0
		}
		if x.LPort != y.LPort {
			return x.LPort < y.LPort
		}
		if c := x.raddr.Compare(y.raddr); c != 0 {
			return c < 0
		}
		return x.RPort < y.RPort
	})
	return out, orows.Err()
}

// fmtAddr formats an address as ss does: IPv6 in brackets, "%if" for
// sockets bound to a device.
func fmtAddr(a netip.Addr, ifname string) string {
	s := a.String()
	if a.Is6() {
		s = "[" + s + "]"
	}
	if ifname != "" {
		s += "%" + ifname
	}
	return s
}

// fmtAddrDual is fmtAddr for sockets recorded with their IPV6_V6ONLY flag:
// like ss, it prints the unspecified IPv6 address of a socket that also
// accepts IPv4 as "*".
func fmtAddrDual(a netip.Addr, ifname string, v6only bool) string {
	if a.Is6() && a.IsUnspecified() && !v6only {
		if ifname != "" {
			return "*%" + ifname
		}
		return "*"
	}
	return fmtAddr(a, ifname)
}

func fmtPort(p int) string {
	if p == 0 {
		return "*"
	}
	return strconv.Itoa(p)
}

func usersCol(owners []Owner) string {
	if len(owners) == 0 {
		return ""
	}
	parts := make([]string, len(owners))
	for i, o := range owners {
		parts[i] = fmt.Sprintf("(\"%s\",pid=%d,fd=%d)", o.Comm, o.PID, o.FD) // as it is, as ss prints it
	}
	return "users:(" + strings.Join(parts, ",") + ")"
}

// PrintSS prints rows in `ss -tanp` layout: addresses right-aligned against
// the ':' and ports left-aligned.
func PrintSS(w io.Writer, rows []SSRow) {
	wState, wLA, wLP, wRA, wRP := len("State"), 0, 0, 0, 0
	for _, r := range rows {
		wState = max(wState, len(r.State))
		wLA = max(wLA, len(r.Local))
		wLP = max(wLP, len(fmtPort(r.LPort)))
		wRA = max(wRA, len(r.Peer))
		wRP = max(wRP, len(fmtPort(r.RPort)))
	}
	wLP = max(wLP, len("Port"))
	wRP = max(wRP, len("Port"))
	wLA = max(wLA, len("Local Address"))
	wRA = max(wRA, len("Peer Address"))
	fmt.Fprintf(w, "%-*s %-6s %-6s %*s:%-*s %*s:%-*s %s\n", wState, "State", "Recv-Q", "Send-Q",
		wLA, "Local Address", wLP, "Port", wRA, "Peer Address", wRP, "Port", "Process")
	for _, r := range rows {
		line := fmt.Sprintf("%-*s %-6d %-6d %*s:%-*s %*s:%-*s %s", wState, r.State, r.RecvQ, r.SendQ,
			wLA, r.Local, wLP, fmtPort(r.LPort), wRA, r.Peer, wRP, fmtPort(r.RPort), usersCol(r.Owners))
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
}

// SSGroup summarises one process's sockets over a time range.
type SSGroup struct {
	FirstSeen int64          `json:"first_seen_ms"`
	LastSeen  int64          `json:"last_seen_ms"`
	Conns     int            `json:"conns"`
	Peak      int            `json:"peak"`
	States    map[string]int `json:"states"`
	Process   string         `json:"process"`
	PID       int            `json:"pid"`
	// From TCP events only (v2).
	Retransmits int `json:"retransmits"`
	Resets      int `json:"resets"`
}

// SocketsInRange groups sockets of proto that existed in [from, to] by owning
// process. Unowned sockets (e.g. TIME-WAIT) are grouped as "(no process)".
// STATES counts each socket once, by its last state within the range.
func SocketsInRange(db *store.DB, from, to int64, proto string, f SockFilter) ([]SSGroup, error) {
	rows, err := db.Query(`
		SELECT k.id, k.laddr, k.lport, k.raddr, k.rport,
		       CASE WHEN k.first_seen > ?1 THEN k.first_seen ELSE ?1 END,
		       CASE WHEN COALESCE(k.last_seen, ?3) < ?2 THEN COALESCE(k.last_seen, ?3) ELSE ?2 END,
		       COALESCE((SELECT state FROM sock_samples WHERE sock_id = k.id AND ts <= ?2 ORDER BY ts DESC LIMIT 1), 0),
		       COALESCE(o.first_seen, 0), COALESCE(o.last_seen, ?3), COALESCE(p.pid, 0), COALESCE(p.comm, ''), COALESCE(p.id, 0)
		FROM sockets k
		LEFT JOIN sock_owners o ON o.sock_id = k.id AND o.first_seen <= ?2 AND COALESCE(o.last_seen, ?3) >= ?1
		LEFT JOIN processes p ON p.id = o.proc_id
		WHERE k.proto = ?4 AND k.first_seen <= ?2 AND COALESCE(k.last_seen, ?3) >= ?1`, from, to, openEnd, proto)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type acc struct {
		g     SSGroup
		socks map[int64]bool
		spans []interval
	}
	groups := map[int64]*acc{}
	var order []int64
	for rows.Next() {
		var r SSRow
		var la, ra, comm string
		var first, last, st, procID int64
		var ofirst, olast int64
		var pid int
		if err := rows.Scan(&r.id, &la, &r.LPort, &ra, &r.RPort, &first, &last, &st, &ofirst, &olast, &pid, &comm, &procID); err != nil {
			return nil, err
		}
		r.laddr, _ = netip.ParseAddr(la)
		r.raddr, _ = netip.ParseAddr(ra)
		if !f.Match(&r) {
			continue
		}
		if procID != 0 { // clamp to the ownership period
			first, last = max(first, ofirst), min(last, olast)
		}
		a := groups[procID]
		if a == nil {
			a = &acc{g: SSGroup{FirstSeen: first, LastSeen: last, States: map[string]int{}, PID: pid,
				Process: fmt.Sprintf("%s,pid=%d", comm, pid)}, socks: map[int64]bool{}}
			if procID == 0 {
				a.g.Process = "(no process)"
			}
			groups[procID] = a
			order = append(order, procID)
		}
		a.g.FirstSeen = min(a.g.FirstSeen, first)
		a.g.LastSeen = max(a.g.LastSeen, last)
		if !a.socks[r.id] {
			a.socks[r.id] = true
			a.g.States[sockdiag.StateName(int(st))]++
		}
		a.spans = append(a.spans, interval{first, last})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]SSGroup, 0, len(groups))
	for _, id := range order {
		a := groups[id]
		a.g.Conns = len(a.socks)
		a.g.Peak = peakOverlap(a.spans)
		out = append(out, a.g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Conns != out[j].Conns {
			return out[i].Conns > out[j].Conns
		}
		return out[i].PID < out[j].PID
	})
	return out, nil
}

type interval struct{ a, b int64 }

// peakOverlap returns the largest number of closed intervals that contain a
// common point.
func peakOverlap(spans []interval) int {
	type ev struct {
		t     int64
		delta int
	}
	evs := make([]ev, 0, 2*len(spans))
	for _, s := range spans {
		evs = append(evs, ev{s.a, +1}, ev{s.b, -1})
	}
	sort.Slice(evs, func(i, j int) bool {
		if evs[i].t != evs[j].t {
			return evs[i].t < evs[j].t
		}
		return evs[i].delta > evs[j].delta // starts before ends at the same time
	})
	cur, peak := 0, 0
	for _, e := range evs {
		cur += e.delta
		peak = max(peak, cur)
	}
	return peak
}

func statesCol(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return m[keys[i]] > m[keys[j]] || (m[keys[i]] == m[keys[j]] && keys[i] < keys[j]) })
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s:%d", k, m[k])
	}
	return strings.Join(parts, ",")
}

func PrintSSGroups(w io.Writer, gs []SSGroup) {
	fmt.Fprintf(w, "%-19s %-19s %6s %6s %7s %6s  %-30s %s\n", "FIRST_SEEN", "LAST_SEEN", "CONNS", "PEAK", "RETRANS", "RESETS", "STATES", "PROCESS")
	for _, g := range gs {
		fmt.Fprintf(w, "%-19s %-19s %6d %6d %7d %6d  %-30s %s\n", FormatMS(g.FirstSeen), FormatMS(g.LastSeen),
			g.Conns, g.Peak, g.Retransmits, g.Resets, statesCol(g.States), g.Process)
	}
}

func PrintJSON(w io.Writer, v any) error { return writeJSON(w, v) }
