package query

import (
	"database/sql"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"clifr/internal/sockdiag"
	"clifr/internal/store"
)

// TCP recorded from eBPF events (v2): tcp_conns has every connection with
// its owner, open and close times, tcp_transitions its state changes, and
// tcp_keyframes full socket dumps (exact queues, and UDP) every keyframe
// interval. In v1 databases (meta tcp = sample) the sockets tables are used.

const (
	stateTimeWait = 6
	stateListen   = 10
)

// TCPFromEvents reports whether TCP was recorded from events.
func TCPFromEvents(db *store.DB) bool {
	var v string
	db.QueryRow(`SELECT value FROM meta WHERE key = 'tcp'`).Scan(&v)
	return strings.HasPrefix(v, "events")
}

// TimeWaitExact reports whether time-wait ends were recorded from events.
func TimeWaitExact(db *store.DB) bool {
	var v string
	db.QueryRow(`SELECT value FROM meta WHERE key = 'tcp'`).Scan(&v)
	return strings.Contains(v, "time-wait end exact")
}

// KeyframeAt is the latest keyframe at or before t (0 if none).
func KeyframeAt(db *store.DB, t int64) int64 {
	var ts sql.NullInt64
	db.QueryRow(`SELECT MAX(ts) FROM tcp_keyframes WHERE ts <= ?1`, t).Scan(&ts)
	return ts.Int64
}

// ConnsAt reconstructs `ss -tanp` (or -uanp) at the exact time t. TCP
// connections, states and owners come from events; Recv-Q and Send-Q from
// the keyframe kf (latest at or before t), and are 0 for connections it does
// not have. UDP comes from that keyframe only.
func ConnsAt(db *store.DB, t int64, proto string, f SockFilter) (rows []SSRow, kf int64, err error) {
	kf = KeyframeAt(db, t)
	if proto != "tcp" {
		rows, err = udpAt(db, kf, f)
		sortSS(rows)
		return rows, kf, err
	}
	if f.NetNS != 0 {
		// Another namespace's TCP files are read at keyframes within a time
		// budget (recorder/netns.go): its queues come from its latest read.
		var ts sql.NullInt64
		db.QueryRow(`SELECT MAX(ts) FROM tcp_keyframes WHERE ts <= ?1 AND proto = 'tcp' AND netns = ?2`, t, f.NetNS).Scan(&ts)
		kf = ts.Int64
	}
	q, err := db.Query(`
		SELECT c.id, c.laddr, c.lport, c.raddr, c.rport, c.inode, c.pid, c.fd, c.owner_until, COALESCE(c.ifname, ''),
		       c.open_ts, c.close_ts, c.linger_state, c.linger_until,
		       COALESCE((SELECT x.new_state FROM tcp_transitions x WHERE x.conn_id = c.id AND x.ts <= ?1
		                 ORDER BY x.ts DESC, x.seq DESC LIMIT 1), c.first_state),
		       COALESCE(p.comm, ''), COALESCE(k.recv_q, 0), COALESCE(k.send_q, 0), COALESCE(c.v6only, 1)
		FROM tcp_conns c
		LEFT JOIN processes p ON p.pid = c.pid AND p.start_time = c.start_time
		LEFT JOIN tcp_keyframes k ON k.ts = ?2 AND k.conn_id = c.id
		WHERE c.open_ts <= ?1 AND COALESCE(c.netns, 0) = ?3
		  AND (c.close_ts > ?1 OR (c.close_ts IS NULL AND c.last_seen >= ?1) OR c.linger_until >= ?1)`, t, kf, f.NetNS)
	if err != nil {
		return nil, kf, err
	}
	defer q.Close()
	type cand struct {
		r      SSRow
		linger bool
		open   int64
		close  int64
	}
	byTuple := map[string]cand{}
	for q.Next() {
		var r SSRow
		var la, ra, comm, ifn string
		var pid, fd, lingerState, state, v6only int
		var openTS int64
		var ownerUntil, closeTS, lingerUntil sql.NullInt64
		if err := q.Scan(&r.id, &la, &r.LPort, &ra, &r.RPort, &r.Inode, &pid, &fd, &ownerUntil, &ifn, &openTS, &closeTS,
			&lingerState, &lingerUntil, &state, &comm, &r.RecvQ, &r.SendQ, &v6only); err != nil {
			return nil, kf, err
		}
		r.Proto = "tcp"
		r.laddr, _ = netip.ParseAddr(la)
		r.raddr, _ = netip.ParseAddr(ra)
		linger := closeTS.Valid && closeTS.Int64 <= t
		if linger { // the time-wait socket left behind; no process holds it
			state, r.RecvQ, r.SendQ, r.Inode = lingerState, 0, 0, 0
		} else if ownerUntil.Valid && ownerUntil.Int64 <= t {
			r.appClosed = true
		} else if pid != 0 {
			r.Owners = []Owner{{Comm: comm, PID: pid, FD: fd}}
		}
		if state == 0 || r.LPort == 0 && state != stateListen {
			continue // no state yet, or a connect still being set up
		}
		r.State = sockdiag.StateName(state)
		r.Local = fmtAddrDual(r.laddr, ifn, v6only != 0)
		r.Peer = fmtAddrDual(r.raddr, "", v6only != 0)
		if !f.Match(&r) {
			continue
		}
		// The same addresses twice: a time-wait leftover and a new
		// connection that reused them, or two live rows when the older
		// connection's close was missed (it is closed later, when seen
		// gone). One row per addresses, whatever order DuckDB returns them
		// in (it has none: the output changed from run to run, 2026-11-21).
		key := fmt.Sprint(r.laddr, r.LPort, r.raddr, r.RPort)
		c := cand{r, linger, openTS, closeTS.Int64}
		if old, ok := byTuple[key]; ok && !tupleWins(c.linger, old.linger, c.open, old.open, c.close, old.close, c.r.id, old.r.id) {
			continue
		}
		byTuple[key] = c
	}
	if err := q.Err(); err != nil {
		return nil, kf, err
	}
	for _, c := range byTuple {
		rows = append(rows, c.r)
	}
	addHolders(db, t, rows)
	sortSS(rows)
	return rows, kf, nil
}

// tupleWins reports whether connection a replaces b, both shown at the
// same addresses: a live one over a time-wait leftover; of two live ones the
// one opened later (the addresses are reused only after the earlier socket
// closed); of two leftovers the one closed later; then the higher id.
func tupleWins(aLinger, bLinger bool, aOpen, bOpen, aClose, bClose, aID, bID int64) bool {
	switch {
	case aLinger != bLinger:
		return !aLinger
	case !aLinger && aOpen != bOpen:
		return aOpen > bOpen
	case aLinger && aClose != bClose:
		return aClose > bClose
	}
	return aID > bID
}

func udpAt(db *store.DB, kf int64, f SockFilter) ([]SSRow, error) {
	q, err := db.Query(`
		SELECT k.laddr, k.lport, k.raddr, k.rport, k.inode, k.state, k.recv_q, k.send_q, k.pid, k.fd, COALESCE(p.comm, ''),
		       COALESCE(k.v6only, 1)
		FROM tcp_keyframes k LEFT JOIN processes p ON p.pid = k.pid AND p.start_time = k.start_time
		WHERE k.ts = ?1 AND k.proto = 'udp' AND COALESCE(k.netns, 0) = ?2`, kf, f.NetNS)
	if err != nil {
		return nil, err
	}
	defer q.Close()
	var out []SSRow
	for q.Next() {
		var r SSRow
		var la, ra, comm string
		var st, pid, fd, v6only int
		if err := q.Scan(&la, &r.LPort, &ra, &r.RPort, &r.Inode, &st, &r.RecvQ, &r.SendQ, &pid, &fd, &comm, &v6only); err != nil {
			return nil, err
		}
		r.Proto = "udp"
		r.laddr, _ = netip.ParseAddr(la)
		r.raddr, _ = netip.ParseAddr(ra)
		r.State, r.Local, r.Peer = sockdiag.StateName(st), fmtAddrDual(r.laddr, "", v6only != 0), fmtAddrDual(r.raddr, "", v6only != 0)
		if pid != 0 {
			r.Owners = []Owner{{Comm: comm, PID: pid, FD: fd}}
		}
		if f.Match(&r) {
			out = append(out, r)
		}
	}
	return out, q.Err()
}

func sortSS(out []SSRow) {
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
		if x.RPort != y.RPort {
			return x.RPort < y.RPort
		}
		// Sockets bound to the same addresses (UDP multicast listeners):
		// a fixed order, not the order the rows were loaded in.
		if x.Inode != y.Inode {
			return x.Inode < y.Inode
		}
		if len(x.Owners) > 0 && len(y.Owners) > 0 && x.Owners[0].PID != y.Owners[0].PID {
			return x.Owners[0].PID < y.Owners[0].PID
		}
		return len(x.Owners) > 0 && len(y.Owners) > 0 && x.Owners[0].FD < y.Owners[0].FD
	})
}

// rangeConn is one TCP connection that existed in a range.
type rangeConn struct {
	row          SSRow // State: its last state in the range (before TCP_CLOSE if it closed)
	first, last  int64 // open time; close time or last seen
	closed       bool  // closed by the end of the range
	retr, resets int
	pid          int
	comm         string
	procID       int64 // processes.id of the owner; 0 unknown
	cmdline      string
}

// connsInRange returns the TCP connections that existed in [from, to] that f
// matches, in the order they opened.
func connsInRange(db *store.DB, from, to int64, f SockFilter) ([]rangeConn, error) {
	q, err := db.Query(`
		SELECT c.id, c.laddr, c.lport, c.raddr, c.rport, c.open_ts, COALESCE(c.close_ts, c.last_seen),
		       COALESCE(c.close_ts <= ?2, false), c.final_state,
		       COALESCE((SELECT x.new_state FROM tcp_transitions x WHERE x.conn_id = c.id AND x.ts <= ?2
		                 ORDER BY x.ts DESC, x.seq DESC LIMIT 1), c.first_state),
		       c.retransmits, c.resets_sent, c.resets_received, c.pid, COALESCE(p.comm, ''),
		       COALESCE(p.id, 0), COALESCE(p.cmdline, '')
		FROM tcp_conns c
		LEFT JOIN processes p ON p.pid = c.pid AND p.start_time = c.start_time
		WHERE c.open_ts <= ?2 AND COALESCE(c.close_ts, c.last_seen) >= ?1 AND COALESCE(c.netns, 0) = ?3
		ORDER BY c.open_ts, c.id`, from, to, f.NetNS)
	if err != nil {
		return nil, err
	}
	defer q.Close()
	var out []rangeConn
	for q.Next() {
		var c rangeConn
		var la, ra string
		var finalState, state, rs, rr int
		if err := q.Scan(&c.row.id, &la, &c.row.LPort, &ra, &c.row.RPort, &c.first, &c.last, &c.closed, &finalState,
			&state, &c.retr, &rs, &rr, &c.pid, &c.comm, &c.procID, &c.cmdline); err != nil {
			return nil, err
		}
		c.row.laddr, _ = netip.ParseAddr(la)
		c.row.raddr, _ = netip.ParseAddr(ra)
		if !f.Match(&c.row) {
			continue
		}
		if c.closed {
			state = finalState // its last state before it closed
		}
		c.row.Proto = "tcp"
		c.row.State = sockdiag.StateName(state)
		c.resets = rs + rr
		out = append(out, c)
	}
	return out, q.Err()
}

// ConnsInRange groups the TCP connections that existed in [from, to] by the
// process that owned them, with retransmits and resets.
func ConnsInRange(db *store.DB, from, to int64, f SockFilter) ([]SSGroup, error) {
	conns, err := connsInRange(db, from, to, f)
	if err != nil {
		return nil, err
	}
	type acc struct {
		g     SSGroup
		spans []interval
	}
	groups := map[string]*acc{}
	var order []string
	for _, c := range conns {
		key := fmt.Sprint(c.pid, c.comm)
		a := groups[key]
		if a == nil {
			a = &acc{g: SSGroup{FirstSeen: c.first, LastSeen: c.last, States: map[string]int{}, PID: c.pid,
				Process: fmt.Sprintf("%s,pid=%d", c.comm, c.pid)}}
			if c.pid == 0 {
				a.g.Process = "(no process)"
			}
			groups[key] = a
			order = append(order, key)
		}
		a.g.FirstSeen = min(a.g.FirstSeen, c.first)
		a.g.LastSeen = max(a.g.LastSeen, c.last)
		a.g.Conns++
		a.g.States[c.row.State]++
		a.g.Retransmits += c.retr
		a.g.Resets += c.resets
		a.spans = append(a.spans, interval{max(c.first, from), min(c.last, to)})
	}
	out := make([]SSGroup, 0, len(groups))
	for _, k := range order {
		a := groups[k]
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
