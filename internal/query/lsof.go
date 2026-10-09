package query

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"sosv/internal/store"
)

// LsofRow is one open file as `lsof -n -P` shows it (without DEVICE and
// SIZE/OFF, which sosv does not record).
type LsofRow struct {
	Command   string `json:"command"`
	PID       int    `json:"pid"`
	User      string `json:"user"`
	FD        string `json:"fd"`
	Type      string `json:"type"`
	Node      string `json:"node"`
	Name      string `json:"name"`
	Deleted   bool   `json:"deleted,omitempty"`
	FirstSeen int64  `json:"first_seen_ms,omitempty"`
	LastSeen  int64  `json:"last_seen_ms,omitempty"`
	SockInode int64  `json:"-"` // inet sockets: lsof shows it as NODE when it cannot resolve the socket
	fdNum     int
}

type LsofOptions struct {
	PID      int  // 0 = all
	InetOnly bool // -i
}

var lsofTCPStates = map[int]string{1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
	5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING"}

func fdLabel(fd int, mode string) string {
	switch fd {
	case -1:
		return "cwd"
	case -2:
		return "rtd"
	case -3:
		return "txt"
	}
	return strconv.Itoa(fd) + mode
}

// lsofAddr formats an endpoint as lsof -n -P: "*" for a wildcard address,
// IPv6 in brackets.
func lsofAddr(a string, port int) string {
	ip, err := netip.ParseAddr(a)
	host := a
	if err == nil {
		switch {
		case ip.IsUnspecified():
			host = "*"
		case ip.Is6():
			host = "[" + a + "]"
		}
	}
	p := "*"
	if port != 0 {
		p = strconv.Itoa(port)
	}
	return host + ":" + p
}

func inetName(proto, la string, lp int, ra string, rp int, state int) string {
	name := lsofAddr(la, lp)
	if rp != 0 {
		name += "->" + lsofAddr(ra, rp)
	}
	if proto == "tcp" {
		name += " (" + lsofTCPStates[state] + ")"
	}
	return name
}

func lsofCommand(comm string) string {
	if len(comm) > 9 {
		return comm[:9]
	}
	return comm
}

// LsofAt reconstructs lsof at t. Open files come from the latest full fd
// walk at or before t (sfd); inet sockets come from socket ownership at the
// latest sample s, which is refreshed every interval. Only processes alive at
// s are listed.
func LsofAt(db *store.DB, t int64, o LsofOptions) (rows []LsofRow, s, sfd int64, err error) {
	if s, err = SnapshotAt(db, t, false); err != nil {
		return
	}
	if sfd, err = SnapshotAt(db, t, true); err != nil {
		return
	}
	pidCond := ""
	args := []any{s, sfd, openEnd}
	if o.PID != 0 {
		pidCond = " AND p.pid = ?4"
		args = append(args, o.PID)
	}
	if !o.InetOnly {
		q := `SELECT p.comm, p.pid, p.uid, f.fd, f.target, COALESCE(f.ftype,''), COALESCE(f.mode,''),
		             COALESCE(f.name, ''), f.deleted, COALESCE(f.node, 0)
		      FROM open_files f JOIN processes p ON p.id = f.proc_id
		      WHERE f.first_seen <= ?2 AND COALESCE(f.last_seen, ?3) >= ?2
		        AND p.first_seen <= ?1 AND COALESCE(p.last_seen, ?3) >= ?1` + pidCond
		r, err2 := db.Query(q, args...)
		if err2 != nil {
			return nil, 0, 0, err2
		}
		for r.Next() {
			var x LsofRow
			var comm, target, mode, name string
			var uid, del int
			var node int64
			if err = r.Scan(&comm, &x.PID, &uid, &x.fdNum, &target, &x.Type, &mode, &name, &del, &node); err != nil {
				r.Close()
				return
			}
			x.Command, x.User, x.FD = lsofCommand(comm), UserName(uid, false), fdLabel(x.fdNum, mode)
			x.Deleted = del == 1
			x.Name = target
			if name != "" {
				x.Name = name
			}
			if node != 0 {
				x.Node = strconv.FormatInt(node, 10)
			} else if ino, ok := strings.CutPrefix(target, "socket:["); ok {
				x.Node = strings.TrimSuffix(ino, "]")
			}
			rows = append(rows, x)
		}
		r.Close()
	}
	q := `SELECT p.comm, p.pid, p.uid, o.fd, k.proto, k.family, k.laddr, k.lport, k.raddr, k.rport,
	             COALESCE((SELECT state FROM sock_samples WHERE sock_id = k.id AND ts <= ?1 ORDER BY ts DESC LIMIT 1), 0), k.inode
	      FROM sock_owners o JOIN sockets k ON k.id = o.sock_id JOIN processes p ON p.id = o.proc_id
	      WHERE o.first_seen <= ?1 AND COALESCE(o.last_seen, ?3) >= ?1` + pidCond
	r, err := db.Query(q, args...)
	if err != nil {
		return
	}
	defer r.Close()
	for r.Next() {
		var x LsofRow
		var comm, proto, la, ra string
		var uid, fam, lp, rp, st int
		if err = r.Scan(&comm, &x.PID, &uid, &x.fdNum, &proto, &fam, &la, &lp, &ra, &rp, &st, &x.SockInode); err != nil {
			return
		}
		x.Command, x.User, x.FD = lsofCommand(comm), UserName(uid, false), fdLabel(x.fdNum, "u")
		x.Type = "IPv" + strconv.Itoa(fam)
		x.Node = strings.ToUpper(proto)
		x.Name = inetName(proto, la, lp, ra, rp, st)
		rows = append(rows, x)
	}
	sortLsof(rows)
	return rows, s, sfd, r.Err()
}

func sortLsof(rows []LsofRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].PID != rows[j].PID {
			return rows[i].PID < rows[j].PID
		}
		return rows[i].fdNum < rows[j].fdNum // cwd(-1), rtd(-2), txt(-3) sort first
	})
}

// LsofRange lists files and inet sockets held at any time in [from, to].
func LsofRange(db *store.DB, from, to int64, o LsofOptions) ([]LsofRow, error) {
	pidCond := ""
	args := []any{from, to, openEnd}
	if o.PID != 0 {
		pidCond = " AND p.pid = ?4"
		args = append(args, o.PID)
	}
	var rows []LsofRow
	if !o.InetOnly {
		r, err := db.Query(`SELECT p.comm, p.pid, p.uid, f.fd, f.target, COALESCE(f.ftype,''), COALESCE(f.mode,''),
		       COALESCE(f.name,''), f.deleted, COALESCE(f.node, 0), f.first_seen, COALESCE(f.last_seen, ?3)
		  FROM open_files f JOIN processes p ON p.id = f.proc_id
		  WHERE f.first_seen <= ?2 AND COALESCE(f.last_seen, ?3) >= ?1`+pidCond, args...)
		if err != nil {
			return nil, err
		}
		for r.Next() {
			var x LsofRow
			var comm, target, mode, name string
			var uid, del int
			var node int64
			if err := r.Scan(&comm, &x.PID, &uid, &x.fdNum, &target, &x.Type, &mode, &name, &del, &node, &x.FirstSeen, &x.LastSeen); err != nil {
				r.Close()
				return nil, err
			}
			x.Command, x.User, x.FD, x.Deleted, x.Name = lsofCommand(comm), UserName(uid, false), fdLabel(x.fdNum, mode), del == 1, target
			if node != 0 {
				x.Node = strconv.FormatInt(node, 10)
			}
			if name != "" {
				x.Name = name
			}
			rows = append(rows, x)
		}
		r.Close()
	}
	r, err := db.Query(`SELECT p.comm, p.pid, p.uid, o.fd, k.proto, k.family, k.laddr, k.lport, k.raddr, k.rport,
	       COALESCE((SELECT state FROM sock_samples WHERE sock_id = k.id AND ts <= ?2 ORDER BY ts DESC LIMIT 1), 0),
	       o.first_seen, COALESCE(o.last_seen, ?3)
	  FROM sock_owners o JOIN sockets k ON k.id = o.sock_id JOIN processes p ON p.id = o.proc_id
	  WHERE o.first_seen <= ?2 AND COALESCE(o.last_seen, ?3) >= ?1`+pidCond, args...)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for r.Next() {
		var x LsofRow
		var comm, proto, la, ra string
		var uid, fam, lp, rp, st int
		if err := r.Scan(&comm, &x.PID, &uid, &x.fdNum, &proto, &fam, &la, &lp, &ra, &rp, &st, &x.FirstSeen, &x.LastSeen); err != nil {
			return nil, err
		}
		x.Command, x.User, x.FD = lsofCommand(comm), UserName(uid, false), fdLabel(x.fdNum, "u")
		x.Type, x.Node, x.Name = "IPv"+strconv.Itoa(fam), strings.ToUpper(proto), inetName(proto, la, lp, ra, rp, st)
		rows = append(rows, x)
	}
	// Still-open rows: show the last sample that saw them instead of "open".
	lastAny, _ := SnapshotAt(db, to, false)
	lastFD, _ := SnapshotAt(db, to, true)
	for i := range rows {
		if rows[i].LastSeen == openEnd {
			rows[i].LastSeen = lastFD
			if rows[i].Node == "TCP" || rows[i].Node == "UDP" {
				rows[i].LastSeen = lastAny
			}
		}
	}
	sortLsof(rows)
	return rows, r.Err()
}

func PrintLsof(w io.Writer, rows []LsofRow, withTimes bool) {
	wc, wu, wn := len("COMMAND"), len("USER"), len("NODE")
	for _, r := range rows {
		wc, wu, wn = max(wc, len(r.Command)), max(wu, len(r.User)), max(wn, len(r.Node))
	}
	prefix := func(first, last string) string {
		if !withTimes {
			return ""
		}
		return fmt.Sprintf("%-19s %-19s ", first, last)
	}
	fmt.Fprintf(w, "%s%-*s %7s %-*s %5s %7s %*s %s\n", prefix("FIRST_SEEN", "LAST_SEEN"),
		wc, "COMMAND", "PID", wu, "USER", "FD", "TYPE", wn, "NODE", "NAME")
	for _, r := range rows {
		fmt.Fprintf(w, "%s%-*s %7d %-*s %5s %7s %*s %s\n", prefix(FormatMS(r.FirstSeen), FormatMS(r.LastSeen)),
			wc, r.Command, r.PID, wu, r.User, r.FD, r.Type, wn, r.Node, r.Name)
	}
}
