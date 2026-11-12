package query

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// v2 open files (meta fds = held): fds_held has the fds held across at least
// two consecutive walks of their process, and deleted files still open.

// FDsHeld reports whether open files were recorded in held mode.
func FDsHeld(db *store.DB) bool {
	var v string
	db.QueryRow(`SELECT value FROM meta WHERE key = 'fds'`).Scan(&v)
	return v == "held"
}

type heldFD struct {
	pid, uid, fd int
	comm, target string
	ftype, mode  string
	name         string
	deleted      bool
	node         int64
}

// heldAt lists the held fds at the fd walk sfd, of processes alive at s.
func heldAt(db *store.DB, s, sfd int64, pid int) ([]heldFD, error) {
	q := `SELECT p.pid, p.uid, p.comm, f.fd, f.target, COALESCE(f.ftype,''), COALESCE(f.mode,''), COALESCE(f.name,''),
	             f.deleted, COALESCE(f.node, 0)
	      FROM fds_held f JOIN processes p ON p.pid = f.pid AND p.start_time = f.start_time
	      WHERE f.first_seen <= ?2 AND COALESCE(f.last_seen, ?3) >= ?2
	        AND p.first_seen <= ?1 AND COALESCE(p.last_seen, ?3) >= ?1`
	args := []any{s, sfd, openEnd}
	if pid != 0 {
		q += ` AND p.pid = ?4`
		args = append(args, pid)
	}
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []heldFD
	for rows.Next() {
		var h heldFD
		var del int
		if err := rows.Scan(&h.pid, &h.uid, &h.comm, &h.fd, &h.target, &h.ftype, &h.mode, &h.name, &del, &h.node); err != nil {
			return nil, err
		}
		h.deleted = del == 1
		out = append(out, h)
	}
	return out, rows.Err()
}

// lsofHeld: files from fds_held at the last walk; TCP sockets from events at
// t; UDP from the keyframe; and inet sockets that other processes hold as
// well (an fd held across walks whose inode is a known connection).
func lsofHeld(db *store.DB, t int64, o LsofOptions) (rows []LsofRow, s, sfd int64, err error) {
	if s, err = SnapshotAt(db, t, false); err != nil {
		return
	}
	if sfd, err = SnapshotAt(db, t, true); err != nil {
		return
	}
	// Inet sockets known at t, by inode.
	inet := map[int64]SSRow{}
	if tcp, _, err := ConnsAt(db, t, "tcp", SockFilter{}); err == nil {
		for _, r := range tcp {
			if r.Inode != 0 {
				inet[int64(r.Inode)] = r
			}
		}
	}
	if udp, err := udpAt(db, KeyframeAt(db, t), SockFilter{}); err == nil {
		for _, r := range udp {
			if r.Inode != 0 {
				inet[int64(r.Inode)] = r
			}
		}
	}
	// TCP rows from the events (owner and fd), and UDP from the keyframe.
	if rows, err = inetEventRows(db, t, o.PID); err != nil {
		return
	}
	have := map[string]bool{}
	for _, r := range rows {
		have[r.FD+"/"+strconv.Itoa(r.PID)] = true
	}
	held, err := heldAt(db, s, sfd, o.PID)
	if err != nil {
		return
	}
	for _, h := range held {
		x := LsofRow{Command: lsofCommand(h.comm), PID: h.pid, User: UserName(h.uid, false), fdNum: h.fd,
			FD: fdLabel(h.fd, h.mode), Type: h.ftype, Name: h.target, Deleted: h.deleted}
		if h.name != "" {
			x.Name = h.name
		}
		if h.node != 0 {
			x.Node = strconv.FormatInt(h.node, 10)
		}
		if ino, ok := procfs.SocketInode(h.target); ok {
			x.Node = strconv.FormatUint(ino, 10)
			if c, isInet := inet[int64(ino)]; isInet {
				if have[fdLabel(h.fd, "u")+"/"+strconv.Itoa(h.pid)] {
					continue // the event owner's row already has it
				}
				x.FD, x.Type, x.Node, x.SockInode = fdLabel(h.fd, "u"), "IPv4", strings.ToUpper(c.Proto), int64(ino)
				if c.laddr.Is6() && !c.laddr.Is4In6() {
					x.Type = "IPv6"
				}
				x.Name = inetName(c.Proto, c.laddr.String(), c.LPort, c.raddr.String(), c.RPort, stateNum(c.State))
			} else if o.InetOnly {
				continue
			}
		} else if o.InetOnly {
			continue
		}
		rows = append(rows, x)
	}
	sortLsof(rows)
	return rows, t, sfd, nil
}

// inetEventRows: TCP sockets held at t by their event owner, and UDP from the
// keyframe.
func inetEventRows(db *store.DB, t int64, pid int) ([]LsofRow, error) {
	args := []any{t, KeyframeAt(db, t), openEnd}
	pidCond, udpCond := "", ""
	if pid != 0 {
		args = append(args, pid)
		pidCond, udpCond = " AND c.pid = ?4", " AND k.pid = ?4"
	}
	q, err := db.Query(`SELECT p.comm, c.pid, p.uid, c.fd, 'tcp', c.family, c.laddr, c.lport, c.raddr, c.rport,
		       COALESCE((SELECT x.new_state FROM tcp_transitions x WHERE x.conn_id = c.id AND x.ts <= ?1
		                 ORDER BY x.ts DESC, x.seq DESC LIMIT 1), c.first_state), c.inode
		FROM tcp_conns c JOIN processes p ON p.pid = c.pid AND p.start_time = c.start_time
		WHERE c.pid <> 0 AND c.fd >= 0 AND c.open_ts <= ?1
		  AND (c.close_ts > ?1 OR (c.close_ts IS NULL AND c.last_seen >= ?1))
		  AND (c.owner_until IS NULL OR c.owner_until > ?1)`+pidCond+`
		UNION ALL
		SELECT p.comm, k.pid, p.uid, k.fd, 'udp', k.family, k.laddr, k.lport, k.raddr, k.rport, k.state, k.inode
		FROM tcp_keyframes k JOIN processes p ON p.pid = k.pid AND p.start_time = k.start_time
		WHERE k.ts = ?2 AND k.proto = 'udp' AND k.pid <> 0 AND k.fd >= 0`+udpCond, args...)
	if err != nil {
		return nil, err
	}
	defer q.Close()
	var out []LsofRow
	for q.Next() {
		var x LsofRow
		var comm, proto, la, ra string
		var uid, fam, lp, rp, st int
		if err := q.Scan(&comm, &x.PID, &uid, &x.fdNum, &proto, &fam, &la, &lp, &ra, &rp, &st, &x.SockInode); err != nil {
			return nil, err
		}
		x.Command, x.User, x.FD = lsofCommand(comm), UserName(uid, false), fdLabel(x.fdNum, "u")
		x.Type, x.Node, x.Name = "IPv"+strconv.Itoa(fam), strings.ToUpper(proto), inetName(proto, la, lp, ra, rp, st)
		out = append(out, x)
	}
	return out, q.Err()
}

func stateNum(name string) int {
	for n, s := range lsofTCPStates {
		if strings.ReplaceAll(s, "_", "-") == name || s == name {
			return n
		}
	}
	switch name {
	case "ESTAB":
		return 1
	case "UNCONN":
		return 7
	}
	return 0
}

// addHolders adds to TCP rows at t the other processes holding the socket
// (fds held across walks), unless the application had closed it.
func addHolders(db *store.DB, t int64, rows []SSRow) {
	if !FDsHeld(db) {
		return
	}
	s, err1 := SnapshotAt(db, t, false)
	sfd, err2 := SnapshotAt(db, t, true)
	if err1 != nil || err2 != nil {
		return
	}
	held, err := heldAt(db, s, sfd, 0)
	if err != nil {
		return
	}
	byInode := map[uint64][]heldFD{}
	for _, h := range held {
		if ino, ok := procfs.SocketInode(h.target); ok {
			byInode[ino] = append(byInode[ino], h)
		}
	}
	for i := range rows {
		r := &rows[i]
		if r.Inode == 0 || r.appClosed {
			continue // a time-wait socket, or closed by the application: nobody holds it
		}
		for _, h := range byInode[r.Inode] {
			dup := false
			for _, o := range r.Owners {
				if o.PID == h.pid && o.FD == h.fd {
					dup = true
				}
			}
			if !dup {
				r.Owners = append(r.Owners, Owner{Comm: h.comm, PID: h.pid, FD: h.fd})
			}
		}
		sortOwners(r.Owners)
	}
}

func sortOwners(o []Owner) {
	for i := 1; i < len(o); i++ {
		for j := i; j > 0 && o[j].PID < o[j-1].PID; j-- {
			o[j], o[j-1] = o[j-1], o[j]
		}
	}
}

// ---- mounts ----

type MountRow struct {
	TS           int64  `json:"ts_ms"`
	Action       string `json:"action"`
	Point        string `json:"mount_point"`
	Source       string `json:"source"`
	FSType       string `json:"fstype"`
	Options      string `json:"options"`
	SuperOptions string `json:"super_options"`
	Dev          string `json:"dev"`
	Root         string `json:"root"`
	LoopFile     string `json:"loop_file,omitempty"`
	UserOptions  string `json:"user_options,omitempty"`
	MountID      int    `json:"mount_id"`
	Label        string `json:"label,omitempty"` // mount -l (AddMountLabels)
	seq          int
	since        int64 // when it was mounted (or the run's snapshot)
}

func mountRows(db *store.DB, q string, args ...any) ([]MountRow, error) {
	rows, err := db.Query(`SELECT ts, action, mount_id, mount_point, source, fstype, options, COALESCE(super_options, ''),
		COALESCE(dev, ''), COALESCE(root, ''), COALESCE(seq, 0), COALESCE(loop_file, ''), COALESCE(user_options, '') FROM mounts `+q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MountRow
	for rows.Next() {
		var m MountRow
		if err := rows.Scan(&m.TS, &m.Action, &m.MountID, &m.Point, &m.Source, &m.FSType, &m.Options, &m.SuperOptions,
			&m.Dev, &m.Root, &m.seq, &m.LoopFile, &m.UserOptions); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MountChanges lists mounts, unmounts and remounts in [from, to].
func MountChanges(db *store.DB, from, to int64) ([]MountRow, error) {
	return mountRows(db, `WHERE ts >= ?1 AND ts <= ?2 AND action <> 'present' ORDER BY ts`, from, to)
}

// MountsAt replays the mount table up to t: each recorder run starts with
// the mounts present, then its changes; runs record the whole table again
// hourly (each snapshot replaces the table).
func MountsAt(db *store.DB, t int64) ([]MountRow, error) {
	all, err := mountRows(db, `WHERE ts <= ?1 ORDER BY ts, action = 'present' DESC, seq`, t)
	if err != nil {
		return nil, err
	}
	cur, prev := map[int]MountRow{}, map[int]MountRow{}
	var presentTS int64 = -1
	ordered := false // recordings before schema 2 have no mountinfo order
	for _, m := range all {
		ordered = ordered || m.seq > 0
		switch m.Action {
		case "present":
			if m.TS != presentTS { // a snapshot (hourly or a new run's) replaces the table
				prev, cur, presentTS = cur, map[int]MountRow{}, m.TS
			}
			// A mount the table already had stays mounted since then: df
			// and lsblk take usage rows from that time on (an hourly usage
			// row may come seconds before the hourly snapshot).
			m.since = m.TS
			if p, ok := prev[m.MountID]; ok && p.Point == m.Point && p.Source == m.Source && p.Dev == m.Dev {
				m.since = p.since
			}
			cur[m.MountID] = m
		case "mount":
			m.since = m.TS
			cur[m.MountID] = m
		case "remount": // same place in the table
			m.since, m.seq = cur[m.MountID].since, cur[m.MountID].seq
			cur[m.MountID] = m
		case "unmount":
			delete(cur, m.MountID)
		}
	}
	out := make([]MountRow, 0, len(cur))
	for _, m := range cur {
		out = append(out, m)
	}
	if !ordered {
		sortMounts(out)
		return out, nil
	}
	// mountinfo order: the run's snapshot as it was, then later mounts in
	// the order they came (the kernel appends them).
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.since != b.since {
			return a.since < b.since
		}
		return a.seq < b.seq
	})
	return out, nil
}

func sortMounts(m []MountRow) {
	for i := 1; i < len(m); i++ {
		for j := i; j > 0 && m[j].Point < m[j-1].Point; j-- {
			m[j], m[j-1] = m[j-1], m[j]
		}
	}
}

func PrintMounts(w io.Writer, rows []MountRow, changes bool) {
	if changes {
		fmt.Fprintf(w, "%-19s %-8s %-30s %-10s %s\n", "TIME", "ACTION", "MOUNT POINT", "FSTYPE", "SOURCE")
		for _, m := range rows {
			fmt.Fprintf(w, "%-19s %-8s %-30s %-10s %s\n", FormatMS(m.TS), m.Action, m.Point, m.FSType, m.Source)
		}
		return
	}
	fmt.Fprintf(w, "%-40s %-10s %-30s %s\n", "MOUNT POINT", "FSTYPE", "SOURCE", "OPTIONS")
	for _, m := range rows {
		fmt.Fprintf(w, "%-40s %-10s %-30s %s\n", m.Point, m.FSType, m.Source, m.Options)
	}
}
