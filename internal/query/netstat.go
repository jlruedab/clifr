package query

import (
	"fmt"
	"io"
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// NetstatView holds netstat's selection and format options (net-tools 2.10):
// -a, -l, -p, -W, -4, -6.
type NetstatView struct {
	All, Listening, Program, Wide, V4, V6 bool
}

// Keep applies netstat's selection: TCP without -a shows every state but
// LISTEN, with -l only LISTEN; UDP without -a only connected sockets, with
// -l only unconnected ones.
func (v NetstatView) Keep(r *SSRow) bool {
	if v.V4 != v.V6 && v.V4 == r.laddr.Is6() {
		return false
	}
	if v.All {
		return true
	}
	server := r.State == "LISTEN" || r.Proto == "udp" && r.State == "UNCONN"
	return server == v.Listening
}

var netstatStates = map[string]string{"ESTAB": "ESTABLISHED", "SYN-SENT": "SYN_SENT", "SYN-RECV": "SYN_RECV",
	"FIN-WAIT-1": "FIN_WAIT1", "FIN-WAIT-2": "FIN_WAIT2", "TIME-WAIT": "TIME_WAIT", "UNCONN": "CLOSE",
	"CLOSE-WAIT": "CLOSE_WAIT", "LAST-ACK": "LAST_ACK", "LISTEN": "LISTEN", "CLOSING": "CLOSING"}

// netstatAddr formats ADDR:PORT like netstat -n: IPv6 without brackets or
// interface, IPv4-mapped addresses as IPv4, the address cut so that the
// whole fits 23 characters unless wide.
func netstatAddr(a netip.Addr, inet6 bool, port int, wide bool) string {
	s := a.Unmap().String() // net-tools prints IPv4-mapped addresses as IPv4
	switch {
	case !a.IsValid() && inet6:
		s = "::"
	case !a.IsValid():
		s = "0.0.0.0"
	}
	p := "*"
	if port != 0 {
		p = strconv.Itoa(port)
	}
	if !wide && len(s)+len(p) > 22 {
		s = s[:max(22-len(p), 0)]
	}
	return s + ":" + p
}

// ProgramNames returns netstat's PID/Program name for the processes alive at
// t: argv[0], cut after its last '/' when it starts with one (net-tools).
// Recordings since schema 2 keep where argv[0] ends; for older ones it is
// taken as the first word of the command line unless that ends with ':' (a
// title set by the process, such as "sshd: /usr/sbin/sshd -D").
func ProgramNames(db *store.DB, t int64) (map[int]string, error) {
	s, err := SnapshotAt(db, t, false)
	if err != nil {
		return nil, err
	}
	procs, err := processesAt(db, s, t)
	if err != nil {
		return nil, err
	}
	argv0 := argv0Lens(db, procs)
	out := make(map[int]string, len(procs))
	for _, p := range procs {
		out[p.pid] = programName(p.cmdline, p.comm, argv0[p.id])
	}
	return out, nil
}

// argv0Lens reads argv0_len of these processes (none where the column does
// not exist: v1 databases).
func argv0Lens(db *store.DB, procs []procAt) map[int64]int {
	out := map[int64]int{}
	if len(procs) == 0 {
		return out
	}
	ids := make([]string, len(procs))
	for i, p := range procs {
		ids[i] = strconv.FormatInt(p.id, 10)
	}
	rows, err := db.Query(`SELECT id, COALESCE(argv0_len, 0) FROM processes WHERE id IN (` + strings.Join(ids, ",") + `)`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n int
		if rows.Scan(&id, &n) == nil && n > 0 {
			out[id] = n
		}
	}
	return out
}

func programName(cmdline, comm string, argv0 int) string {
	if cmdline == "" {
		return comm
	}
	if argv0 > 0 && argv0 <= len(cmdline) {
		a := cmdline[:argv0]
		if strings.HasPrefix(a, "/") {
			return a[strings.LastIndexByte(a, '/')+1:]
		}
		return a
	}
	if strings.HasPrefix(cmdline, "/") {
		first, _, _ := strings.Cut(cmdline, " ")
		return path.Base(first)
	}
	first, _, _ := strings.Cut(cmdline, " ")
	if strings.HasSuffix(first, ":") {
		return cmdline
	}
	return first
}

// PrintNetstat prints rows like netstat -n with these options: TCP before
// UDP, IPv4 before IPv6 (tcp, tcp6, udp, udp6).
func PrintNetstat(w io.Writer, rows []SSRow, v NetstatView, progs map[int]string) {
	what := "(w/o servers)"
	switch {
	case v.All:
		what = "(servers and established)"
	case v.Listening:
		what = "(only servers)"
	}
	fmt.Fprintf(w, "Active Internet connections %s\n", what)
	head := fmt.Sprintf("%-5s %6s %6s %-23s %-23s %-11s", "Proto", "Recv-Q", "Send-Q", "Local Address", "Foreign Address", "State")
	if v.Program {
		head += " PID/Program name    "
	}
	fmt.Fprintln(w, head)
	rank := func(r SSRow) int {
		n := 0
		if r.Proto == "udp" {
			n = 2
		}
		if r.laddr.Is6() {
			n++
		}
		return n
	}
	sort.SliceStable(rows, func(i, j int) bool { return rank(rows[i]) < rank(rows[j]) })
	for _, r := range rows {
		proto := r.Proto
		if r.laddr.Is6() {
			proto += "6"
		}
		state := netstatStates[r.State]
		sendQ := r.SendQ
		switch {
		case r.State == "LISTEN":
			sendQ = 0 // /proc/net/tcp has no backlog; ss shows it
		case r.Proto == "udp" && r.State == "UNCONN":
			state = ""
		}
		line := fmt.Sprintf("%-4s  %6d %6d %-23s %-23s %-11s", proto, r.RecvQ, sendQ,
			netstatAddr(r.laddr.WithZone(""), r.laddr.Is6(), r.LPort, v.Wide), netstatAddr(r.raddr.WithZone(""), r.laddr.Is6(), r.RPort, v.Wide), state)
		if v.Program {
			prog := "-"
			if len(r.Owners) > 0 {
				o := r.Owners[0]
				name := progs[o.PID]
				if name == "" {
					name = o.Comm
				}
				prog = fmt.Sprintf("%d/%s", o.PID, name)
				if len(prog) > 19 {
					prog = prog[:19]
				}
			}
			line += fmt.Sprintf(" %-20s", prog)
		}
		fmt.Fprintln(w, line)
	}
}
