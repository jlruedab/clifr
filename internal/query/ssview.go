package query

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// SSView holds the ss options that choose and format rows: -a, -l, -p, -n,
// -4, -6.
type SSView struct {
	All, Listening, Process, Numeric, V4, V6 bool
}

// Keep applies ss's state and family selection. Without -a or -l, ss shows
// connected sockets only: not LISTEN, UNCONN (TCP_CLOSE), TIME-WAIT or
// SYN-RECV. -l shows only LISTEN and UNCONN.
func (v SSView) Keep(r *SSRow) bool {
	if v.V4 != v.V6 {
		inet6 := r.laddr.Is6() // AF_INET6, IPv4-mapped included
		if v.V4 == inet6 {
			return false
		}
	}
	listening := r.State == "LISTEN" || r.State == "UNCONN"
	switch {
	case v.All:
		return true
	case v.Listening:
		return listening
	}
	return !listening && r.State != "TIME-WAIT" && r.State != "SYN-RECV"
}

// Filter keeps the rows v selects.
func (v SSView) Filter(rows []SSRow) []SSRow {
	out := rows[:0]
	for i := range rows {
		if v.Keep(&rows[i]) {
			out = append(out, rows[i])
		}
	}
	return out
}

// PrintSSView prints rows like ss with these options: a Netid column when
// both TCP and UDP are shown, service names unless -n, owners only with -p.
// Rows are in the order given; ss lists UDP before TCP.
func PrintSSView(w io.Writer, rows []SSRow, v SSView, netid bool) {
	svc := map[string]map[int]string{}
	if !v.Numeric {
		svc = services()
	}
	port := func(r SSRow, p int) string {
		if n, ok := svc[r.Proto][p]; ok && p != 0 {
			return n
		}
		return fmtPort(p)
	}
	wState, wLA, wLP, wRA, wRP := len("State"), len("Local Address"), len("Port"), len("Peer Address"), len("Port")
	for _, r := range rows {
		wState = max(wState, len(r.State))
		wLA, wLP = max(wLA, len(r.Local)), max(wLP, len(port(r, r.LPort)))
		wRA, wRP = max(wRA, len(r.Peer)), max(wRP, len(port(r, r.RPort)))
	}
	prefix := func(s string) string {
		if !netid {
			return ""
		}
		return fmt.Sprintf("%-5s ", s)
	}
	head := ""
	if v.Process { // ss prints the Process heading only with -p
		head = "Process"
	}
	line := fmt.Sprintf("%s%-*s %-6s %-6s %*s:%-*s %*s:%-*s %s", prefix("Netid"), wState, "State", "Recv-Q", "Send-Q",
		wLA, "Local Address", wLP, "Port", wRA, "Peer Address", wRP, "Port", head)
	fmt.Fprintln(w, strings.TrimRight(line, " "))
	for _, r := range rows {
		users := ""
		if v.Process {
			users = usersCol(r.Owners)
		}
		line := fmt.Sprintf("%s%-*s %-6d %-6d %*s:%-*s %*s:%-*s %s", prefix(r.Proto), wState, r.State, r.RecvQ, r.SendQ,
			wLA, r.Local, wLP, port(r, r.LPort), wRA, r.Peer, wRP, port(r, r.RPort), users)
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
}

// services reads /etc/services of the machine running clifr: port to name
// by protocol, as ss resolves them without -n (getservbyport).
func services() map[string]map[int]string {
	m := map[string]map[int]string{"tcp": {}, "udp": {}}
	f, err := os.Open("/etc/services")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fs := strings.Fields(line)
		if len(fs) < 2 {
			continue
		}
		p, proto, ok := strings.Cut(fs[1], "/")
		n, err := strconv.Atoi(p)
		if !ok || err != nil || m[proto] == nil {
			continue
		}
		if _, seen := m[proto][n]; !seen { // the first entry wins, like getservbyport
			m[proto][n] = fs[0]
		}
	}
	return m
}
