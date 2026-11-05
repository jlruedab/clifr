package query

import (
	"fmt"
	"io"
	"strings"

	"clifr/internal/store"
)

// ConnSpan is one TCP connection over a range, for clifr --list: the
// addresses, its last state in the range (before TCP_CLOSE if it closed),
// when it opened and closed, and its owner.
type ConnSpan struct {
	State       string  `json:"state"`
	Local       string  `json:"local"`
	LPort       int     `json:"lport"`
	Peer        string  `json:"peer"`
	RPort       int     `json:"rport"`
	Owners      []Owner `json:"owners"` // fd -1: not known over a range
	Opened      int64   `json:"opened_ms"`
	Closed      int64   `json:"closed_ms"` // 0: still open at the end of the range
	Retransmits int     `json:"retransmits"`
	Resets      int     `json:"resets"`
	Program     string  `json:"program"` // netstat's program name (argv[0]), else comm
	row         SSRow   // for the commands' selection (Keep)
}

// Row is the connection as an SSRow (addresses, last state), for the ss
// and netstat selection rules.
func (c *ConnSpan) Row() *SSRow { return &c.row }

// ConnList returns every TCP connection that existed in [from, to] (from
// events, however short), in the order they opened.
func ConnList(db *store.DB, from, to int64, f SockFilter) ([]ConnSpan, error) {
	conns, err := connsInRange(db, from, to, f)
	if err != nil {
		return nil, err
	}
	var procs []procAt
	for _, c := range conns {
		if c.procID != 0 {
			procs = append(procs, procAt{id: c.procID})
		}
	}
	argv0 := argv0Lens(db, procs)
	out := make([]ConnSpan, len(conns))
	for i, c := range conns {
		s := ConnSpan{State: c.row.State, LPort: c.row.LPort, RPort: c.row.RPort, Opened: c.first,
			Retransmits: c.retr, Resets: c.resets, row: c.row}
		if c.closed {
			s.Closed = c.last
		}
		s.Local, s.Peer = fmtAddr(c.row.laddr, ""), fmtAddr(c.row.raddr, "")
		if c.pid != 0 {
			s.Owners = []Owner{{Comm: c.comm, PID: c.pid, FD: -1}}
			s.Program = programName(c.cmdline, c.comm, argv0[c.procID])
		}
		out[i] = s
	}
	return out, nil
}

// closedCol is the CLOSED column: the close time, or "-" for a connection
// still open at the end of the range.
func closedCol(ms int64) string {
	if ms == 0 {
		return "-"
	}
	return FormatMS(ms)
}

// PrintNetstatList prints conns in netstat -n's columns with OPENED and
// CLOSED in place of the queues (known only at keyframes, not over a range).
func PrintNetstatList(w io.Writer, conns []ConnSpan, v NetstatView) {
	wt := len(TimeLayout)
	head := fmt.Sprintf("%-5s %-23s %-23s %-11s %-*s %-*s", "Proto", "Local Address", "Foreign Address", "State",
		wt, "Opened", wt, "Closed")
	if v.Program {
		head += " PID/Program name"
	}
	fmt.Fprintln(w, strings.TrimRight(head, " "))
	for _, c := range conns {
		proto := "tcp"
		la, ra := c.row.laddr, c.row.raddr
		if la.Is6() {
			proto = "tcp6"
		}
		line := fmt.Sprintf("%-4s  %-23s %-23s %-11s %-*s %-*s", proto,
			netstatAddr(la.WithZone(""), la.Is6(), c.LPort, v.Wide),
			netstatAddr(ra.WithZone(""), la.Is6(), c.RPort, v.Wide),
			netstatStates[c.State], wt, FormatMS(c.Opened), wt, closedCol(c.Closed))
		if v.Program {
			prog := "-"
			if len(c.Owners) > 0 {
				prog = fmt.Sprintf("%d/%s", c.Owners[0].PID, c.Program)
				if len(prog) > 19 {
					prog = prog[:19]
				}
			}
			line += " " + prog
		}
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
}

// PrintSSList prints conns in ss's columns with Opened and Closed in place of
// the queues; with -p the owner as users:(("comm",pid=N)).
func PrintSSList(w io.Writer, conns []ConnSpan, v SSView) {
	svc := map[string]map[int]string{}
	if !v.Numeric {
		svc = services()
	}
	port := func(p int) string {
		if n, ok := svc["tcp"][p]; ok && p != 0 {
			return n
		}
		return fmtPort(p)
	}
	wt := len(TimeLayout)
	wState, wLA, wLP, wRA, wRP := len("State"), len("Local Address"), len("Port"), len("Peer Address"), len("Port")
	for _, c := range conns {
		wState = max(wState, len(c.State))
		wLA, wLP = max(wLA, len(c.Local)), max(wLP, len(port(c.LPort)))
		wRA, wRP = max(wRA, len(c.Peer)), max(wRP, len(port(c.RPort)))
	}
	head := ""
	if v.Process {
		head = "Process"
	}
	line := fmt.Sprintf("%-*s %*s:%-*s %*s:%-*s %-*s %-*s %s", wState, "State", wLA, "Local Address", wLP, "Port",
		wRA, "Peer Address", wRP, "Port", wt, "Opened", wt, "Closed", head)
	fmt.Fprintln(w, strings.TrimRight(line, " "))
	for _, c := range conns {
		users := ""
		if v.Process && len(c.Owners) > 0 {
			users = fmt.Sprintf("users:((\"%s\",pid=%d))", c.Owners[0].Comm, c.Owners[0].PID)
		}
		line := fmt.Sprintf("%-*s %*s:%-*s %*s:%-*s %-*s %-*s %s", wState, c.State, wLA, c.Local, wLP, port(c.LPort),
			wRA, c.Peer, wRP, port(c.RPort), wt, FormatMS(c.Opened), wt, closedCol(c.Closed), users)
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
}
