package query

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"clifr/internal/store"
)

// netstat -s: net-tools prints each counter of /proc/net/snmp and netstat
// (with -6: snmp6, then snmp's Tcp) as a sentence from a table per section.
// The tables are looked up by binary search in their written order, which is
// not quite sorted in every table: a counter the search misses prints as
// "Name: value" when not 0, like a counter that is in no table (net-tools
// 2.10, statistics.c: "Forwarding: 1", "OutTransmits: 3216438").

type statKind int

const (
	statNumber    statKind = iota // printed, 0 included
	statOptNumber                 // printed when not 0
	statForward                   // "Forwarding is enabled"
	statInICMP                    // under "ICMP input histogram:", when not 0
	statOutICMP                   // under "ICMP output histogram:", when not 0
	statRTO                       // never printed
)

type statEntry struct {
	name, text string
	kind       statKind
	static     bool // a setting: netstat -s never prints it
}

func (k statKind) indent() int {
	if k == statInICMP || k == statOutICMP {
		return 8
	}
	return 4
}

func (k statKind) title() string {
	switch k {
	case statInICMP:
		return "ICMP input histogram:"
	case statOutICMP:
		return "ICMP output histogram:"
	}
	return ""
}

var (
	ipStats = []statEntry{
		{"DefaultTTL", "Default TTL is %d", statNumber, true},
		{"Forwarding", "Forwarding is %s", statForward, true},
		{"ForwDatagrams", "%d forwarded", statNumber, false},
		{"FragCreates", "%d fragments created", statOptNumber, false},
		{"FragFails", "%d outgoing packets failed fragmentation", statOptNumber, false},
		{"FragOKs", "%d outgoing packets fragmented ok", statOptNumber, false},
		{"InAddrErrors", "%d with invalid addresses", statOptNumber, false},
		{"InDelivers", "%d incoming packets delivered", statNumber, false},
		{"InDiscards", "%d incoming packets discarded", statNumber, false},
		{"InHdrErrors", "%d with invalid headers", statOptNumber, false},
		{"InReceives", "%d total packets received", statNumber, false},
		{"InUnknownProtos", "%d with unknown protocol", statOptNumber, false},
		{"OutDiscards", "%d outgoing packets dropped", statOptNumber, false},
		{"OutNoRoutes", "%d dropped because of missing route", statOptNumber, false},
		{"OutRequests", "%d requests sent out", statNumber, false},
		{"ReasmFails", "%d packet reassemblies failed", statOptNumber, false},
		{"ReasmOKs", "%d packets reassembled ok", statOptNumber, false},
		{"ReasmReqds", "%d reassemblies required", statOptNumber, false},
		{"ReasmTimeout", "%d fragments dropped after timeout", statOptNumber, false},
	}
	ip6Stats = []statEntry{
		{"Ip6FragCreates", "%d fragments created", statOptNumber, false},
		{"Ip6FragFails", "%d outgoing packets failed fragmentation", statOptNumber, false},
		{"Ip6FragOKs", "%d outgoing packets fragmented ok", statOptNumber, false},
		{"Ip6InAddrErrors", "%d with invalid addresses", statOptNumber, false},
		{"Ip6InDelivers", "%d incoming packets delivered", statNumber, false},
		{"Ip6InDiscards", "%d incoming packets discarded", statNumber, false},
		{"Ip6InHdrErrors", "%d with invalid headers", statOptNumber, false},
		{"Ip6InMcastPkts", "%d incoming multicast packets", statOptNumber, false},
		{"Ip6InNoRoutes", "%d incoming packets with no route", statOptNumber, false},
		{"Ip6InReceives", "%d total packets received", statNumber, false},
		{"Ip6InTooBigErrors", "%d with packets too big", statOptNumber, false},
		{"Ip6InTruncatedPkts", "%d with truncated packets", statOptNumber, false},
		{"Ip6InUnknownProtos", "%d with unknown protocol", statOptNumber, false},
		{"Ip6OutDiscards", "%d outgoing packets dropped", statOptNumber, false},
		{"Ip6OutForwDatagrams", "%d forwarded", statNumber, false},
		{"Ip6OutMcastPkts", "%d outgoing multicast packets", statOptNumber, false},
		{"Ip6OutNoRoutes", "%d dropped because of missing route", statOptNumber, false},
		{"Ip6OutRequests", "%d requests sent out", statNumber, false},
		{"Ip6ReasmFails", "%d packet reassemblies failed", statOptNumber, false},
		{"Ip6ReasmOKs", "%d packets reassembled ok", statOptNumber, false},
		{"Ip6ReasmReqds", "%d reassemblies required", statOptNumber, false},
		{"Ip6ReasmTimeout", "%d fragments dropped after timeout", statOptNumber, false},
	}
	icmpStats = []statEntry{
		{"InAddrMaskReps", "address mask replies: %d", statInICMP, false},
		{"InAddrMasks", "address mask request: %d", statInICMP, false},
		{"InDestUnreachs", "destination unreachable: %d", statInICMP, false},
		{"InEchoReps", "echo replies: %d", statInICMP, false},
		{"InEchos", "echo requests: %d", statInICMP, false},
		{"InErrors", "%d input ICMP message failed", statNumber, false},
		{"InMsgs", "%d ICMP messages received", statNumber, false},
		{"InParmProbs", "wrong parameters: %d", statInICMP, false},
		{"InRedirects", "redirects: %d", statInICMP, false},
		{"InSrcQuenchs", "source quenches: %d", statInICMP, false},
		{"InTimeExcds", "timeout in transit: %d", statInICMP, false},
		{"InTimestampReps", "timestamp reply: %d", statInICMP, false},
		{"InTimestamps", "timestamp request: %d", statInICMP, false},
		{"OutAddrMaskReps", "address mask replies: %d", statOutICMP, false},
		{"OutAddrMasks", "address mask requests: %d", statOutICMP, false},
		{"OutDestUnreachs", "destination unreachable: %d", statOutICMP, false},
		{"OutEchoReps", "echo replies: %d", statOutICMP, false},
		{"OutEchos", "echo requests: %d", statOutICMP, false},
		{"OutErrors", "%d ICMP messages failed", statNumber, false},
		{"OutMsgs", "%d ICMP messages sent", statNumber, false},
		{"OutParmProbs", "wrong parameters: %d", statOutICMP, false},
		{"OutRedirects", "redirect: %d", statOutICMP, false},
		{"OutSrcQuenchs", "source quench: %d", statOutICMP, false},
		{"OutTimeExcds", "time exceeded: %d", statOutICMP, false},
		{"OutTimestampReps", "timestamp replies: %d", statOutICMP, false},
		{"OutTimestamps", "timestamp requests: %d", statOutICMP, false},
	}
	icmp6Stats = []statEntry{
		{"Icmp6InDestUnreachs", "destination unreachable: %d", statInICMP, false},
		{"Icmp6InEchoReplies", "echo replies: %d", statInICMP, false},
		{"Icmp6InEchos", "echo requests: %d", statInICMP, false},
		{"Icmp6InErrors", "%d input ICMP message failed", statNumber, false},
		{"Icmp6InGroupMembQueries", "group member queries: %d", statInICMP, false},
		{"Icmp6InGroupMembReductions", "group member reductions: %d", statInICMP, false},
		{"Icmp6InGroupMembResponses", "group member responses: %d", statInICMP, false},
		{"Icmp6InMsgs", "%d ICMP messages received", statNumber, false},
		{"Icmp6InNeighborAdvertisements", "neighbour advertisement: %d", statInICMP, false},
		{"Icmp6InNeighborSolicits", "neighbour solicits: %d", statInICMP, false},
		{"Icmp6InParmProblems", "parameter problem: %d", statInICMP, false},
		{"Icmp6InPktTooBigs", "packets too big: %d", statInICMP, false},
		{"Icmp6InRedirects", "redirects: %d", statInICMP, false},
		{"Icmp6InRouterAdvertisements", "router advertisement: %d", statInICMP, false},
		{"Icmp6InRouterSolicits", "router solicits: %d", statInICMP, false},
		{"Icmp6InTimeExcds", "received ICMPv6 time exceeded: %d", statInICMP, false},
		{"Icmp6OutDestUnreachs", "destination unreachable: %d", statOutICMP, false},
		{"Icmp6OutEchoReplies", "echo replies: %d", statOutICMP, false},
		{"Icmp6OutEchos", "echo requests: %d", statOutICMP, false},
		{"Icmp6OutGroupMembQueries", "group member queries: %d", statOutICMP, false},
		{"Icmp6OutGroupMembReductions", "group member reductions: %d", statOutICMP, false},
		{"Icmp6OutGroupMembResponses", "group member responses: %d", statOutICMP, false},
		{"Icmp6OutMsgs", "%d ICMP messages sent", statNumber, false},
		{"Icmp6OutNeighborAdvertisements", "neighbor advertisements: %d", statOutICMP, false},
		{"Icmp6OutNeighborSolicits", "neighbor solicits: %d", statOutICMP, false},
		{"Icmp6OutParmProblems", "parameter problem: %d", statOutICMP, false},
		{"Icmp6OutPktTooBigs", "packets too big: %d", statOutICMP, false},
		{"Icmp6OutRedirects", "redirects: %d", statOutICMP, false},
		{"Icmp6OutRouterAdvertisements ", "router advertisement: %d", statOutICMP, false}, // sic: never matches
		{"Icmp6OutRouterSolicits", "router solicits: %d", statOutICMP, false},
		{"Icmp6OutTimeExcds", "sent ICMPv6 time exceeded: %d", statOutICMP, false},
	}
	tcpStats = []statEntry{
		{"ActiveOpens", "%d active connection openings", statNumber, false},
		{"AttemptFails", "%d failed connection attempts", statNumber, false},
		{"CurrEstab", "%d connections established", statNumber, false},
		{"EstabResets", "%d connection resets received", statNumber, false},
		{"InErrs", "%d bad segments received", statNumber, false},
		{"InSegs", "%d segments received", statNumber, false},
		{"MaxConn", "", statNumber, false},
		{"OutRsts", "%d resets sent", statNumber, false},
		{"OutSegs", "%d segments sent out", statNumber, false},
		{"PassiveOpens", "%d passive connection openings", statNumber, false},
		{"RetransSegs", "%d segments retransmitted", statNumber, false},
		{"RtoAlgorithm", "RTO algorithm is %s", statRTO, true},
		{"RtoMax", "", statNumber, false},
		{"RtoMin", "", statNumber, false},
	}
	udpStats = []statEntry{
		{"InDatagrams", "%d packets received", statNumber, false},
		{"InErrors", "%d packet receive errors", statNumber, false},
		{"NoPorts", "%d packets to unknown port received", statNumber, false},
		{"OutDatagrams", "%d packets sent", statNumber, false},
		{"RcvbufErrors", "%d receive buffer errors", statNumber, false},
		{"SndbufErrors", "%d send buffer errors", statNumber, false},
	}
	udp6Stats = []statEntry{
		{"Udp6InDatagrams", "%d packets received", statNumber, false},
		{"Udp6InErrors", "%d packet receive errors", statNumber, false},
		{"Udp6NoPorts", "%d packets to unknown port received", statNumber, false},
		{"Udp6OutDatagrams", "%d packets sent", statNumber, false},
	}
	tcpExtStats = []statEntry{
		{"DelayedACKLocked", "%d delayed acks further delayed because of locked socket", statOptNumber, false},
		{"DelayedACKLost", "Quick ack mode was activated %d times", statOptNumber, false},
		{"DelayedACKs", "%d delayed acks sent", statOptNumber, false},
		{"EmbryonicRsts", "%d resets received for embryonic SYN_RECV sockets", statOptNumber, false},
		{"ListenDrops", "%d SYNs to LISTEN sockets dropped", statOptNumber, false},
		{"ListenOverflows", "%d times the listen queue of a socket overflowed", statOptNumber, false},
		{"LockDroppedIcmps", "%d ICMP packets dropped because socket was locked", statOptNumber, false},
		{"OfoPruned", "%d packets dropped from out-of-order queue because of socket buffer overrun", statOptNumber, false},
		{"OutOfWindowIcmps", "%d ICMP packets dropped because they were out-of-window", statOptNumber, false},
		{"PAWSActive", "%d active connections rejected because of time stamp", statOptNumber, false},
		{"PAWSEstab", "%d packets rejected in established connections because of timestamp", statOptNumber, false},
		{"PAWSPassive", "%d passive connections rejected because of time stamp", statOptNumber, false},
		{"PruneCalled", "%d packets pruned from receive queue because of socket buffer overrun", statOptNumber, false},
		{"RcvPruned", "%d packets pruned from receive queue", statOptNumber, false},
		{"SockMallocOOM", "Ran %d times out of system memory during packet sending", statOptNumber, false},
		{"SyncookiesFailed", "%d invalid SYN cookies received", statOptNumber, false},
		{"SyncookiesRecv", "%d SYN cookies received", statOptNumber, false},
		{"SyncookiesSent", "%d SYN cookies sent", statOptNumber, false},
		{"TCPAbortFailed", "%d times unable to send RST due to no memory", statOptNumber, false},
		{"TCPAbortOnClose", "%d connections reset due to early user close", statOptNumber, false},
		{"TCPAbortOnData", "%d connections reset due to unexpected data", statOptNumber, false},
		{"TCPAbortOnLinger", "%d connections aborted after user close in linger timeout", statOptNumber, false},
		{"TCPAbortOnMemory", "%d connections aborted due to memory pressure", statOptNumber, false},
		{"TCPAbortOnSyn", "%d connections reset due to unexpected SYN", statOptNumber, false},
		{"TCPAbortOnTimeout", "%d connections aborted due to timeout", statOptNumber, false},
		{"TCPDirectCopyFromBacklog", "%d bytes directly in process context from backlog", statOptNumber, false},
		{"TCPDirectCopyFromPrequeue", "%d bytes directly received in process context from prequeue", statOptNumber, false},
		{"TCPDSACKOfoRecv", "%d DSACKs for out of order packets received", statOptNumber, false},
		{"TCPDSACKOfoSent", "%d DSACKs sent for out of order packets", statOptNumber, false},
		{"TCPDSACKOldSent", "%d DSACKs sent for old packets", statOptNumber, false},
		{"TCPDSACKRecv", "%d DSACKs received", statOptNumber, false},
		{"TCPDSackUndo", "%d congestion window recovered without slow start using DSACK", statOptNumber, false},
		{"TCPDSACKUndo", "%d congestion windows recovered without slow start by DSACK", statOptNumber, false},
		{"TCPFACKReorder", "Detected reordering %d times using FACK", statOptNumber, false},
		{"TCPFastRetrans", "%d fast retransmits", statOptNumber, false},
		{"TCPForwardRetrans", "%d forward retransmits", statOptNumber, false},
		{"TCPFullUndo", "%d congestion windows fully recovered without slow start", statOptNumber, false},
		{"TCPHPAcks", "%d predicted acknowledgments", statOptNumber, false},
		{"TCPHPHits", "%d packet headers predicted", statNumber, false},
		{"TCPHPHitsToUser", "%d packet headers predicted and directly queued to user", statOptNumber, false},
		{"TCPLossFailures", "%d timeouts in loss state", statOptNumber, false},
		{"TCPLoss", "%d TCP data loss events", statOptNumber, false},
		{"TCPLossUndo", "%d congestion windows recovered without slow start after partial ack", statOptNumber, false},
		{"TCPLostRetransmits", "%d retransmits lost", statOptNumber, false},
		{"TCPMemoryPressures", "TCP ran low on memory %d times", statOptNumber, false},
		{"TCPPartialUndo", "%d congestion windows partially recovered using Hoe heuristic", statOptNumber, false},
		{"TCPPrequeued", "%d packets directly queued to recvmsg prequeue", statOptNumber, false},
		{"TCPPrequeueDropped", "%d packets dropped from prequeue", statOptNumber, false},
		{"TCPPureAcks", "%d acknowledgments not containing data payload received", statOptNumber, false},
		{"TCPRcvCollapsed", "%d packets collapsed in receive queue due to low socket buffer", statOptNumber, false},
		{"TCPRenoFailures", "%d timeouts after reno fast retransmit", statOptNumber, false},
		{"TCPRenoRecoveryFailed", "%d reno fast retransmits failed", statOptNumber, false},
		{"TCPRenoRecoveryFail", "%d classic Reno fast retransmits failed", statOptNumber, false},
		{"TCPRenoRecovery", "%d times recovered from packet loss due to fast retransmit", statOptNumber, false},
		{"TCPRenoReorder", "Detected reordering %d times using reno fast retransmit", statOptNumber, false},
		{"TCPSackFailures", "%d timeouts after SACK recovery", statOptNumber, false},
		{"TCPSackRecoveryFail", "%d SACK retransmits failed", statOptNumber, false},
		{"TCPSackRecovery", "%d times recovered from packet loss by selective acknowledgements", statOptNumber, false},
		{"TCPSACKReneging", "%d bad SACK blocks received", statOptNumber, false},
		{"TCPSACKReorder", "Detected reordering %d times using SACK", statOptNumber, false},
		{"TCPSchedulerFailed", "%d times receiver scheduled too late for direct processing", statOptNumber, false},
		{"TCPSlowStartRetrans", "%d retransmits in slow start", statOptNumber, false},
		{"TCPTimeouts", "%d other TCP timeouts", statOptNumber, false},
		{"TCPTSReorder", "Detected reordering %d times using time stamp", statOptNumber, false},
		{"TWKilled", "%d TCP sockets finished time wait in slow timer", statOptNumber, false},
		{"TW", "%d TCP sockets finished time wait in fast timer", statOptNumber, false},
		{"TWRecycled", "%d time wait sockets recycled by time stamp", statOptNumber, false},
	}
)

// statSection is a section netstat -s knows; filter says which of -w (raw:
// ip and icmp), -t and -u shows it.
type statSection struct {
	table  []statEntry
	filter string
}

var (
	statSections  = map[string]statSection{"Ip": {ipStats, "raw"}, "Icmp": {icmpStats, "raw"}, "Tcp": {tcpStats, "tcp"}, "Udp": {udpStats, "udp"}, "TcpExt": {tcpExtStats, "tcp"}}
	stat6Sections = map[string]statSection{"Ip6": {ip6Stats, "raw"}, "Icmp6": {icmp6Stats, "raw"}, "Udp6": {udp6Stats, "udp"}, "Tcp6": {tcpStats, "tcp"}}
)

// statFind is C's bsearch over the table as written (strcmp order).
func statFind(table []statEntry, name string) (statEntry, bool) {
	lo, hi := 0, len(table)
	for lo < hi {
		i := (lo + hi) / 2
		switch c := strings.Compare(name, table[i].name); {
		case c < 0:
			hi = i
		case c > 0:
			lo = i + 1
		default:
			return table[i], true
		}
	}
	return statEntry{}, false
}

// NetstatStatsOptions: which sections netstat -s shows (-w raw, -t, -u;
// none: all of them) and -6.
type NetstatStatsOptions struct {
	Raw, TCP, UDP, V6 bool
}

// statCounter is one counter in file order with its section and its name
// in the section.
type statCounter struct {
	section, field string
	value          uint64
}

// NetstatStats renders netstat -s at the system sample at or before t,
// returning the sample's time.
func NetstatStats(db *store.DB, t int64, o NetstatStatsOptions) (string, int64, error) {
	var ts int64
	if err := db.QueryRow(`SELECT COALESCE(MAX(ts), 0) FROM net_counters WHERE ts <= ?`, t).Scan(&ts); err != nil || ts == 0 {
		return "", 0, fmt.Errorf("protocol counters (/proc/net/snmp) are not recorded at or before %s (recorded since 2026-10-21)", FormatMS(t))
	}
	rows, err := db.Query(`SELECT arg_max(section, ts), name, arg_max(value, ts), arg_max(pos, ts) FROM net_counters
		WHERE ts <= ? AND ts >= ? GROUP BY name`, ts, ts-store.NetCountersFullMS-60_000)
	if err != nil {
		return "", 0, err
	}
	type rec struct {
		section, name string
		value         int64
		pos           int
	}
	var all []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.section, &r.name, &r.value, &r.pos); err != nil {
			rows.Close()
			return "", 0, err
		}
		all = append(all, r)
	}
	rows.Close()
	sort.Slice(all, func(i, j int) bool { return all[i].pos < all[j].pos })
	var snmp, snmp6 []statCounter
	for _, r := range all {
		c := statCounter{section: r.section, field: strings.TrimPrefix(r.name, r.section), value: uint64(r.value)}
		if r.section == "" {
			c.field = r.name
			snmp6 = append(snmp6, c)
		} else {
			snmp = append(snmp, c)
		}
	}
	all6 := !o.Raw && !o.TCP && !o.UDP
	shown := func(filter string) bool {
		return all6 || filter == "raw" && o.Raw || filter == "tcp" && o.TCP || filter == "udp" && o.UDP
	}
	var sb strings.Builder
	p := statPrinter{w: &sb, shown: shown}
	if o.V6 {
		// snmp6 has no sections: a section is the name up to its first "6".
		var title string
		for _, c := range snmp6 {
			if title == "" || !strings.Contains(c.field, title) {
				if i := strings.IndexByte(c.field, '6'); i >= 0 {
					title = c.field[:i+1]
				} else {
					title = c.field
				}
				p.section(stat6Sections, title)
			}
			p.value(c.field, c.value)
		}
		for _, c := range snmp {
			if c.section == "Tcp" {
				if p.cur != "Tcp" {
					p.section(statSections, "Tcp")
				}
				p.value(c.field, c.value)
			}
		}
		return sb.String(), ts, nil
	}
	for _, c := range snmp {
		if c.section != p.cur {
			p.section(statSections, c.section)
		}
		p.value(c.field, c.value)
	}
	return sb.String(), ts, nil
}

type statPrinter struct {
	w     io.Writer
	shown func(filter string) bool
	cur   string
	table []statEntry
	known bool
	on    bool // this section's values are printed
	state statKind
}

func (p *statPrinter) section(sections map[string]statSection, title string) {
	p.cur = title
	if s, ok := sections[title]; ok {
		p.table, p.known, p.on, p.state = s.table, true, p.shown(s.filter), statNumber
	} else {
		// Unknown sections are always shown, and keep the indentation of the
		// section before them (net-tools resets it for known ones only).
		p.table, p.known, p.on = nil, false, true
	}
	if p.on {
		fmt.Fprintf(p.w, "%s:\n", title)
	}
}

func (p *statPrinter) value(name string, v uint64) {
	if !p.on {
		return
	}
	e, ok := statFind(p.table, name)
	if !ok {
		if v != 0 {
			fmt.Fprintf(p.w, "%*s%s: %d\n", p.state.indent(), "", name, v)
		}
		return
	}
	if e.static || e.text == "" {
		return
	}
	kind := e.kind
	if kind == statInICMP || kind == statOutICMP {
		if p.state != kind {
			fmt.Fprintf(p.w, "%*s%s\n", p.state.indent(), "", kind.title())
		}
	}
	line := ""
	switch kind {
	case statOptNumber:
		if v != 0 {
			line = fmt.Sprintf(e.text, v)
		}
	case statNumber:
		line = fmt.Sprintf(e.text, v)
	case statForward:
		kind = statNumber
		line = fmt.Sprintf(e.text, map[bool]string{true: "enabled", false: "disabled"}[v == 2])
	case statInICMP, statOutICMP:
		if v > 0 {
			line = fmt.Sprintf(e.text, v)
		}
	}
	if line != "" {
		fmt.Fprintf(p.w, "%*s%s\n", kind.indent(), "", line)
	}
	p.state = kind
}
