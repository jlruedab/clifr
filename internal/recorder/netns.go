package recorder

import (
	"slices"
	"time"

	"clifr/internal/sockdiag"
)

// Sockets of other network namespaces (containers, pods: the user,
// 2026-11-08). sock_diag lists the namespace of the socket asking, the
// host's, and entering another (setns) needs CAP_SYS_ADMIN, which the unit
// does not grant. A process's /proc/<pid>/net/{tcp,tcp6,udp,udp6} lists its
// namespace's sockets with what clifrd already has (CAP_SYS_PTRACE): one
// process per namespace, at each keyframe. Those lines have no IPv6-only
// flag, interface or listener backlog (ss's Send-Q of a listener).
//
// Cost (measured 2026-11-08): each TCP file read walks the kernel's whole
// established hash table, about 2 ms on a 64 GB machine however few sockets
// the namespace has (4 ms a namespace, tcp and tcp6); the UDP files take
// about 50 µs, and more under load (each walk visits every socket of every
// namespace). So the UDP files are read for every namespace at every
// keyframe (UDP has no events), and the TCP files only for a namespace with
// TCP connections open in the event state, and for the namespaces that
// existed at the run's first keyframe (connections older than clifrd, which
// no event announced) until each was read once; within netnsTCPBudget per
// keyframe, the least recently read first: the rest wait for the next
// keyframe. A namespace that appears later gets its connections through
// events (a desktop's browser makes one empty namespace per content process,
// a new one every few minutes: reading each once cost 100+ ms a keyframe,
// benchmark A/B 20261109-1047). Only queues (Recv-Q/Send-Q) and missed
// events wait.
const netnsTCPBudget = 100 * time.Millisecond

// otherNetNSSockets appends to list (the host's dump) the sockets of the
// other network namespaces processes were seen in, each marked with its
// namespace, and returns the namespaces whose TCP sockets the result covers
// (0, the host's, and each one whose TCP files were read): the keyframe
// judges only their connections.
func (r *Recorder) otherNetNSSockets(list []sockdiag.Socket) ([]sockdiag.Socket, map[uint32]bool) {
	t := r.tcp
	covered := map[uint32]bool{0: true}
	t.pendingFirst = map[uint32]bool{}
	byNS := map[uint32][]int{}
	for k, e := range r.procs {
		if ns := e.upd.NetNS; ns != 0 && !e.closed {
			byNS[ns] = append(byNS[ns], k.pid)
		}
	}
	if len(byNS) == 0 {
		return list, covered
	}
	if t.nsTCPRead == nil {
		t.nsTCPRead = map[uint32]int64{}
	}
	active := map[uint32]bool{} // namespaces with TCP connections open in the event state
	for _, c := range t.conns {
		active[c.row.NetNS] = true
	}
	for _, c := range t.unattached {
		active[c.row.NetNS] = true
	}
	if t.keyframes == 0 { // the namespaces that predate the run: each read once
		t.nsInitial = map[uint32]bool{}
		for ns := range byNS {
			t.nsInitial[ns] = true
		}
	}
	order := make([]uint32, 0, len(byNS))
	for ns := range byNS {
		order = append(order, ns)
	}
	// The least recently read TCP first (never read: 0), then by number.
	slices.SortFunc(order, func(a, b uint32) int {
		if x, y := t.nsTCPRead[a], t.nsTCPRead[b]; x != y {
			return int(x - y)
		}
		return int(int64(a) - int64(b))
	})
	start := time.Now()
	for _, ns := range order {
		wantTCP := (t.nsInitial[ns] || active[ns]) && time.Since(start) < netnsTCPBudget
		pids := byNS[ns]
		slices.Sort(pids) // the oldest process first: least likely to be gone
		for _, pid := range pids {
			// The process may have exited, its pid reused, or moved
			// (setns): read its namespace again.
			if n, err := r.fs.ReadNetNS(pid); err != nil || n != ns {
				continue
			}
			socks, err := sockdiag.ReadProcNetProtos(r.fs.PIDDir(pid), wantTCP, true)
			if err != nil {
				continue
			}
			for i := range socks {
				socks[i].NetNS = ns
			}
			list = append(list, socks...)
			if wantTCP {
				covered[ns] = true
				if t.nsTCPRead[ns] == 0 { // its first read: as a run's first keyframe for it
					t.pendingFirst[ns] = true
				}
				delete(t.nsInitial, ns)
				t.nsTCPRead[ns] = t.dumpSeq + 1 // 0: never read
				t.netnsRead++
			}
			break
		}
	}
	t.dumpSeq++
	for ns := range t.nsTCPRead { // namespaces gone
		if byNS[ns] == nil {
			delete(t.nsTCPRead, ns)
		}
	}
	for ns := range t.nsInitial {
		if byNS[ns] == nil {
			delete(t.nsInitial, ns)
		}
	}
	return list, covered
}
