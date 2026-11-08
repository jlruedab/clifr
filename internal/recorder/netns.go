package recorder

import (
	"slices"

	"clifr/internal/sockdiag"
)

// Sockets of other network namespaces (containers, pods: the user,
// 2026-11-08). sock_diag lists the namespace of the socket asking, the
// host's, and entering another (setns) needs CAP_SYS_ADMIN, which the unit
// does not grant. A process's /proc/<pid>/net/{tcp,tcp6,udp,udp6} lists its
// namespace's sockets with what clifrd already has (CAP_SYS_PTRACE): one
// process per namespace, at each keyframe. Those lines have no IPv6-only
// flag, interface or listener backlog (ss's Send-Q of a listener).

// otherNetNSSockets appends to list (the host's dump) the sockets of every
// other network namespace a process was seen in, each marked with its
// namespace, and returns the namespaces the result covers (0, the host's,
// and each one read). A namespace whose processes are gone, or that cannot
// be read, is left out: the keyframe then does not judge its connections.
func (r *Recorder) otherNetNSSockets(list []sockdiag.Socket) ([]sockdiag.Socket, map[uint32]bool) {
	covered := map[uint32]bool{0: true}
	byNS := map[uint32][]int{}
	for k, e := range r.procs {
		if ns := e.upd.NetNS; ns != 0 && !e.closed {
			byNS[ns] = append(byNS[ns], k.pid)
		}
	}
	for ns, pids := range byNS {
		slices.Sort(pids) // the oldest process first: least likely to be gone
		for _, pid := range pids {
			// The process may have exited, its pid reused, or moved
			// (setns): read its namespace again.
			if n, err := r.fs.ReadNetNS(pid); err != nil || n != ns {
				continue
			}
			socks, err := sockdiag.ReadProcNet(r.fs.PIDDir(pid))
			if err != nil {
				continue
			}
			for i := range socks {
				socks[i].NetNS = ns
			}
			list = append(list, socks...)
			covered[ns] = true
			r.tcp.netnsRead++
			break
		}
	}
	return list, covered
}
