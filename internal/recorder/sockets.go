package recorder

import (
	"net"
	"net/netip"

	"clifr/internal/procfs"
	"clifr/internal/sockdiag"
	"clifr/internal/store"
)

// sockKey identifies a socket. The inode alone is not enough: TIME-WAIT and
// SYN-RECV entries all have inode 0, and a socket's address can change
// (bind/connect), which we record as a new row.
type sockKey struct {
	proto        string
	inode        uint64
	laddr, raddr netip.Addr
	lport, rport int
}

type sockEntry struct {
	id        int64
	first     int64
	last      int64
	gen       uint64
	everOwned bool
	closed    bool
	sample    store.SockSample
	hasSamp   bool
}

type ownKey struct {
	sock, proc int64
	fd         int
}

type ownEntry struct {
	id   int64
	gen  uint64
	last int64
	sock *sockEntry
	proc *procEntry
}

// initSockets picks sock_diag, falling back to /proc/net/* if it fails.
// With a non-default --proc-root (fixtures) /proc/net under it is used.
func (r *Recorder) initSockets() {
	procNet := func() ([]sockdiag.Socket, error) { return sockdiag.ReadProcNet(r.fs.Root) }
	if r.fs.Root != "/proc" {
		r.listSockets, r.sockSource = procNet, "proc_net"
		return
	}
	if _, err := sockdiag.Dump(); err != nil {
		r.log.Warnf("sock_diag unavailable (%v), falling back to /proc/net (slower)", err)
		r.listSockets, r.sockSource = procNet, "proc_net"
		return
	}
	r.listSockets, r.sockSource = sockdiag.Dump, "sock_diag"
}

func (r *Recorder) sampleSockets(ts int64, b *store.Batch) int {
	list, err := r.listSockets()
	if err != nil {
		r.log.Errorf("list sockets: %v", err)
		return 0
	}
	for _, s := range list {
		k := sockKey{proto: s.Proto, inode: s.Inode, laddr: s.LAddr, raddr: s.RAddr, lport: s.LPort, rport: s.RPort}
		e := r.socks[k]
		if e == nil {
			e = &sockEntry{id: r.nextID("sockets"), first: ts}
			r.socks[k] = e
			if s.Inode != 0 {
				r.byInode[s.Inode] = e
			}
			b.SockInserts = append(b.SockInserts, store.SockRow{ID: e.id, Inode: s.Inode, Proto: s.Proto,
				Family: s.Family, LAddr: s.LAddr.String(), LPort: s.LPort, RAddr: s.RAddr.String(),
				RPort: s.RPort, IfName: ifName(s.IfIndex), UID: int(s.UID), FirstSeen: ts})
		}
		if e.gen == r.gen {
			continue // duplicate in one dump (a socket moved between hash buckets)
		}
		e.gen, e.last = r.gen, ts
		smp := store.SockSample{SockID: e.id, TS: ts, State: s.State, RxQ: int64(s.RxQ), TxQ: int64(s.TxQ)}
		if !e.hasSamp || smp.State != e.sample.State || smp.RxQ != e.sample.RxQ || smp.TxQ != e.sample.TxQ {
			b.SockSamples = append(b.SockSamples, smp)
			e.sample, e.hasSamp = smp, true
		}
	}
	for k, e := range r.socks {
		if e.gen != r.gen {
			b.SockCloses = append(b.SockCloses, store.Close{ID: e.id, LastSeen: e.last})
			e.closed = true
			delete(r.socks, k)
			if k.inode != 0 && r.byInode[k.inode] == e {
				delete(r.byInode, k.inode)
			}
		}
	}
	return len(list)
}

// observeOwners records the socket fds of one walked process.
func (r *Recorder) observeOwners(p *procEntry, fds []procfs.FD, ts int64, b *store.Batch) {
	p.owns = false
	for _, fd := range fds {
		ino, ok := procfs.SocketInode(fd.Target)
		if !ok {
			continue
		}
		s := r.byInode[ino]
		if s == nil {
			continue // unix, netlink, raw or other non-inet socket
		}
		p.owns = true
		k := ownKey{sock: s.id, proc: p.id, fd: fd.Num}
		o := r.owners[k]
		if o == nil {
			first := ts
			if !s.everOwned {
				// Nobody owned it at an earlier walk, so this process most
				// likely held it since the socket (or process) appeared.
				first = max(s.first, p.first)
			}
			o = &ownEntry{id: r.nextID("sock_owners"), sock: s, proc: p}
			r.owners[k] = o
			b.OwnInserts = append(b.OwnInserts, store.OwnerRow{ID: o.id, SockID: s.id, ProcID: p.id, FD: fd.Num, FirstSeen: first})
		}
		s.everOwned = true
		o.gen, o.last = r.gen, ts
	}
	p.walked = r.gen
}

// sweepOwners closes ownerships whose socket or process is gone, or whose
// process was walked in this sample without the fd.
func (r *Recorder) sweepOwners(ts int64, b *store.Batch) {
	for k, o := range r.owners {
		gone := o.sock.closed || o.proc.closed || (o.proc.walked == r.gen && o.gen != r.gen)
		if !gone {
			if o.gen != r.gen {
				o.last = ts // not re-walked this sample but still plausible: extend
			}
			continue
		}
		b.OwnCloses = append(b.OwnCloses, store.Close{ID: o.id, LastSeen: o.last})
		delete(r.owners, k)
	}
}

var ifNames = map[uint32]string{}

func ifName(idx uint32) string {
	if idx == 0 {
		return ""
	}
	if n, ok := ifNames[idx]; ok {
		return n
	}
	n := ""
	if i, err := net.InterfaceByIndex(int(idx)); err == nil {
		n = i.Name
	}
	ifNames[idx] = n
	return n
}
