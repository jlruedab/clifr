package rtnl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ConntrackCPU is one CPU's connection tracking counters as ctnetlink
// sends them: CTA_STATS_* attribute numbers and values, in the message's
// order.
type ConntrackCPU struct {
	CPU   int
	Attrs [][2]uint32 // {type, value}
}

// ConntrackStats asks ctnetlink for the per-CPU counters (conntrack -S).
// It asks only when nf_conntrack_netlink is loaded: the request would load
// it (and nf_conntrack) otherwise, and the recorder must not change the
// kernel. ok is false then.
func ConntrackStats() (stats []ConntrackCPU, ok bool, err error) {
	if _, err := os.Stat("/sys/module/nf_conntrack_netlink"); err != nil {
		return nil, false, nil
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, false, fmt.Errorf("netfilter netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, false, err
	}
	const subsysCtnetlink, getStatsCPU = 1, 4 // NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_GET_STATS_CPU
	req := make([]byte, nlmsghdrLen+4)        // nlmsghdr, nfgenmsg
	ne := binary.NativeEndian
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], subsysCtnetlink<<8|getStatsCPU)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	ne.PutUint32(req[8:], 1)
	req[nlmsghdrLen] = unix.AF_UNSPEC
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, false, fmt.Errorf("netfilter netlink send: %w", err)
	}
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return stats, false, fmt.Errorf("netfilter netlink recv: %w", err)
		}
		done, err := messages(buf[:n], func(_ uint16, m []byte) {
			if len(m) < 4 {
				return
			}
			c := ConntrackCPU{CPU: int(binary.BigEndian.Uint16(m[2:]))} // nfgenmsg res_id
			Attrs(m, 4, func(t int, v []byte) {
				if len(v) >= 4 {
					c.Attrs = append(c.Attrs, [2]uint32{uint32(t & 0x3fff), binary.BigEndian.Uint32(v)})
				}
			})
			stats = append(stats, c)
		})
		if err != nil {
			return stats, false, err
		}
		if done {
			return stats, true, nil
		}
	}
}
