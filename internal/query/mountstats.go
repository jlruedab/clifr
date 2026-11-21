package query

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// NFSMount is one NFS mount's section of /proc/self/mountstats, parsed.
// Counters keep the kernel's order: Events (27 on the kernels seen),
// Bytes (8), Xprt (the numbers after the protocol on the xprt line).
type NFSMount struct {
	Device       string   `json:"device"`
	MountPoint   string   `json:"mount_point"`
	FSType       string   `json:"fstype"`
	StatVers     string   `json:"statvers,omitempty"`
	Opts         string   `json:"opts"`
	AgeS         int64    `json:"age_s"`
	Caps         string   `json:"caps,omitempty"`
	NFSv4        string   `json:"nfsv4,omitempty"`
	Flavor       int64    `json:"flavor"`
	PseudoFlavor int64    `json:"pseudoflavor"`
	Events       []uint64 `json:"events"`
	Bytes        []uint64 `json:"bytes"`
	RPCStatVers  string   `json:"rpc_statvers,omitempty"`
	ProgVers     string   `json:"prog_vers,omitempty"` // "100003/3"
	ProgName     string   `json:"prog_name,omitempty"` // "nfs"
	XprtProto    string   `json:"xprt_proto,omitempty"`
	Xprt         []uint64 `json:"xprt,omitempty"`
	Ops          []NFSOp  `json:"ops"`
}

// NFSOp is one line of the per-op statistics. Fields is how many numbers
// the kernel printed (8 before the error count was added, 9 with it).
type NFSOp struct {
	Name      string `json:"name"`
	Ops       uint64 `json:"ops"`
	Trans     uint64 `json:"trans"`
	Timeouts  uint64 `json:"timeouts"`
	BytesSent uint64 `json:"bytes_sent"`
	BytesRecv uint64 `json:"bytes_recv"`
	QueueMS   uint64 `json:"queue_ms"`
	RTTMS     uint64 `json:"rtt_ms"`
	ExecMS    uint64 `json:"execute_ms"`
	Errors    uint64 `json:"errors"`
	Fields    int    `json:"-"`
}

func (o NFSOp) values() []uint64 {
	v := []uint64{o.Ops, o.Trans, o.Timeouts, o.BytesSent, o.BytesRecv, o.QueueMS, o.RTTMS, o.ExecMS, o.Errors}
	if o.Fields < len(v) {
		v = v[:o.Fields]
	}
	return v
}

// MountstatsAt returns the NFS mounts as clifrd last read them at or before t,
// in file order.
func MountstatsAt(db *store.DB, t int64) ([]NFSMount, error) {
	lines, _, ok, err := FileAt(db, "mountstats", t)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("mountstats: not recorded at %s (recorded since schema 9)", FormatMS(t))
	}
	return parseMountstats(lines), nil
}

func parseUints(ws []string) []uint64 {
	out := make([]uint64, 0, len(ws))
	for _, w := range ws {
		v, _ := strconv.ParseUint(w, 10, 64)
		out = append(out, v)
	}
	return out
}

// parseMountstats parses the recorded lines (trimmed, NFS sections only).
func parseMountstats(lines []string) []NFSMount {
	var out []NFSMount
	var m *NFSMount
	perOp := false
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		if f[0] == "device" && len(f) >= 8 {
			out = append(out, NFSMount{Device: f[1], MountPoint: f[4], FSType: f[7]})
			m = &out[len(out)-1]
			if len(f) > 8 {
				m.StatVers = strings.TrimPrefix(f[8], "statvers=")
			}
			perOp = false
			continue
		}
		if m == nil {
			continue
		}
		rest := strings.Join(f[1:], "")
		switch {
		case f[0] == "opts:":
			m.Opts = rest
		case f[0] == "age:" && len(f) > 1:
			m.AgeS, _ = strconv.ParseInt(f[1], 10, 64)
		case f[0] == "caps:":
			m.Caps = rest
		case f[0] == "nfsv4:":
			m.NFSv4 = rest
		case f[0] == "sec:":
			for _, kv := range strings.Split(rest, ",") {
				k, v, _ := strings.Cut(kv, "=")
				n, _ := strconv.ParseInt(v, 10, 64)
				switch k {
				case "flavor":
					m.Flavor = n
				case "pseudoflavor":
					m.PseudoFlavor = n
				}
			}
		case f[0] == "events:":
			m.Events = parseUints(f[1:])
		case f[0] == "bytes:":
			m.Bytes = parseUints(f[1:])
		case f[0] == "RPC" && len(f) >= 4 && f[1] == "iostats":
			// RPC iostats version: 1.1  p/v: 100003/3 (nfs)
			m.RPCStatVers = f[3]
			if len(f) >= 6 {
				m.ProgVers = f[5]
			}
			if len(f) >= 7 {
				m.ProgName = strings.Trim(f[6], "()")
			}
		case f[0] == "xprt:" && len(f) > 1:
			m.XprtProto, m.Xprt = f[1], parseUints(f[2:])
		case f[0] == "per-op":
			perOp = true
		case perOp && strings.HasSuffix(f[0], ":"):
			v := parseUints(f[1:])
			op := NFSOp{Name: strings.TrimSuffix(f[0], ":"), Fields: len(v)}
			for i, p := range []*uint64{&op.Ops, &op.Trans, &op.Timeouts, &op.BytesSent, &op.BytesRecv,
				&op.QueueMS, &op.RTTMS, &op.ExecMS, &op.Errors} {
				if i < len(v) {
					*p = v[i]
				}
			}
			m.Ops = append(m.Ops, op)
		}
	}
	return out
}

// MountstatsOptions: -n, -r, -x, -R (at most one), the mount points given,
// and V233 for nfs-utils 2.3.3's layout (RHEL 8).
type MountstatsOptions struct {
	NFS, RPC, Xprt, Raw bool
	MountPoints         []string
	V233                bool
}

// mountstatsV3Ops are the NFSv3 operations -R prints (in the kernel's order).
var mountstatsV3Ops = []string{"NULL", "GETATTR", "SETATTR", "LOOKUP", "ACCESS", "READLINK", "READ", "WRITE", "CREATE",
	"MKDIR", "SYMLINK", "MKNOD", "REMOVE", "RMDIR", "RENAME", "LINK", "READDIR", "READDIRPLUS", "FSSTAT", "FSINFO",
	"PATHCONF", "COMMIT"}

// mountstatsV4Ops are the NFSv4 operations -R prints: nfs-utils 2.3.3 knows
// them up to CLONE, 2.5.4 and 2.6.1 up to COPY_NOTIFY (the later kernels'
// GETXATTR ... READ_PLUS are left out by both).
var mountstatsV4Ops = []string{"NULL", "READ", "WRITE", "COMMIT", "OPEN", "OPEN_CONFIRM", "OPEN_NOATTR",
	"OPEN_DOWNGRADE", "CLOSE", "SETATTR", "FSINFO", "RENEW", "SETCLIENTID", "SETCLIENTID_CONFIRM", "LOCK", "LOCKT",
	"LOCKU", "ACCESS", "GETATTR", "LOOKUP", "LOOKUP_ROOT", "REMOVE", "RENAME", "LINK", "SYMLINK", "CREATE", "PATHCONF",
	"STATFS", "READLINK", "READDIR", "SERVER_CAPS", "DELEGRETURN", "GETACL", "SETACL", "FS_LOCATIONS",
	"RELEASE_LOCKOWNER", "SECINFO", "FSID_PRESENT", "EXCHANGE_ID", "CREATE_SESSION", "DESTROY_SESSION", "SEQUENCE",
	"GET_LEASE_TIME", "RECLAIM_COMPLETE", "LAYOUTGET", "GETDEVICEINFO", "LAYOUTCOMMIT", "LAYOUTRETURN",
	"SECINFO_NO_NAME", "TEST_STATEID", "FREE_STATEID", "GETDEVICELIST", "BIND_CONN_TO_SESSION", "DESTROY_CLIENTID",
	"SEEK", "ALLOCATE", "DEALLOCATE", "LAYOUTSTATS", "CLONE",
	// 2.5.4 and later:
	"COPY", "OFFLOAD_CANCEL", "LOOKUPP", "LAYOUTERROR", "COPY_NOTIFY"}

// mountstatsV4Ops233 is how many of mountstatsV4Ops 2.3.3 knows.
const mountstatsV4Ops233 = 59

// rawOps are the operations -R prints, in file order: for NFSv3 and v4
// only the names the tool knows (any other version: all).
func (m NFSMount) rawOps(v233 bool) []NFSOp {
	var known []string
	switch {
	case strings.HasSuffix(m.ProgVers, "/3"):
		known = mountstatsV3Ops
	case strings.HasSuffix(m.ProgVers, "/4"):
		known = mountstatsV4Ops
		if v233 {
			known = known[:mountstatsV4Ops233]
		}
	default:
		return m.Ops
	}
	set := make(map[string]bool, len(known))
	for _, k := range known {
		set[k] = true
	}
	var out []NFSOp
	for _, op := range m.Ops {
		if set[op.Name] {
			out = append(out, op)
		}
	}
	return out
}

// PrintMountstats prints mountstats [-n|-r|-x|-R] [MOUNTPOINT...]. False
// (the tool's exit status 1) when no NFS mount, or none of the mount points
// given, was found: then it prints "No NFS mount points were found".
func PrintMountstats(w io.Writer, mounts []NFSMount, o MountstatsOptions) bool {
	sel := mounts
	if len(o.MountPoints) > 0 {
		want := map[string]bool{}
		for _, p := range o.MountPoints {
			want[p] = true
		}
		sel = nil
		for _, m := range mounts {
			if want[m.MountPoint] {
				sel = append(sel, m)
			}
		}
	}
	if len(sel) == 0 {
		fmt.Fprintln(w, "No NFS mount points were found")
		return false
	}
	for _, m := range sel {
		switch {
		case o.Raw:
			printMountstatsRaw(w, m, o.V233)
		case o.Xprt:
			fmt.Fprintf(w, "Stats for %s mounted on %s:\n\n", m.Device, m.MountPoint)
			printMountstatsXprt(w, m)
			fmt.Fprintln(w)
		case o.RPC:
			fmt.Fprintf(w, "Stats for %s mounted on %s:\n\n", m.Device, m.MountPoint)
			printMountstatsRPC(w, m)
			fmt.Fprintln(w)
		case o.NFS:
			fmt.Fprintf(w, "Stats for %s mounted on %s:\n\n", m.Device, m.MountPoint)
			printMountstatsMount(w, m, o.V233)
			fmt.Fprintln(w)
			printMountstatsEvents(w, m)
			printMountstatsBytes(w, m)
			fmt.Fprintln(w)
		default:
			fmt.Fprintf(w, "Stats for %s mounted on %s:\n\n", m.Device, m.MountPoint)
			printMountstatsMount(w, m, o.V233)
			fmt.Fprintln(w)
			printMountstatsBytes(w, m)
			printMountstatsRPC(w, m)
			fmt.Fprintln(w)
		}
	}
	return true
}

// msAt is the i-th value of a counter list, 0 when the kernel did not print it.
func msAt(v []uint64, i int) uint64 {
	if i < len(v) {
		return v[i]
	}
	return 0
}

// msDiv is the integer quotient (rounded down), 0 for a zero divisor.
func msDiv(a, b uint64) uint64 {
	if b == 0 {
		return 0
	}
	return a / b
}

// mountAge is the age like "3 days, 2:00:05" or "0:00:00" (hours not padded).
func mountAge(s int64) string {
	d, s := s/86400, s%86400
	hms := fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	switch {
	case d == 1:
		return "1 day, " + hms
	case d != 0:
		return fmt.Sprintf("%d days, %s", d, hms)
	}
	return hms
}

// pseudoFlavor is the pseudoflavor printed: 0 for flavor 1 (AUTH_UNIX)
// although the kernel prints 1 there, as every golden output shows.
// Other flavors were not seen: their recorded value is printed.
func (m NFSMount) pseudoFlavor() int64 {
	if m.Flavor == 1 {
		return 0
	}
	return m.PseudoFlavor
}

// printMountstatsMount prints the options block: the values are the words of
// the kernel's line run together ("pnfs=not configured" becomes
// "pnfs=notconfigured"); 2.3.3 prints no age; the NFSv4 line only for v4.
func printMountstatsMount(w io.Writer, m NFSMount, v233 bool) {
	fmt.Fprintf(w, "  NFS mount options: %s\n", m.Opts)
	if !v233 {
		fmt.Fprintf(w, "  NFS mount age: %s\n", mountAge(m.AgeS))
	}
	fmt.Fprintf(w, "  NFS server capabilities: %s\n", m.Caps)
	if m.NFSv4 != "" {
		fmt.Fprintf(w, "  NFSv4 capability flags: %s\n", m.NFSv4)
	}
	fmt.Fprintf(w, "  NFS security flavor: %d  pseudoflavor: %d\n", m.Flavor, m.pseudoFlavor())
}

// printMountstatsEvents prints -n's event counters, picked from the events
// line by position.
func printMountstatsEvents(w io.Writer, m NFSMount) {
	e := func(i int) uint64 { return msAt(m.Events, i) }
	fmt.Fprintf(w, "Cache events:\n  data cache invalidated %d times\n  attribute cache invalidated %d times\n\n", e(2), e(3))
	fmt.Fprintf(w, "VFS calls:\n  VFS requested %d inode revalidations\n  VFS requested %d dentry revalidations\n\n", e(0), e(1))
	for _, c := range []struct {
		name string
		i    int
	}{{"nfs_readdir", 12}, {"nfs_lookup", 5}, {"nfs_permission", 6}, {"nfs_file_open", 4}, {"nfs_file_flush", 14},
		{"nfs_lock", 16}, {"nfs_fsync", 15}, {"nfs_file_release", 17}} {
		fmt.Fprintf(w, "  VFS called %s() %d times\n", c.name, e(c.i))
	}
	fmt.Fprintln(w, "\nVM calls:")
	for _, c := range []struct {
		name string
		i    int
	}{{"nfs_readpage", 8}, {"nfs_readpages", 9}, {"nfs_writepage", 10}, {"nfs_writepages", 11}} {
		fmt.Fprintf(w, "  VFS called %s() %d times\n", c.name, e(c.i))
	}
	fmt.Fprintf(w, "\nGeneric NFS counters:\n  File size changing operations:\n    truncating SETATTRs: %d  extending WRITEs: %d\n", e(19), e(20))
	fmt.Fprintf(w, "  %d silly renames\n  short reads: %d  short writes: %d\n  NFSERR_DELAYs from server: %d\n", e(21), e(22), e(23), e(24))
	fmt.Fprintf(w, "  pNFS READs: %d\n  pNFS WRITEs: %d\n\n", e(25), e(26))
}

// printMountstatsBytes prints the first six counters of the bytes line.
func printMountstatsBytes(w io.Writer, m NFSMount) {
	b := func(i int) uint64 { return msAt(m.Bytes, i) }
	fmt.Fprintln(w, "NFS byte counts:")
	fmt.Fprintf(w, "  applications read %d bytes via read(2)\n", b(0))
	fmt.Fprintf(w, "  applications wrote %d bytes via write(2)\n", b(1))
	fmt.Fprintf(w, "  applications read %d bytes via O_DIRECT read(2)\n", b(2))
	fmt.Fprintf(w, "  applications wrote %d bytes via O_DIRECT write(2)\n", b(3))
	fmt.Fprintf(w, "  client read %d bytes via NFS READ\n", b(4))
	fmt.Fprintf(w, "  client wrote %d bytes via NFS WRITE\n", b(5))
}

// xprtFields are the positions of the xprt line's counters after the
// protocol: sends, receives, bad XIDs, backlog, max slots, sending and
// pending (summed queue lengths). tcp and rdma begin with source port, bind
// count, connect count, connect time and idle time; udp only with the port
// and the bind count. Only tcp was seen in the goldens.
type xprtFields struct {
	sends, recvs, badXids, bklog, maxSlots, sending, pending int
	tcp                                                      bool
}

func (m NFSMount) xprtFields() xprtFields {
	if m.XprtProto == "udp" {
		return xprtFields{sends: 2, recvs: 3, badXids: 4, bklog: 6, maxSlots: 7, sending: 8, pending: 9}
	}
	return xprtFields{sends: 5, recvs: 6, badXids: 7, bklog: 9, maxSlots: 10, sending: 11, pending: 12, tcp: true}
}

// printMountstatsRPC prints the RPC summary and the operations with at least
// one call, most calls first (equal counts in the kernel's order). An
// operation's share is its calls in percent of the RPC requests sent, its
// errors' in percent of its calls (both rounded down, so they can pass
// 100%); the byte averages are rounded down, the times per call printed
// with six decimals.
func printMountstatsRPC(w io.Writer, m NFSMount) {
	x := m.xprtFields()
	sends := msAt(m.Xprt, x.sends)
	fmt.Fprintln(w, "RPC statistics:")
	fmt.Fprintf(w, "  %d RPC requests sent, %d RPC replies received (%d XIDs not found)\n",
		sends, msAt(m.Xprt, x.recvs), msAt(m.Xprt, x.badXids))
	fmt.Fprintf(w, "  average backlog queue length: %d\n\n", msDiv(msAt(m.Xprt, x.bklog), sends))
	ops := make([]NFSOp, 0, len(m.Ops))
	for _, op := range m.Ops {
		if op.Ops > 0 {
			ops = append(ops, op)
		}
	}
	// a stable insertion sort, most calls first
	for i := 1; i < len(ops); i++ {
		for j := i; j > 0 && ops[j].Ops > ops[j-1].Ops; j-- {
			ops[j], ops[j-1] = ops[j-1], ops[j]
		}
	}
	for _, op := range ops {
		fmt.Fprintf(w, "%s:\n", op.Name)
		fmt.Fprintf(w, "\t%d ops (%d%%) ", op.Ops, msDiv(op.Ops*100, sends))
		if op.Errors > 0 {
			fmt.Fprintf(w, "\t%d errors (%d%%)", op.Errors, msDiv(op.Errors*100, op.Ops))
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "\tavg bytes sent per op: %d\tavg bytes received per op: %d\n",
			op.BytesSent/op.Ops, op.BytesRecv/op.Ops)
		n := float64(op.Ops)
		fmt.Fprintf(w, "\tbacklog wait: %f \tRTT: %f \ttotal execute time: %f (milliseconds)\n",
			float64(op.QueueMS)/n, float64(op.RTTMS)/n, float64(op.ExecMS)/n)
	}
}

// printMountstatsXprt prints -x: the xprt line's counters by name, the
// average queue lengths as the summed lengths per request sent (rounded
// down).
func printMountstatsXprt(w io.Writer, m NFSMount) {
	x := m.xprtFields()
	v := func(i int) uint64 { return msAt(m.Xprt, i) }
	sends := v(x.sends)
	fmt.Fprintf(w, "\tTransport protocol: %s\n", m.XprtProto)
	fmt.Fprintf(w, "\tSource port: %d\n", v(0))
	fmt.Fprintf(w, "\tBind count: %d\n", v(1))
	if x.tcp {
		fmt.Fprintf(w, "\tConnect count: %d\n", v(2))
		fmt.Fprintf(w, "\tConnect time: %d seconds\n", v(3))
		fmt.Fprintf(w, "\tIdle time: %d seconds\n", v(4))
	}
	fmt.Fprintf(w, "\tRPC requests: %d\n", sends)
	fmt.Fprintf(w, "\tRPC replies: %d\n", v(x.recvs))
	fmt.Fprintf(w, "\tXIDs not found: %d\n", v(x.badXids))
	fmt.Fprintf(w, "\tMax slots: %d\n", v(x.maxSlots))
	fmt.Fprintf(w, "\tAvg backlog length: %d\n", msDiv(v(x.bklog), sends))
	fmt.Fprintf(w, "\tAvg send queue length: %d\n", msDiv(v(x.sending), sends))
	fmt.Fprintf(w, "\tAvg pending queue length: %d\n", msDiv(v(x.pending), sends))
}

func joinUints(v []uint64) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.FormatUint(n, 10)
	}
	return strings.Join(s, " ")
}

// printMountstatsRaw prints -R: the section rebuilt from what was parsed.
// impl_id and nfsv4 lines are not printed, words are separated by one space
// (no trailing space after the counters), the pseudoflavor as in the
// options block, each operation's name right-aligned in 12 columns and only
// the operations the tool knows (rawOps); two empty lines after each mount.
func printMountstatsRaw(w io.Writer, m NFSMount, v233 bool) {
	dev := fmt.Sprintf("device %s mounted on %s with fstype %s", m.Device, m.MountPoint, m.FSType)
	if m.StatVers != "" {
		dev += " statvers=" + m.StatVers
	}
	fmt.Fprintln(w, dev)
	fmt.Fprintf(w, "\topts:\t%s\n", m.Opts)
	fmt.Fprintf(w, "\tage:\t%d\n", m.AgeS)
	fmt.Fprintf(w, "\tcaps:\t%s\n", m.Caps)
	fmt.Fprintf(w, "\tsec:\tflavor=%d,pseudoflavor=%d\n", m.Flavor, m.pseudoFlavor())
	fmt.Fprintf(w, "\tevents:\t%s\n", joinUints(m.Events))
	fmt.Fprintf(w, "\tbytes:\t%s\n", joinUints(m.Bytes))
	if m.RPCStatVers != "" {
		fmt.Fprintf(w, "\tRPC iostats version: %s p/v: %s (%s)\n", m.RPCStatVers, m.ProgVers, m.ProgName)
		fmt.Fprintf(w, "\txprt:\t%s %s\n", m.XprtProto, joinUints(m.Xprt))
		fmt.Fprintln(w, "\tper-op statistics")
		for _, op := range m.rawOps(v233) {
			fmt.Fprintf(w, "\t%12s: %s\n", op.Name, joinUints(op.values()))
		}
	}
	fmt.Fprint(w, "\n\n")
}
