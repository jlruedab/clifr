package query

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// mountstats.py's counter names (nfs-utils 2.3 to 2.6).
var (
	nfsEventCounters = []string{"inoderevalidates", "dentryrevalidates", "datainvalidates", "attrinvalidates", "vfsopen",
		"vfslookup", "vfspermission", "vfsupdatepage", "vfsreadpage", "vfsreadpages", "vfswritepage", "vfswritepages",
		"vfsreaddir", "vfssetattr", "vfsflush", "vfsfsync", "vfslock", "vfsrelease", "congestionwait", "setattrtrunc",
		"extendwrite", "sillyrenames", "shortreads", "shortwrites", "delay", "pnfsreads", "pnfswrites"}
	nfsByteCounters = []string{"normalreadbytes", "normalwritebytes", "directreadbytes", "directwritebytes",
		"serverreadbytes", "serverwritebytes", "readpages", "writepages"}
	xprtCounters = map[string][]string{
		"udp": {"port", "bind_count", "rpcsends", "rpcreceives", "badxids", "inflightsends", "backlogutil", "maxslots",
			"sendutil", "pendutil"},
		"tcp": {"port", "bind_count", "connect_count", "connect_time", "idle_time", "rpcsends", "rpcreceives", "badxids",
			"inflightsends", "backlogutil", "maxslots", "sendutil", "pendutil"},
		"rdma": {"port", "bind_count", "connect_count", "connect_time", "idle_time", "rpcsends", "rpcreceives", "badxids",
			"inflightsends", "backlogutil", "read_segments", "write_segments", "reply_segments", "total_rdma_req",
			"total_rdma_rep", "pullup", "fixup", "hardway", "failed_marshal", "bad_reply", "nomsg_calls", "recovered_mrs",
			"orphaned_mrs", "allocated_mrs", "local_invalidates", "empty_sendctx_q", "reply_waits_for_send"},
	}
	nfsv3Ops = []string{"NULL", "GETATTR", "SETATTR", "LOOKUP", "ACCESS", "READLINK", "READ", "WRITE", "CREATE", "MKDIR",
		"SYMLINK", "MKNOD", "REMOVE", "RMDIR", "RENAME", "LINK", "READDIR", "READDIRPLUS", "FSSTAT", "FSINFO", "PATHCONF",
		"COMMIT"}
	nfsv4Ops = []string{"NULL", "READ", "WRITE", "COMMIT", "OPEN", "OPEN_CONFIRM", "OPEN_NOATTR", "OPEN_DOWNGRADE", "CLOSE",
		"SETATTR", "FSINFO", "RENEW", "SETCLIENTID", "SETCLIENTID_CONFIRM", "LOCK", "LOCKT", "LOCKU", "ACCESS", "GETATTR",
		"LOOKUP", "LOOKUP_ROOT", "REMOVE", "RENAME", "LINK", "SYMLINK", "CREATE", "PATHCONF", "STATFS", "READLINK",
		"READDIR", "SERVER_CAPS", "DELEGRETURN", "GETACL", "SETACL", "FS_LOCATIONS", "RELEASE_LOCKOWNER", "SECINFO",
		"FSID_PRESENT", "EXCHANGE_ID", "CREATE_SESSION", "DESTROY_SESSION", "SEQUENCE", "GET_LEASE_TIME",
		"RECLAIM_COMPLETE", "LAYOUTGET", "GETDEVICEINFO", "LAYOUTCOMMIT", "LAYOUTRETURN", "SECINFO_NO_NAME",
		"TEST_STATEID", "FREE_STATEID", "GETDEVICELIST", "BIND_CONN_TO_SESSION", "DESTROY_CLIENTID", "SEEK", "ALLOCATE",
		"DEALLOCATE", "LAYOUTSTATS", "CLONE", "COPY", "OFFLOAD_CANCEL", "LOOKUPP", "LAYOUTERROR", "COPY_NOTIFY"}
)

// NFSMount is one NFS mount of /proc/self/mountstats as mountstats.py's
// DeviceData parses it.
type NFSMount struct {
	Export, MountPoint, FSType, StatVers string
	Age                                  int64
	Options, Caps, V4Flags               []string
	Flavor, PseudoFlavor                 int64
	HasPseudo                            bool
	Nfs                                  map[string]int64
	StatsVers                            string
	ProgVers, Protocol                   string
	Rpc                                  map[string]int64
	Ops                                  []string
	OpStats                              map[string][]int64
}

// MountstatsAt returns the NFS mounts as clifrd last read mountstats at or
// before t (every minute), in the file's order.
func MountstatsAt(db *store.DB, t int64, padOps bool) ([]NFSMount, error) {
	lines, _, ok, err := FileAt(db, "mountstats", t)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("mountstats: not recorded at %s (recorded since schema 9)", FormatMS(t))
	}
	var out []NFSMount
	var cur *NFSMount
	rpc := false
	for _, l := range lines {
		w := strings.Fields(l)
		if len(w) == 0 {
			continue
		}
		if w[0] == "device" && len(w) >= 8 {
			out = append(out, NFSMount{Export: w[1], MountPoint: w[4], FSType: w[7], Nfs: map[string]int64{},
				Rpc: map[string]int64{}, OpStats: map[string][]int64{}})
			cur, rpc = &out[len(out)-1], false
			if len(w) > 8 {
				cur.StatVers = w[8]
			}
			continue
		}
		if cur == nil {
			continue
		}
		atoi := func(s string) int64 { v, _ := strconv.ParseInt(s, 10, 64); return v }
		if !rpc && w[0] != "RPC" {
			switch w[0] {
			case "age:":
				cur.Age = atoi(w[1])
			case "opts:":
				cur.Options = strings.Split(strings.Join(w[1:], ""), ",")
			case "caps:":
				cur.Caps = strings.Split(strings.Join(w[1:], ""), ",")
			case "nfsv4:":
				cur.V4Flags = strings.Split(strings.Join(w[1:], ""), ",")
			case "sec:":
				keys := strings.Split(strings.Join(w[1:], ""), ",")
				_, f, _ := strings.Cut(keys[0], "=")
				cur.Flavor, cur.HasPseudo = atoi(f), true
				if cur.Flavor == 6 && len(keys) > 1 {
					_, p, _ := strings.Cut(keys[1], "=")
					cur.PseudoFlavor = atoi(p)
				}
			case "events:":
				for i, k := range nfsEventCounters {
					if i+1 < len(w) {
						cur.Nfs[k] = atoi(w[i+1])
					}
				}
			case "bytes:":
				for i, k := range nfsByteCounters {
					if i+1 < len(w) {
						cur.Nfs[k] = atoi(w[i+1])
					}
				}
			}
			continue
		}
		rpc = true
		switch w[0] {
		case "RPC":
			if len(w) > 5 {
				cur.StatsVers, cur.ProgVers = w[3], w[5]
			}
		case "xprt:":
			cur.Protocol = w[1]
			for i, k := range xprtCounters[w[1]] {
				if i+2 < len(w) {
					cur.Rpc[k] = atoi(w[i+2])
				}
			}
		case "per-op":
		default:
			op := strings.TrimSuffix(w[0], ":")
			var vals []int64
			for _, x := range w[1:] {
				vals = append(vals, atoi(x))
			}
			if padOps && len(vals) < 9 {
				vals = append(vals, 0)
			}
			cur.Ops = append(cur.Ops, op)
			cur.OpStats[op] = vals
		}
	}
	return out, nil
}

// MountstatsOptions: -n, -r, -x, -R (one report; the default without),
// the mount points asked for, and the recorded nfs-utils: V233 (RHEL 8's
// 2.3.3: no mount age, no error counts).
type MountstatsOptions struct {
	NFS, RPC, Xprt, Raw bool
	MountPoints         []string
	V233                bool
}

// pyTimedelta is str(datetime.timedelta(seconds=s)).
func pyTimedelta(s int64) string {
	d, s := s/86400, s%86400
	hms := fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	switch d {
	case 0:
		return hms
	case 1:
		return "1 day, " + hms
	}
	return fmt.Sprintf("%d days, %s", d, hms)
}

// PrintMountstats prints mountstats [-n|-r|-x|-R] [MOUNTPOINT...] as
// nfs-utils' mountstats.py does.
func PrintMountstats(w io.Writer, mounts []NFSMount, o MountstatsOptions) {
	byMP := map[string]*NFSMount{}
	var order []string
	for i := range mounts {
		m := &mounts[i]
		if m.FSType != "nfs" && m.FSType != "nfs4" {
			continue
		}
		if _, dup := byMP[m.MountPoint]; !dup {
			order = append(order, m.MountPoint)
		}
		byMP[m.MountPoint] = m // a later mount on the same point wins, at the first one's place
	}
	if len(o.MountPoints) > 0 {
		var asked []string
		for _, mp := range o.MountPoints {
			mp = strings.TrimSuffix(mp, "/")
			if mp == "" {
				mp = "/"
			}
			if _, ok := byMP[mp]; ok {
				asked = append(asked, mp)
			}
		}
		order = asked
	}
	if len(order) == 0 {
		fmt.Fprintln(w, "No NFS mount points were found")
		return
	}
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	for _, mp := range order {
		m := byMP[mp]
		header := func() { p("Stats for %s mounted on %s:\n\n", m.Export, m.MountPoint) }
		options := func() {
			p("  NFS mount options: %s\n", strings.Join(m.Options, ","))
			if !o.V233 {
				p("  NFS mount age: %s\n", pyTimedelta(m.Age))
			}
			p("  NFS server capabilities: %s\n", strings.Join(m.Caps, ","))
			if m.V4Flags != nil {
				p("  NFSv4 capability flags: %s\n", strings.Join(m.V4Flags, ","))
			}
			if m.HasPseudo {
				p("  NFS security flavor: %d  pseudoflavor: %d\n", m.Flavor, m.PseudoFlavor)
			}
		}
		n := m.Nfs
		events := func() {
			p("\nCache events:\n  data cache invalidated %d times\n  attribute cache invalidated %d times\n\n", n["datainvalidates"], n["attrinvalidates"])
			p("VFS calls:\n  VFS requested %d inode revalidations\n  VFS requested %d dentry revalidations\n\n", n["inoderevalidates"], n["dentryrevalidates"])
			p("  VFS called nfs_readdir() %d times\n  VFS called nfs_lookup() %d times\n  VFS called nfs_permission() %d times\n",
				n["vfsreaddir"], n["vfslookup"], n["vfspermission"])
			p("  VFS called nfs_file_open() %d times\n  VFS called nfs_file_flush() %d times\n  VFS called nfs_lock() %d times\n",
				n["vfsopen"], n["vfsflush"], n["vfslock"])
			p("  VFS called nfs_fsync() %d times\n  VFS called nfs_file_release() %d times\n\n", n["vfsfsync"], n["vfsrelease"])
			p("VM calls:\n  VFS called nfs_readpage() %d times\n  VFS called nfs_readpages() %d times\n", n["vfsreadpage"], n["vfsreadpages"])
			p("  VFS called nfs_writepage() %d times\n  VFS called nfs_writepages() %d times\n\n", n["vfswritepage"], n["vfswritepages"])
			p("Generic NFS counters:\n  File size changing operations:\n    truncating SETATTRs: %d  extending WRITEs: %d\n",
				n["setattrtrunc"], n["extendwrite"])
			p("  %d silly renames\n  short reads: %d  short writes: %d\n  NFSERR_DELAYs from server: %d\n",
				n["sillyrenames"], n["shortreads"], n["shortwrites"], n["delay"])
			p("  pNFS READs: %d\n  pNFS WRITEs: %d\n", n["pnfsreads"], n["pnfswrites"])
		}
		bytes := func() {
			p("\nNFS byte counts:\n  applications read %d bytes via read(2)\n  applications wrote %d bytes via write(2)\n",
				n["normalreadbytes"], n["normalwritebytes"])
			p("  applications read %d bytes via O_DIRECT read(2)\n  applications wrote %d bytes via O_DIRECT write(2)\n",
				n["directreadbytes"], n["directwritebytes"])
			p("  client read %d bytes via NFS READ\n  client wrote %d bytes via NFS WRITE\n", n["serverreadbytes"], n["serverwritebytes"])
		}
		r := m.Rpc
		sends := r["rpcsends"]
		generic := func() {
			p("RPC statistics:\n  %d RPC requests sent, %d RPC replies received (%d XIDs not found)\n", sends, r["rpcreceives"], r["badxids"])
			if sends != 0 {
				p("  average backlog queue length: %d\n", int64(float64(r["backlogutil"])/float64(sends)))
			}
		}
		opStats := func() {
			p("\n")
			ops := append([]string(nil), m.Ops...)
			first := func(op string) int64 {
				if s := m.OpStats[op]; len(s) > 0 {
					return s[0]
				}
				return 0
			}
			sort.SliceStable(ops, func(i, j int) bool { return first(ops[i]) > first(ops[j]) })
			for _, op := range ops {
				s := append([]int64{0}, m.OpStats[op]...) // python's [op] + stats: stats[1] is the count
				for len(s) < 9 {
					s = append(s, 0)
				}
				count := s[1]
				if count == 0 {
					continue
				}
				pct := 0.0
				if sends != 0 {
					pct = float64(count*100) / float64(sends)
				}
				p("%s:\n\t%d ops (%d%%) ", op, count, int64(pct))
				if retrans := s[2] - count; retrans != 0 {
					p("\t%d retrans (%d%%) ", retrans, int64(float64(retrans*100)/float64(count)))
					if o.V233 {
						p("\t%d major timeouts\n", s[3])
					} else {
						p("\t%d major timeouts", s[3])
					}
				} else if o.V233 {
					p("\n")
				}
				if !o.V233 {
					if len(s) >= 10 && s[9] != 0 {
						p("\t%d errors (%d%%)\n", s[9], int64(float64(s[9]*100)/float64(count)))
					} else {
						p("\n")
					}
				}
				p("\tavg bytes sent per op: %d\tavg bytes received per op: %d\n", int64(float64(s[4])/float64(count)), int64(float64(s[5])/float64(count)))
				p("\tbacklog wait: %f \tRTT: %f \ttotal execute time: %f (milliseconds)\n",
					float64(s[6])/float64(count), float64(s[7])/float64(count), float64(s[8])/float64(count))
			}
		}
		xprt := func() {
			div := func(a string) int64 { return int64(float64(r[a]) / float64(sends)) }
			switch m.Protocol {
			case "udp", "tcp":
				p("\tTransport protocol: %s\n\tSource port: %d\n\tBind count: %d\n", m.Protocol, r["port"], r["bind_count"])
				if m.Protocol == "tcp" {
					p("\tConnect count: %d\n\tConnect time: %d seconds\n\tIdle time: %d seconds\n", r["connect_count"], r["connect_time"], r["idle_time"])
				}
				p("\tRPC requests: %d\n\tRPC replies: %d\n\tXIDs not found: %d\n\tMax slots: %d\n", sends, r["rpcreceives"], r["badxids"], r["maxslots"])
				if sends != 0 {
					p("\tAvg backlog length: %d\n\tAvg send queue length: %d\n\tAvg pending queue length: %d\n",
						div("backlogutil"), div("sendutil"), div("pendutil"))
				}
			case "rdma":
				p("\tTransport protocol: rdma\n\tConnect count: %d\n\tConnect time: %d seconds\n\tIdle time: %d seconds\n",
					r["connect_count"], r["connect_time"], r["idle_time"])
				p("\tRPC requests: %d\n\tRPC replies: %d\n\tXIDs not found: %d\n", sends, r["rpcreceives"], r["badxids"])
				if sends != 0 {
					p("\tAvg backlog length: %d\n", div("backlogutil"))
				}
				p("\tRead segments: %d\n\tWrite segments: %d\n\tReply segments: %d\n", r["read_segments"], r["write_segments"], r["reply_segments"])
				p("\tRegistered: %d bytes\n\tRDMA received: %d bytes\n\tTotal pull-up: %d bytes\n\tTotal fix-up: %d bytes\n",
					r["total_rdma_req"], r["total_rdma_rep"], r["pullup"], r["fixup"])
				p("\tHardway allocations: %d bytes\n\tFailed marshals: %d\n\tBad replies: %d\n", r["hardway"], r["failed_marshal"], r["bad_reply"])
				for _, k := range [][2]string{{"nomsg_calls", "RDMA_NOMSG calls"}, {"allocated_mrs", "Allocated MRs"},
					{"recovered_mrs", "Recovered MRs"}, {"orphaned_mrs", "Orphaned MRs"}, {"local_invalidates", "Local Invalidates needed"},
					{"empty_sendctx_q", "Empty sendctx queue count"}, {"reply_waits_for_send", "Replies that waited for Send completion"}} {
					if v, ok := r[k[0]]; ok {
						p("\t%s: %d\n", k[1], v)
					}
				}
			}
		}
		raw := func() {
			p("device %s mounted on %s with fstype %s %s\n", m.Export, m.MountPoint, m.FSType, m.StatVers)
			p("\topts:\t%s\n\tage:\t%d\n\tcaps:\t%s\n", strings.Join(m.Options, ","), m.Age, strings.Join(m.Caps, ","))
			p("\tsec:\tflavor=%d,pseudoflavor=%d\n", m.Flavor, m.PseudoFlavor)
			vals := func(keys []string, src map[string]int64) string {
				var f []string
				for _, k := range keys {
					f = append(f, strconv.FormatInt(src[k], 10))
				}
				return strings.Join(f, " ")
			}
			p("\tevents:\t%s\n\tbytes:\t%s\n", vals(nfsEventCounters, n), vals(nfsByteCounters, n))
			sv, _ := strconv.ParseFloat(m.StatsVers, 64)
			p("\tRPC iostats version: %1.1f p/v: %s (nfs)\n", sv, m.ProgVers)
			p("\txprt:\t%s %s\n\tper-op statistics\n", m.Protocol, vals(xprtCounters[m.Protocol], r))
			_, vers, _ := strings.Cut(m.ProgVers, "/")
			opNames := nfsv4Ops
			if vers == "3" {
				opNames = nfsv3Ops
			} else if o.V233 {
				opNames = nfsv4Ops[:59] // 2.3.3 ends at CLONE
			}
			for _, op := range opNames {
				s, ok := m.OpStats[op]
				if !ok {
					continue
				}
				var f []string
				for _, v := range s {
					f = append(f, strconv.FormatInt(v, 10))
				}
				p("\t%12s: %s\n", op, strings.Join(f, " "))
			}
			p("\n")
		}
		switch {
		case o.NFS:
			header()
			options()
			events()
			bytes()
		case o.RPC:
			header()
			generic()
			opStats()
		case o.Raw:
			raw()
		case o.Xprt:
			header()
			xprt()
		default:
			header()
			options()
			bytes()
			generic()
			opStats()
		}
		p("\n")
	}
}
