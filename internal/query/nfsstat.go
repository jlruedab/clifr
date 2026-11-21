// Parts of this file follow nfs-utils' utils/nfsstat/nfsstat.c (GPL-2.0-or-later), used under the
// GPL-3.0: see LICENSING.md and packaging/notices/nfs-utils.txt.

package query

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// nfsstat's names of the NFS procedures and operations (nfs-utils 2.3 to
// 2.6: the same).
var (
	nfsv2Names = []string{"null", "getattr", "setattr", "root", "lookup", "readlink", "read", "wrcache", "write", "create",
		"remove", "rename", "link", "symlink", "mkdir", "rmdir", "readdir", "fsstat"}
	nfsv3Names = []string{"null", "getattr", "setattr", "lookup", "access", "readlink", "read", "write", "create", "mkdir",
		"symlink", "mknod", "remove", "rmdir", "rename", "link", "readdir", "readdirplus", "fsstat", "fsinfo", "pathconf", "commit"}
	nfsSrv4Names = []string{"null", "compound"}
	nfsClt4Names = []string{"null", "read", "write", "commit", "open", "open_conf", "open_noat", "open_dgrd", "close",
		"setattr", "fsinfo", "renew", "setclntid", "confirm", "lock", "lockt", "locku", "access", "getattr", "lookup",
		"lookup_root", "remove", "rename", "link", "symlink", "create", "pathconf", "statfs", "readlink", "readdir",
		"server_caps", "delegreturn", "getacl", "setacl", "fs_locations", "rel_lkowner", "secinfo", "fsid_present",
		"exchange_id", "create_session", "destroy_session", "sequence", "get_lease_time", "reclaim_comp", "layoutget",
		"getdevinfo", "layoutcommit", "layoutreturn", "secinfo_no", "test_stateid", "free_stateid", "getdevicelist",
		"bind_conn_to_ses", "destroy_clientid", "seek", "allocate", "deallocate", "layoutstats", "clone"}
	nfsSrv4OpNames = []string{"op0-unused", "op1-unused", "op2-future", "access", "close", "commit", "create", "delegpurge",
		"delegreturn", "getattr", "getfh", "link", "lock", "lockt", "locku", "lookup", "lookup_root", "nverify", "open",
		"openattr", "open_conf", "open_dgrd", "putfh", "putpubfh", "putrootfh", "read", "readdir", "readlink", "remove",
		"rename", "renew", "restorefh", "savefh", "secinfo", "setattr", "setcltid", "setcltidconf", "verify", "write",
		"rellockowner", "bc_ctl", "bind_conn", "exchange_id", "create_ses", "destroy_ses", "free_stateid", "getdirdeleg",
		"getdevinfo", "getdevlist", "layoutcommit", "layoutget", "layoutreturn", "secinfononam", "sequence", "set_ssv",
		"test_stateid", "want_deleg", "destroy_clid", "reclaim_comp", "allocate", "copy", "copy_notify", "deallocate",
		"ioadvise", "layouterror", "layoutstats", "offloadcancel", "offloadstatus", "readplus", "seek", "write_same"}
)

// nfsSizes are the sizes of nfsstat's value arrays by tag (the last slot
// is overwritten with the sum of what was read).
var (
	nfsSrvSizes = map[string]int{"net": 5, "rpc": 6, "rc": 9, "fh": 7, "io": 3, "ra": 13, "proc2": 20, "proc3": 24, "proc4": 4,
		"proc4ops": 73}
	nfsCltSizes = map[string]int{"net": 5, "rpc": 4, "proc2": 20, "proc3": 24, "proc4": 61}
)

// NFSStats are /proc/net/rpc/nfs (client) and nfsd (server) as nfsstat
// parses them; nil maps when the file did not exist.
type NFSStats struct {
	Server, Client map[string][]uint32
}

// NFSStatsAt returns the NFS counters as clifrd last read them at or before
// t (every minute).
func NFSStatsAt(db *store.DB, t int64) (*NFSStats, error) {
	parse := func(src string, sizes map[string]int) (map[string][]uint32, error) {
		lines, _, ok, err := FileAt(db, src, t)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("nfsstat: not recorded at %s (recorded since schema 9)", FormatMS(t))
		}
		if len(lines) == 0 {
			return nil, nil
		}
		out := map[string][]uint32{}
		for tag, n := range sizes {
			out[tag] = make([]uint32, n)
		}
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) == 0 {
				continue
			}
			vals, ok := out[f[0]]
			if !ok {
				continue
			}
			var total uint32
			for i := 0; i < len(vals) && i+1 < len(f); i++ {
				v, _ := strconv.ParseUint(f[i+1], 0, 32)
				vals[i] = uint32(v)
				total += vals[i]
			}
			vals[len(vals)-1] = total
		}
		return out, nil
	}
	srv, err := parse("rpc/nfsd", nfsSrvSizes)
	if err != nil {
		return nil, err
	}
	clt, err := parse("rpc/nfs", nfsCltSizes)
	if err != nil {
		return nil, err
	}
	return &NFSStats{Server: srv, Client: clt}, nil
}

// NFSStatOptions: -s, -c (both by default), -o all (or net, rpc, rc, fh, io,
// ra), -n (calls), -r (rpc), -2/-3/-4, -l (list).
type NFSStatOptions struct {
	Server, Client                  bool
	Net, RPC, RC, FH, IO, RA, Calls bool
	V2, V3, V4, List                bool
}

// PrintNFSStat prints nfsstat (nfs-utils 2.3 to 2.6). An error when
// neither file existed, as nfsstat exits with one.
func PrintNFSStat(w io.Writer, st *NFSStats, o NFSStatOptions) error {
	if !o.Server && !o.Client {
		o.Server, o.Client = true, true
	}
	if !(o.Net || o.RPC || o.RC || o.FH || o.IO || o.RA || o.Calls) {
		o.Calls, o.RPC = true, true
	}
	auto := !o.V2 && !o.V3 && !o.V4
	if o.Server && st.Server == nil {
		o.Server = false
		if !o.Client {
			return fmt.Errorf("Error: No Server Stats (/proc/net/rpc/nfsd: No such file or directory). ")
		}
	}
	if o.Client && st.Client == nil {
		if !o.Server {
			return fmt.Errorf("Error: No Client Stats (/proc/net/rpc/nfs: No such file or directory). ")
		}
		o.Client = false
	}
	numbers := func(hdr string, vals []uint32) {
		var b strings.Builder
		b.WriteString(hdr)
		for i, v := range vals {
			if i > 0 {
				b.WriteString("   ")
			}
			fmt.Fprintf(&b, "%-8d", v)
		}
		fmt.Fprintln(w, b.String())
		fmt.Fprintln(w)
	}
	calls := func(hdr string, names []string, info []uint32) {
		if o.List {
			var total uint64
			for _, v := range info[:len(names)] {
				total += uint64(v)
			}
			if total == 0 {
				return
			}
			fmt.Fprintf(w, "%13s %13s %8d \n", hdr, "total:", total)
			fmt.Fprintln(w, "------------- ------------- --------")
			for i, n := range names {
				if info[i] != 0 {
					fmt.Fprintf(w, "%13s %12s: %8d \n", hdr, n, info[i])
				}
			}
			fmt.Fprintln(w)
			return
		}
		fmt.Fprint(w, hdr)
		var total uint64
		for _, v := range info[:len(names)] {
			total += uint64(v)
		}
		if total == 0 {
			total = 1
		}
		for i := 0; i < len(names); i += 5 {
			var a, b strings.Builder
			for j := 0; j < 5 && i+j < len(names); j++ {
				fmt.Fprintf(&a, "%-17s", names[i+j])
				fmt.Fprintf(&b, "%-8d%3d%%     ", info[i+j], uint64(info[i+j])*100/total)
			}
			fmt.Fprintln(w, a.String())
			fmt.Fprintln(w, b.String())
		}
		fmt.Fprintln(w)
	}
	has := func(v []uint32) bool { return v[0] != 0 && v[len(v)-1] > v[0] }
	if o.Server {
		s := st.Server
		if !o.List {
			if o.Net {
				numbers("Server packet stats:\npackets    udp        tcp        tcpconn\n", s["net"][:4])
			}
			if o.RPC {
				numbers("Server rpc stats:\ncalls      badcalls   badfmt     badauth    badclnt\n", s["rpc"][:5])
			}
			if o.RC {
				numbers("Server reply cache:\nhits       misses     nocache\n", s["rc"][:3])
			}
			if o.IO {
				numbers("Server io stats:\nread       write\n", s["io"][:2])
			}
			if o.RA {
				numbers("Server read ahead cache:\nsize       0-10%      10-20%     20-30%     30-40%     40-50%     50-60%     60-70%     70-80%     80-90%     90-100%    notfound\n", s["ra"][:12])
			}
			if o.FH {
				fh := append([]uint32(nil), s["fh"]...)
				fh[3], fh[4] = fh[4], fh[3]
				fh[5] = fh[0] // 'stale' moved
				numbers("Server file handle cache:\nlookup     anon       ncachedir  ncachenondir  stale\n", fh[1:6])
			}
		}
		if o.Calls {
			hdr := map[bool][3]string{false: {"Server nfs v2:\n", "Server nfs v3:\n", "Server nfs v4:\n"},
				true: {"nfs v2 server", "nfs v3 server", "nfs v4 server"}}[o.List]
			if o.V2 || auto && has(s["proc2"]) {
				calls(hdr[0], nfsv2Names, s["proc2"][1:])
			}
			if o.V3 || auto && has(s["proc3"]) {
				calls(hdr[1], nfsv3Names, s["proc3"][1:])
			}
			if o.V4 || auto && has(s["proc4"]) {
				calls(hdr[2], nfsSrv4Names, s["proc4"][1:])
				if o.List {
					calls("nfs v4 servop", nfsSrv4OpNames, s["proc4ops"][1:])
				} else {
					calls("Server nfs v4 operations:\n", nfsSrv4OpNames, s["proc4ops"][1:])
				}
			}
		}
	}
	if o.Client {
		c := st.Client
		if !o.List {
			if o.Net {
				numbers("Client packet stats:\npackets    udp        tcp        tcpconn\n", c["net"][:4])
			}
			if o.RPC {
				numbers("Client rpc stats:\ncalls      retrans    authrefrsh\n", c["rpc"][:3])
			}
		}
		if o.Calls {
			hdr := map[bool][3]string{false: {"Client nfs v2:\n", "Client nfs v3:\n", "Client nfs v4:\n"},
				true: {"nfs v2 client", "nfs v3 client", "nfs v4 client"}}[o.List]
			if o.V2 || auto && has(c["proc2"]) {
				calls(hdr[0], nfsv2Names, c["proc2"][1:])
			}
			if o.V3 || auto && has(c["proc3"]) {
				calls(hdr[1], nfsv3Names, c["proc3"][1:])
			}
			if o.V4 || auto && has(c["proc4"]) {
				calls(hdr[2], nfsClt4Names, c["proc4"][1:])
			}
		}
	}
	return nil
}

// PrintNFSMounts prints nfsstat -m: each NFS mount from /proc/mounts with
// its options.
func PrintNFSMounts(w io.Writer, mounts []MountRow) {
	for _, m := range mounts {
		if m.FSType != "nfs" && m.FSType != "nfs4" {
			continue
		}
		fmt.Fprintf(w, "%s from %s\n Flags:\t%s\n\n", m.Point, m.Source, MountOptions(m.Options, m.SuperOptions))
	}
}
