package duck

import (
	"database/sql"
	"flag"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"clifr/internal/pqstore"
	"clifr/internal/store"
)

func p64(v int64) *int64 { return &v }
func pint(v int) *int    { return &v }

// batches is a small recording: a process with a socket and a file, an
// event-only process, an update, then everything closes.
func batches() []*store.Batch {
	return []*store.Batch{
		{
			Sample:      store.Sample{TS: 1000, FDWalk: true, NProc: 1, Rows: 5, CPUUS: 10},
			ProcInserts: []store.ProcRow{{ID: 101, PID: 10, StartTime: 900, PPID: 1, Comm: "srv", Cmdline: "srv -x", FirstSeen: 1000, Source: "sample"}},
			ProcSamples: []store.ProcSample{{ProcID: 101, TS: 1000, State: "S", CPUTicks: 5, RSSKB: 100, VSZKB: 200, Threads: 2, RChar: 7, ReadBytes: 4096, WriteBytes: 8192,
				MinFlt: 11, MajFlt: 2, ShrKB: 40, Priority: -51, Policy: 1, RTPriority: 50, CPU: 3, PSFlags: 5, VolCtx: 9, NonVolCtx: 4, Wchan: "do_epoll_wait"}},
			SockInserts: []store.SockRow{{ID: 201, Inode: 555, Proto: "tcp", Family: 4, LAddr: "127.0.0.1", LPort: 80, RAddr: "127.0.0.2", RPort: 4000, FirstSeen: 1000}},
			SockSamples: []store.SockSample{{SockID: 201, TS: 1000, State: 1}},
			OwnInserts:  []store.OwnerRow{{ID: 301, SockID: 201, ProcID: 101, FD: 3, FirstSeen: 1000}},
			FileInserts: []store.FileRow{{ID: 401, ProcID: 101, FD: 4, Target: "/var/log/x (deleted)", Deleted: true, FType: "REG", Mode: "w", Node: 77, FirstSeen: 1000}},
			Guard:       []store.GuardEvent{{TS: 1000, Kind: "skip", Detail: "d"}},
			Verify:      []store.VerifySnap{{TS: 1001, EndTS: 1002, Cmd: "ps aux", SampleTS: 1000, Output: "USER PID"}},
			Sys: []store.SysSample{{TS: 1000, UptimeMS: 500, Load1: 149, Threads: 7, Ctxt: 1 << 40, MemTotal: 8000000, PgMajFault: 3,
				SockUsed: 1417, TCPAlloc: 46, TCPTW: 2, UDPInUse: 13, TCP6InUse: 4, Frag6Memory: 5}},
			CPUs:  []store.CPUSample{{TS: 1000, CPU: -1, T: [10]int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}, {TS: 1000, CPU: 0, T: [10]int64{1, 2, 3, 4}}},
			Disks: []store.DiskSample{{TS: 1000, Major: 259, Minor: 1, Name: "nvme0n1p1", Part: true, V: [17]int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}}},
		},
		{
			Sample: store.Sample{TS: 2000, NProc: 2, Rows: 3, CPUUS: 20},
			Skips:  []int64{1500},
			ProcInserts: []store.ProcRow{{ID: 102, PID: 11, StartTime: 1600, PPID: 10, Comm: "sh", Cmdline: "sh -c true", FirstSeen: 1600,
				LastSeen: p64(1700), Ended: p64(1700), Source: "ebpf", Exe: "/bin/sh", ExecTS: p64(1600), ExitTS: p64(1700), ExitCode: pint(3)}},
			ProcUpdates: []store.ProcUpdate{{ID: 101, UID: 5, PPID: 1, Comm: "srv", Cmdline: "srv -y", Source: "sample", Exe: "/usr/bin/srv", ExecTS: 1900,
				Label: "unconfined", Cgroup: "0::/system.slice/srv.service"}},
			ProcExits:   []store.ProcExit{{ID: 101, OOMKilled: true}},
			OOMEvents:   []store.OOMEvent{{TS: 1950, PID: 10, StartTime: 900, Comm: "srv", RSSKB: 4000, Snapshot: true}},
			Stats:       []store.StatRow{{TS: 2000, Source: "ebpf_exec", Events: 7, Dropped: 1}},
			TCPConns: []store.TCPConn{
				{ID: 501, PID: 10, StartTime: 900, FD: 5, Inode: 777, Family: 4, LAddr: ip("127.0.0.1"), LPort: 4000, RAddr: ip("127.0.0.2"),
					RPort: 80, Direction: store.DirActive, OpenTS: 1500, FirstState: 2, Source: store.SrcEBPF, LastSeen: 1500},
				{ID: 502, PID: 10, StartTime: 900, FD: -1, Family: 4, LAddr: ip("127.0.0.1"), LPort: 4001, RAddr: ip("127.0.0.2"),
					RPort: 80, Direction: store.DirActive, OpenTS: 1600, CloseTS: 1650, FinalState: 2, ResetsReceived: 1, Source: store.SrcEBPF, LastSeen: 1650},
			},
			TCPTrans:    []store.TCPTransition{{ConnID: 501, TS: 1500, Old: 7, New: 2}, {ConnID: 501, TS: 1501, Old: 2, New: 1}},
			Keyframes:   []store.KeyframeRow{{TS: 2000, Proto: store.ProtoTCP, Family: 4, LAddr: ip("127.0.0.1"), LPort: 4000, RAddr: ip("127.0.0.2"), RPort: 80, Inode: 777, State: 1, RecvQ: 3, ConnID: 501, PID: 10, StartTime: 900, FD: 5}},
			HeldInserts: []store.HeldFD{{ID: 601, PID: 10, StartTime: 900, FD: 4, Target: "/var/log/x (deleted)", Deleted: true, FType: "REG", Mode: "w", Node: 77, FirstSeen: 1000}},
			Mounts: []store.MountEvent{{TS: 1000, Action: "present", MountID: 22, Point: "/", Source: "/dev/sda", FSType: "ext4", Options: "rw",
				SuperOptions: "rw,errors=remount-ro", Dev: "8:1", Root: "/", Seq: 0},
				{TS: 1700, Action: "mount", MountID: 95, Point: "/mnt", Source: "tmpfs", FSType: "tmpfs", Options: "rw", Seq: 1}},
			FSSamples:   []store.FSSample{{TS: 1000, MountID: 22, FrSize: 4096, Blocks: 100, BFree: 40, BAvail: 30, Files: 64, FFree: 10}},
			Reconcile:   []store.ReconcileRow{{TS: 2000, Kind: "tcp", DumpRows: 1, MissingFromEvents: 0, ExtraInEvents: 0}},
			ProcSamples: []store.ProcSample{{ProcID: 101, TS: 2000, State: "R", CPUTicks: 9, RSSKB: 120, VSZKB: 200, Threads: 2}},
			SockSamples: []store.SockSample{{SockID: 201, TS: 2000, State: 8, RxQ: 1}},
		},
	}
}

func ip(s string) store.Addr { return store.AddrOf(netip.MustParseAddr(s)) }

func shutdown() *store.Batch {
	return &store.Batch{
		ProcCloses: []store.Close{{ID: 101, LastSeen: 2000, Ended: p64(2500)}},
		ProcExits:  []store.ProcExit{{ID: 101, ExitTS: p64(2500), Signal: pint(9)}},
		TCPConns: []store.TCPConn{{ID: 501, PID: 10, StartTime: 900, FD: 5, OwnerUntil: 2400, Inode: 777, Family: 4, LAddr: ip("127.0.0.1"),
			LPort: 4000, RAddr: ip("127.0.0.2"), RPort: 80, Direction: store.DirActive, OpenTS: 1500, CloseTS: 2450, FirstState: 2,
			FinalState: 5, LingerState: 6, LingerUntil: 62450, Retransmits: 2, Source: store.SrcEBPF, LastSeen: 2450}},
		SockCloses: []store.Close{{ID: 201, LastSeen: 2000}},
		OwnCloses:  []store.Close{{ID: 301, LastSeen: 2000}},
		FileCloses: []store.Close{{ID: 401, LastSeen: 1000}},
		HeldCloses: []store.Close{{ID: 601, LastSeen: 1000}},
	}
}

// dump renders a table sorted, with NULLs visible.
func dump(t *testing.T, db *sql.DB, table, cols string) string {
	t.Helper()
	rows, err := db.Query(`SELECT ` + cols + ` FROM ` + table + ` ORDER BY ` + strings.Split(cols, ",")[0] + `, 2`)
	if err != nil {
		t.Fatalf("%s: %v", table, err)
	}
	defer rows.Close()
	n := len(strings.Split(cols, ","))
	var out []string
	for rows.Next() {
		v := make([]any, n)
		p := make([]any, n)
		for i := range v {
			p[i] = &v[i]
		}
		if err := rows.Scan(p...); err != nil {
			t.Fatal(err)
		}
		f := make([]string, n)
		for i := range v {
			f[i] = fmt.Sprint(v[i])
		}
		out = append(out, strings.Join(f, " | "))
	}
	return strings.Join(out, "\n")
}

var compare = map[string]string{
	"samples":          "ts, fd_walk, skipped, nproc, rows, cpu_us",
	"processes":        "id, pid, start_time, ppid, uid, comm, cmdline, first_seen, last_seen, ended, source, exe, exec_ts, exit_ts, exit_code, signal, oom_killed, label, cgroup",
	"oom_events":       "ts, pid, start_time, comm, rss_kb, snapshot",
	"recorder_stats":   "ts, source, events, dropped",
	"tcp_conns":        "id, pid, start_time, fd, owner_until, inode, laddr, lport, raddr, rport, direction, open_ts, close_ts, first_state, final_state, linger_state, linger_until, retransmits, resets_sent, resets_received, source",
	"fds_held":         "id, pid, start_time, fd, target, deleted, ftype, mode, name, node, first_seen, last_seen",
	"mounts":           "ts, action, mount_id, mount_point, source, fstype, options, super_options, dev, root, seq, loop_file, user_options",
	"tcp_transitions":  "conn_id, ts, seq, old_state, new_state",
	"tcp_keyframes":    "ts, proto, laddr, lport, inode, state, recv_q, conn_id, pid, fd",
	"reconcile":        "ts, kind, dump_rows, missing_from_events, extra_in_events",
	"proc_samples":     "proc_id, ts, state, cpu_ticks, rss_kb, vsz_kb, threads, rchar, read_bytes, write_bytes, min_flt, maj_flt, shr_kb, priority, policy, rt_priority, processor, ps_flags, vol_ctx, nonvol_ctx, wchan",
	"sockets":          "id, inode, proto, family, laddr, lport, raddr, rport, first_seen, last_seen",
	"sock_samples":     "sock_id, ts, state, rxq, txq",
	"sock_owners":      "id, sock_id, proc_id, fd, first_seen, last_seen",
	"open_files":       "id, proc_id, fd, target, deleted, ftype, mode, name, node, first_seen, last_seen",
	"guard_events":     "ts, kind, detail",
	"verify_snapshots": "ts, end_ts, cmd, sample_ts, output",
	"meta":             "key, value",
	"sys_samples":      "ts, uptime_ms, load1, threads, ctxt, mem_total, pgmajfault, sock_used, tcp_alloc, tcp_tw, udp_inuse, tcp6_inuse, frag6_memory",
	"cpu_samples":      "ts, cpu, user, nice, system, idle, guest_nice",
	"disk_samples":     "ts, major, minor, name, part, rd_ios, time_in_queue, fl_ticks",
	"fs_samples":       "ts, mount_id, frsize, blocks, bfree, bavail, files, ffree",
}

var update = flag.Bool("update", false, "rewrite testdata/roundtrip.golden")

// The batches written to Parquet, with a mid-run flush (the open file, then
// closed rows replace it), read back through DuckDB: every table as in
// testdata/roundtrip.golden (go test -run RoundTrip -update rewrites it).
func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pq, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	pq.SetMeta("interval_s", "30")
	for _, x := range batches() {
		if err := pq.Write(x); err != nil {
			t.Fatal(err)
		}
	}
	pq.Flush()
	if err := pq.Write(shutdown()); err != nil {
		t.Fatal(err)
	}
	if err := pq.Close(); err != nil {
		t.Fatal(err)
	}
	dk, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer dk.Close()
	var sb strings.Builder
	for _, table := range slices.Sorted(maps.Keys(compare)) {
		if _, err := dk.Prepare(table); err != nil { // tables load when a query names them
			t.Fatal(err)
		}
		d := dump(t, dk.DB, table, compare[table])
		if d == "" {
			t.Errorf("%s: no rows", table)
		}
		fmt.Fprintf(&sb, "== %s: %s\n%s\n", table, compare[table], d)
	}
	golden := filepath.Join("testdata", "roundtrip.golden")
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(golden, []byte(sb.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got := sb.String(); got != string(want) {
		t.Errorf("tables differ from %s:\n%s", golden, got)
	}
}

// A crash after a flush: entities still open are read from the run's open
// file, seen until the last sample before the flush.
func TestCrashKeepsOpenRows(t *testing.T) {
	dir := t.TempDir()
	pq, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range batches() {
		pq.Write(x)
	}
	if err := pq.Flush(); err != nil {
		t.Fatal(err)
	}
	pq.Write(&store.Batch{Sample: store.Sample{TS: 3000}}) // unflushed: lost in the crash
	dk, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer dk.Close()
	for _, c := range []struct {
		q    string
		want int64
	}{
		{`SELECT last_seen FROM processes WHERE id = 101`, 2000},
		{`SELECT last_seen FROM sockets WHERE id = 201`, 2000},
		{`SELECT last_seen FROM open_files WHERE id = 401`, 1000}, // last fd walk
		{`SELECT COUNT(*) FROM processes`, 2},
		{`SELECT MAX(ts) FROM samples`, 2000},
	} {
		var v int64
		if err := dk.QueryRow(c.q).Scan(&v); err != nil || v != c.want {
			t.Errorf("%s = %d (%v), want %d", c.q, v, err, c.want)
		}
	}
}

// A recording from a newer clifrd is refused; the current schema opens.
func TestSchemaVersion(t *testing.T) {
	for _, c := range []struct {
		version string
		ok      bool
	}{{strconv.Itoa(store.SchemaVersion), true}, {strconv.Itoa(store.SchemaVersion + 1), false}} {
		dir := t.TempDir()
		pq, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		pq.SetMeta("schema_version", c.version)
		pq.Write(&store.Batch{Sample: store.Sample{TS: 1000}})
		if err := pq.Close(); err != nil {
			t.Fatal(err)
		}
		dk, err := Open(dir)
		if err == nil {
			dk.Close()
		}
		if (err == nil) != c.ok || err != nil && !strings.Contains(err.Error(), "newer clifrd") {
			t.Errorf("schema %s: %v", c.version, err)
		}
	}
}
