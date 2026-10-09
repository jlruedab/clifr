package duck

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sosv/internal/pqstore"
	"sosv/internal/store"
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
			ProcSamples: []store.ProcSample{{ProcID: 101, TS: 1000, State: "S", CPUTicks: 5, RSSKB: 100, VSZKB: 200, Threads: 2}},
			SockInserts: []store.SockRow{{ID: 201, Inode: 555, Proto: "tcp", Family: 4, LAddr: "127.0.0.1", LPort: 80, RAddr: "127.0.0.2", RPort: 4000, FirstSeen: 1000}},
			SockSamples: []store.SockSample{{SockID: 201, TS: 1000, State: 1}},
			OwnInserts:  []store.OwnerRow{{ID: 301, SockID: 201, ProcID: 101, FD: 3, FirstSeen: 1000}},
			FileInserts: []store.FileRow{{ID: 401, ProcID: 101, FD: 4, Target: "/var/log/x (deleted)", Deleted: true, FType: "REG", Mode: "w", Node: 77, FirstSeen: 1000}},
			Guard:       []store.GuardEvent{{TS: 1000, Kind: "skip", Detail: "d"}},
			Verify:      []store.VerifySnap{{TS: 1001, EndTS: 1002, Cmd: "ps aux", SampleTS: 1000, Output: "USER PID"}},
		},
		{
			Sample: store.Sample{TS: 2000, NProc: 2, Rows: 3, CPUUS: 20},
			Skips:  []int64{1500},
			ProcInserts: []store.ProcRow{{ID: 102, PID: 11, StartTime: 1600, PPID: 10, Comm: "sh", Cmdline: "sh -c true", FirstSeen: 1600,
				LastSeen: p64(1700), Ended: p64(1700), Source: "ebpf", Exe: "/bin/sh", ExecTS: p64(1600), ExitTS: p64(1700), ExitCode: pint(3)}},
			ProcUpdates: []store.ProcUpdate{{ID: 101, UID: 5, PPID: 1, Comm: "srv", Cmdline: "srv -y", Source: "sample", Exe: "/usr/bin/srv", ExecTS: 1900}},
			ProcExits:   []store.ProcExit{{ID: 101, OOMKilled: true}},
			OOMEvents:   []store.OOMEvent{{TS: 1950, PID: 10, StartTime: 900, Comm: "srv", RSSKB: 4000, Snapshot: true}},
			Stats:       []store.StatRow{{TS: 2000, Source: "ebpf_exec", Events: 7, Dropped: 1}},
			ProcSamples: []store.ProcSample{{ProcID: 101, TS: 2000, State: "R", CPUTicks: 9, RSSKB: 120, VSZKB: 200, Threads: 2}},
			SockSamples: []store.SockSample{{SockID: 201, TS: 2000, State: 8, RxQ: 1}},
		},
	}
}

func shutdown() *store.Batch {
	return &store.Batch{
		ProcCloses: []store.Close{{ID: 101, LastSeen: 2000, Ended: p64(2500)}},
		ProcExits:  []store.ProcExit{{ID: 101, ExitTS: p64(2500), Signal: pint(9)}},
		SockCloses: []store.Close{{ID: 201, LastSeen: 2000}},
		OwnCloses:  []store.Close{{ID: 301, LastSeen: 2000}},
		FileCloses: []store.Close{{ID: 401, LastSeen: 1000}},
	}
}

// dump renders a table sorted, with NULLs visible, for comparison.
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
		out = append(out, fmt.Sprint(v...))
	}
	return strings.Join(out, "\n")
}

var compare = map[string]string{
	"samples":          "ts, fd_walk, skipped, nproc, rows, cpu_us",
	"processes":        "id, pid, start_time, ppid, uid, comm, cmdline, first_seen, last_seen, ended, source, exe, exec_ts, exit_ts, exit_code, signal, oom_killed",
	"oom_events":       "ts, pid, start_time, comm, rss_kb, snapshot",
	"recorder_stats":   "ts, source, events, dropped",
	"proc_samples":     "proc_id, ts, state, cpu_ticks, rss_kb, vsz_kb, threads",
	"sockets":          "id, inode, proto, family, laddr, lport, raddr, rport, first_seen, last_seen",
	"sock_samples":     "sock_id, ts, state, rxq, txq",
	"sock_owners":      "id, sock_id, proc_id, fd, first_seen, last_seen",
	"open_files":       "id, proc_id, fd, target, deleted, ftype, mode, name, node, first_seen, last_seen",
	"guard_events":     "ts, kind, detail",
	"verify_snapshots": "ts, end_ts, cmd, sample_ts, output",
	"meta":             "key, value",
}

// The same batches through Tee: every table reads back identically from
// SQLite and from Parquet through DuckDB.
func TestParityWithSQLite(t *testing.T) {
	dir := t.TempDir()
	lite, err := store.Open(filepath.Join(dir, "v1.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	pq, err := pqstore.Open(filepath.Join(dir, "data"), pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	b := store.Tee(pq, lite)
	b.SetMeta("interval_s", "30")
	for _, x := range batches() {
		if err := b.Write(x); err != nil {
			t.Fatal(err)
		}
	}
	pq.Flush() // a mid-run flush: the open file, then closed rows replace it
	if err := b.Write(shutdown()); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	lite, _ = store.Open(filepath.Join(dir, "v1.db"), true)
	defer lite.Close()
	dk, err := Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer dk.Close()
	for table, cols := range compare {
		a, b := dump(t, lite.DB, table, cols), dump(t, dk.DB, table, cols)
		if a != b {
			t.Errorf("%s differs\nSQLite:\n%s\nParquet:\n%s", table, a, b)
		}
		if a == "" {
			t.Errorf("%s: no rows", table)
		}
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
