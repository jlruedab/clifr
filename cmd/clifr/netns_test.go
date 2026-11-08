package main

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"clifr/internal/pqstore"
	"clifr/internal/store"
)

// ss shows the host's network namespace; -N picks a container's (by id
// prefix) or a process's; the same addresses in both stay apart.
func TestSSNetNS(t *testing.T) {
	dir := t.TempDir()
	pq, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	boot := now.Add(-48 * time.Hour).UnixMilli()
	for k, v := range map[string]string{"hostname": "web01", "machine_id": "0123456789abcdef0123456789abcdef", "boot_ms": strconv.FormatInt(boot, 10),
		"interval_s": "30", "clk_tck": "100", "page_kb": "4", "mem_total_kb": "1000000", "fds": "held", "tcp": "events"} {
		pq.SetMeta(k, v)
	}
	const ns = 4026532999
	id := strings.Repeat("ab", 32)
	t1, t2 := now.Add(-90*time.Second).UnixMilli(), now.Add(-60*time.Second).UnixMilli()
	host := store.ProcRow{ID: 101, PID: 100, StartTime: boot + 1000, PPID: 1, Comm: "hostd", Cmdline: "hostd", FirstSeen: t1, Source: "sample",
		Cgroup: "0::/system.slice/hostd.service"}
	ctr := store.ProcRow{ID: 102, PID: 200, StartTime: boot + 2000, PPID: 1, Comm: "nginx", Cmdline: "nginx", FirstSeen: t1, Source: "sample",
		Cgroup: "0::/system.slice/docker-" + id + ".scope", NetNS: ns}
	a := func(s string) store.Addr { return store.AddrOf(netip.MustParseAddr(s)) }
	conn := func(cid int64, pid int32, start int64, n uint32) store.TCPConn {
		return store.TCPConn{ID: cid, PID: pid, StartTime: start, FD: 5, Family: 4, LAddr: a("127.0.0.1"), LPort: 8080,
			RAddr: a("0.0.0.0"), Direction: store.DirListen, OpenTS: t1, FirstState: 10, Source: store.SrcEBPF, LastSeen: t2, NetNS: n}
	}
	for i, ts := range []int64{t1, t2} {
		b := &store.Batch{Sample: store.Sample{TS: ts, NProc: 2},
			ProcSamples: []store.ProcSample{{ProcID: 101, TS: ts, State: "S"}, {ProcID: 102, TS: ts, State: "S"}}}
		if i == 0 {
			b.ProcInserts = []store.ProcRow{host, ctr}
		}
		b.TCPConns = []store.TCPConn{conn(501, 100, host.StartTime, 0), conn(502, 200, ctr.StartTime, ns)}
		if err := pq.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := pq.Close(); err != nil {
		t.Fatal(err)
	}
	when := time.UnixMilli(t2).Format("2006-01-02 15:04:05")
	ss := func(args string) (string, error) {
		return capture(t, "--data-dir", dir, "--plain", "--at", when, "ss -ltnp"+args)
	}
	for _, c := range []struct{ args, want, not string }{
		{"", "hostd", "nginx"},
		{" -N " + id[:6], "nginx", "hostd"},
		{" -N 200", "nginx", "hostd"},
		{" -N 100", "hostd", "nginx"}, // a host process: the host's namespace
	} {
		out, err := ss(c.args)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, c.not) {
			t.Errorf("ss -ltnp%s: %v\n%s", c.args, err, out)
		}
	}
	if _, err := ss(" -N abc"); err == nil || !strings.Contains(err.Error(), "no container or process") {
		t.Errorf("-N abc: %v", err)
	}
}
