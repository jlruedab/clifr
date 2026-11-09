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

// clifr containers shows the recorded names; ss -N takes a name.
func TestContainerNamesQuery(t *testing.T) {
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
	id, pid := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	t1, t2 := now.Add(-90*time.Second).UnixMilli(), now.Add(-60*time.Second).UnixMilli()
	web := store.ProcRow{ID: 102, PID: 200, StartTime: boot + 2000, PPID: 1, Comm: "nginx", Cmdline: "nginx", FirstSeen: t1, Source: "sample",
		Cgroup: "0::/system.slice/docker-" + id + ".scope", NetNS: ns}
	podProc := store.ProcRow{ID: 103, PID: 300, StartTime: boot + 3000, PPID: 1, Comm: "app", Cmdline: "app", FirstSeen: t1, Source: "sample",
		Cgroup: "0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-" + pid + ".scope", NetNS: ns + 1}
	listener := store.TCPConn{ID: 502, PID: 200, StartTime: web.StartTime, FD: 5, Family: 4, LAddr: store.AddrOf(netip.MustParseAddr("0.0.0.0")),
		LPort: 80, RAddr: store.AddrOf(netip.MustParseAddr("0.0.0.0")), Direction: store.DirListen, OpenTS: t1, FirstState: 10,
		Source: store.SrcEBPF, LastSeen: t2, NetNS: ns}
	for i, ts := range []int64{t1, t2} {
		b := &store.Batch{Sample: store.Sample{TS: ts, NProc: 2},
			ProcSamples: []store.ProcSample{{ProcID: 102, TS: ts, State: "S"}, {ProcID: 103, TS: ts, State: "S"}},
			TCPConns:    []store.TCPConn{listener}}
		if i == 0 {
			b.ProcInserts = []store.ProcRow{web, podProc}
			b.Snapshots = []store.SnapshotRow{
				{TS: ts, Source: "containers", Key: id, Pos: 0, Full: true, Line: "docker\tweb-1\tnginx:1.27\t\t\tshop"},
				{TS: ts, Source: "containers", Key: pid, Pos: 1, Full: true, Line: "kubernetes\tapp\t\tapi-5f7c\tprod\t"},
			}
		}
		if err := pq.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := pq.Close(); err != nil {
		t.Fatal(err)
	}
	when := time.UnixMilli(t2).Format("2006-01-02 15:04:05")
	out, err := capture(t, "--data-dir", dir, "--plain", "--at", when, "containers")
	if err != nil || !strings.Contains(out, "web-1") || !strings.Contains(out, "prod/api-5f7c/app") {
		t.Errorf("containers: %v\n%s", err, out)
	}
	js, err := capture(t, "--data-dir", dir, "--json", "--at", when, "containers")
	if err != nil || !strings.Contains(js, `"image":"nginx:1.27"`) || !strings.Contains(js, `"compose_project":"shop"`) {
		t.Errorf("containers --json: %v\n%s", err, js)
	}
	for _, spec := range []string{"web-1", "api-5f7c", "prod/api-5f7c/app"} {
		out, err := capture(t, "--data-dir", dir, "--plain", "--at", when, "ss -ltn -N "+spec)
		want := spec == "web-1"
		if err != nil || strings.Contains(out, ":80 ") != want {
			t.Errorf("ss -ltn -N %s: %v (listener shown %v, want %v)\n%s", spec, err, !want, want, out)
		}
	}
}
