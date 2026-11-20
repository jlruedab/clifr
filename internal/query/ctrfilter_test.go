package query

import (
	"strings"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

func TestContainerFilter(t *testing.T) {
	web := strings.Repeat("ab", 32)
	db1 := strings.Repeat("cd", 32)
	pod1 := "1234" + strings.Repeat("e", 60)
	pod2 := "5678" + strings.Repeat("f", 60)
	cg := func(id string) string { return "0::/system.slice/docker-" + id + ".scope" }
	kcg := func(id string) string {
		return "0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-" + id + ".scope"
	}
	b := &store.Batch{Sample: store.Sample{TS: 1000},
		ProcInserts: []store.ProcRow{
			{ID: 1, PID: 10, Comm: "nginx", FirstSeen: 1000, Cgroup: cg(web)},
			{ID: 2, PID: 11, Comm: "nginx", FirstSeen: 1000, Cgroup: cg(web)},
			{ID: 3, PID: 20, Comm: "postgres", FirstSeen: 1000, Cgroup: cg(db1)},
			{ID: 4, PID: 30, Comm: "app", FirstSeen: 1000, Cgroup: kcg(pod1)},
			{ID: 5, PID: 31, Comm: "sidecar", FirstSeen: 1000, Cgroup: kcg(pod2)},
			{ID: 6, PID: 1, Comm: "systemd", FirstSeen: 1000, Cgroup: "0::/init.scope"},
		},
		Snapshots: []store.SnapshotRow{
			{TS: 1000, Source: "containers", Key: web, Pos: 0, Full: true, Line: "docker\tweb\tnginx:1\t\t\t"},
			{TS: 1000, Source: "containers", Key: db1, Pos: 1, Full: true, Line: "docker\tdb\tpostgres:18\t\t\t"},
			{TS: 1000, Source: "containers", Key: pod1, Pos: 2, Full: true, Line: "containerd\tapp\tapp:2\tshop\tprod\t"},
			{TS: 1000, Source: "containers", Key: pod2, Pos: 3, Full: true, Line: "containerd\tproxy\tenvoy:1\tshop\tprod\t"},
		},
	}
	for i := 1; i <= 6; i++ {
		b.ProcSamples = append(b.ProcSamples, store.ProcSample{ProcID: int64(i), TS: 1000, State: "S"})
	}
	db := testrec.Open(t, nil, b)
	for _, c := range []struct {
		spec, label string
		pids        []int
	}{
		{"web", "container abababababab web (docker)", []int{10, 11}},
		{"cdcd", "container cdcdcdcdcdcd db (docker)", []int{20}},
		{db1, "container cdcdcdcdcdcd db (docker)", []int{20}},
		{"shop", "2 containers: ", []int{30, 31}},
		{"prod/shop/proxy", "container 5678ffffffff prod/shop/proxy (containerd)", []int{31}},
	} {
		in, label, err := ContainerFilter(db, 1000, 1000, c.spec)
		if err != nil {
			t.Fatalf("%s: %v", c.spec, err)
		}
		if !strings.HasPrefix(label, c.label) {
			t.Errorf("%s: label %q", c.spec, label)
		}
		rows, _, err := PSAt(db, 1000)
		if err != nil {
			t.Fatal(err)
		}
		var got []int
		for _, r := range rows {
			if in(r.Cgroup) {
				got = append(got, r.PID)
			}
		}
		if len(got) != len(c.pids) || got[0] != c.pids[0] || got[len(got)-1] != c.pids[len(c.pids)-1] {
			t.Errorf("%s: pids %v, want %v", c.spec, got, c.pids)
		}
	}
	for _, spec := range []string{"abc", "nope", "init.scope"} { // under 4 digits, unknown, not a container
		if _, _, err := ContainerFilter(db, 1000, 1000, spec); err == nil {
			t.Errorf("%s: no error", spec)
		}
	}
}
