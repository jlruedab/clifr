package query

import (
	"strings"
	"testing"
)

func TestContainerOf(t *testing.T) {
	id := strings.Repeat("3f2a9c1b", 8)
	for _, c := range []struct{ cgroup, id, rt string }{
		{"/system.slice/docker-" + id + ".scope", id, "docker"},
		{"/system.slice/docker-" + id + ".scope/init.scope", id, "docker"}, // systemd inside the container
		{"/docker/" + id, id, "docker"},
		{"/machine.slice/libpod-" + id + ".scope/container", id, "podman"},
		{"/machine.slice/libpod-conmon-" + id + ".scope", "", ""},
		{"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice/cri-containerd-" + id + ".scope", id, "containerd"},
		{"/kubepods/burstable/pod1234/" + id, id, "kubernetes"},
		{"/lxc.payload.web1", "web1", "lxc"},            // LXC 4+, LXD, Incus
		{"/lxc.payload.web1/init.scope", "web1", "lxc"}, // systemd in the container
		{"/lxc.payload.web1/system.slice/nginx.service", "web1", "lxc"},
		{"/lxc.monitor.web1", "", ""}, // LXC's monitor, not the container
		{"/lxc/db-2", "db-2", "lxc"},  // LXC 3, cgroup v1
		{"/lxc/db-2/system.slice/sshd.service", "db-2", "lxc"},
		{"/system.slice/lxc.service", "", ""},
		{"/system.slice/ssh.service", "", ""},
	} {
		if got, rt := ContainerOf(c.cgroup); got != c.id || rt != c.rt {
			t.Errorf("%s: %q %q", c.cgroup, got, rt)
		}
	}
}

func TestGroupContainers(t *testing.T) {
	id := strings.Repeat("ab", 32)
	cg := "0::/system.slice/docker-" + id + ".scope"
	cs := groupContainers([]containerProc{
		{pid: 120, startMS: 2000, endMS: openEnd, cgroup: cg, command: "sleep 1"},
		{pid: 100, startMS: 1000, endMS: openEnd, cgroup: cg, command: "/bin/sh -c sleep"},
		{pid: 90, startMS: 500, endMS: openEnd, cgroup: "0::/system.slice/ssh.service", command: "sshd"},
		// v1: the container is in a controller's hierarchy only.
		{pid: 300, startMS: 3000, endMS: 4000, cgroup: "12:cpu,cpuacct:/docker/" + strings.Repeat("cd", 32) + "\n1:name=systemd:/system.slice/docker.service", command: "nginx"},
	}, 5000)
	if len(cs) != 2 || cs[0].ID != id || cs[0].Procs != 2 || cs[0].MainPID != 100 || cs[0].StartMS != 1000 || !cs[0].Running ||
		cs[1].Running || cs[1].LastMS != 4000 || cs[1].Runtime != "docker" {
		t.Errorf("%+v", cs)
	}
}

// LXC containers are grouped by name, and the name is printed whole (a
// hex id is still cut to 12 characters).
func TestContainersLXC(t *testing.T) {
	id := strings.Repeat("ab", 32)
	cs := groupContainers([]containerProc{
		{pid: 10, startMS: 1000, endMS: openEnd, cgroup: "0::/lxc.payload.web1/init.scope", command: "/sbin/init"},
		{pid: 11, startMS: 1100, endMS: openEnd, cgroup: "0::/lxc.payload.web1/system.slice/nginx.service", command: "nginx"},
		{pid: 12, startMS: 900, endMS: openEnd, cgroup: "0::/lxc.monitor.web1", command: "[lxc monitor] /var/lib/lxc web1"},
		{pid: 20, startMS: 2000, endMS: openEnd, cgroup: "0::/system.slice/docker-" + id + ".scope", command: "redis-server"},
	}, 5000)
	if len(cs) != 2 || cs[0].ID != "web1" || cs[0].Runtime != "lxc" || cs[0].Procs != 2 || cs[0].MainPID != 10 {
		t.Fatalf("containers: %+v", cs)
	}
	var b strings.Builder
	PrintContainers(&b, cs, false, false)
	out := b.String()
	if !strings.Contains(out, "web1 ") || !strings.Contains(out, id[:12]+" ") || strings.Contains(out, id[:13]) {
		t.Errorf("output:\n%s", out)
	}
}
