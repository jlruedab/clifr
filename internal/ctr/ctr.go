// Package ctr recognises containers from their processes' cgroups (pure Go:
// clifrd uses it to notice new containers, clifr to list them).
package ctr

import (
	"regexp"
	"strings"

	"clifr/internal/procfs"
)

// Container cgroup names: docker and podman with the systemd cgroup driver
// (docker-ID.scope, libpod-ID.scope), containerd and CRI-O under
// Kubernetes (cri-containerd-ID.scope, crio-ID.scope), and the cgroupfs
// driver's /docker/ID and /libpod_parent/libpod-ID. A conmon scope
// (libpod-conmon-, crio-conmon-) is the runtime's monitor, not the
// container. LXC, LXD and Incus (the user, 2026-11-08): the payload cgroup
// lxc.payload.NAME (LXC 4+, cgroup v2 and v1), or /lxc/NAME (LXC 3); the
// container's name is its id (lxc.monitor.NAME is LXC's monitor).
var containerName = regexp.MustCompile(`^(docker|libpod|cri-containerd|crio)-([0-9a-f]{64})(\.scope)?$`)
var hexID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// IsHexID reports whether id is a 64-digit runtime id (not an LXC name).
func IsHexID(id string) bool { return hexID.MatchString(id) }

// Of returns the container id and runtime for a cgroup path, or "" when it
// is not in a container.
func Of(cgroup string) (id, runtime string) {
	parts := strings.Split(strings.Trim(cgroup, "/"), "/")
	for i, part := range parts {
		if name, ok := strings.CutPrefix(part, "lxc.payload."); ok && name != "" {
			return name, "lxc"
		}
		if i == 1 && parts[0] == "lxc" && part != "" {
			return part, "lxc"
		}
		if m := containerName.FindStringSubmatch(part); m != nil {
			rt := map[string]string{"docker": "docker", "libpod": "podman", "cri-containerd": "containerd", "crio": "cri-o"}[m[1]]
			return m[2], rt
		}
		if hexID.MatchString(part) && i > 0 {
			switch {
			case parts[i-1] == "docker":
				return part, "docker"
			case strings.HasPrefix(parts[0], "kubepods"):
				return part, "kubernetes"
			}
		}
	}
	return "", ""
}

// Paths returns every cgroup line's path of /proc/<pid>/cgroup: on cgroup v1
// a container may show in a controller's hierarchy only.
func Paths(cg string) []string {
	var out []string
	if p, _, ok := procfs.SystemdCgroup(cg); ok {
		out = append(out, p)
	}
	for _, l := range strings.Split(cg, "\n") {
		if i := strings.LastIndexByte(l, ':'); i >= 0 {
			out = append(out, l[i+1:])
		}
	}
	return out
}

// OfProcess is the container of a process's /proc/<pid>/cgroup contents.
func OfProcess(cg string) (id, runtime string) {
	for _, p := range Paths(cg) {
		if id, rt := Of(p); id != "" {
			return id, rt
		}
	}
	return "", ""
}
