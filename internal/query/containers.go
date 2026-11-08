package query

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// Container is a container found from its processes' cgroups. Only the id
// and the runtime are known (names, images and states are the runtime's,
// not in /proc).
type Container struct {
	ID      string `json:"id"`
	Runtime string `json:"runtime"`
	Cgroup  string `json:"cgroup"`
	StartMS int64  `json:"start_ms"`  // the earliest start of its processes
	LastMS  int64  `json:"last_ms"`   // over a range: when its last process was last seen
	Running bool   `json:"running"`   // processes alive at the end of the range (or at T)
	Procs   int    `json:"processes"` // processes seen (at T: alive)
	MainPID int    `json:"main_pid"`  // its earliest process
	Command string `json:"command"`
	// NetNS: its earliest process's network namespace (0: the host's, also
	// for recordings before 2026-11-08); ss -N ID shows its sockets.
	NetNS     uint32 `json:"netns"`
	startedAt int64  // MainPID's start, to pick it
}

// Container cgroup names: docker and podman with the systemd cgroup driver
// (docker-ID.scope, libpod-ID.scope), containerd and CRI-O under
// Kubernetes (cri-containerd-ID.scope, crio-ID.scope), and the cgroupfs
// driver's /docker/ID and /libpod_parent/libpod-ID. A conmon scope
// (libpod-conmon-, crio-conmon-) is the runtime's monitor, not the
// container. LXC, LXD and Incus (the user, 2026-11-08): the payload cgroup
// lxc.payload.NAME (LXC 4+, cgroup v2 and v1), or /lxc/NAME (LXC 3); the
// container's name is its id (lxc.monitor.NAME is LXC's monitor).
var containerName = regexp.MustCompile(`^(docker|libpod|cri-containerd|crio)-([0-9a-f]{64})(\.scope)?$`)
var containerHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ContainerOf returns the container id and runtime for a cgroup path, or
// "" when it is not in a container.
func ContainerOf(cgroup string) (id, runtime string) {
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
		if containerHex.MatchString(part) && i > 0 {
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

// cgroupPaths returns every cgroup line's path of /proc/<pid>/cgroup: on
// cgroup v1 a container may show in a controller's hierarchy only.
func cgroupPaths(cg string) []string {
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

type containerProc struct {
	pid, ppid      int
	startMS, endMS int64 // endMS: last seen (openEnd: still open)
	cgroup         string
	command        string
	netns          uint32
}

func groupContainers(procs []containerProc, end int64) []Container {
	byID := map[string]*Container{}
	for _, p := range procs {
		var id, rt, path string
		for _, c := range cgroupPaths(p.cgroup) {
			if id, rt = ContainerOf(c); id != "" {
				path = c
				break
			}
		}
		if id == "" {
			continue
		}
		c := byID[id]
		if c == nil {
			c = &Container{ID: id, Runtime: rt, Cgroup: path, StartMS: p.startMS, startedAt: p.startMS + 1}
			byID[id] = c
		}
		c.Procs++
		c.StartMS = min(c.StartMS, p.startMS)
		c.LastMS = max(c.LastMS, min(p.endMS, end))
		c.Running = c.Running || p.endMS >= end
		if p.startMS < c.startedAt || p.startMS == c.startedAt && p.pid < c.MainPID {
			c.MainPID, c.Command, c.startedAt, c.NetNS = p.pid, p.command, p.startMS, p.netns
		}
	}
	out := make([]Container, 0, len(byID))
	for _, c := range byID {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartMS != out[j].StartMS {
			return out[i].StartMS < out[j].StartMS
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ContainersAt lists the containers with processes at the sample at or
// before t.
func ContainersAt(db *store.DB, t int64) ([]Container, int64, error) {
	s, err := SnapshotAt(db, t, false)
	if err != nil {
		return nil, 0, err
	}
	procs, err := processesAt(db, s, s)
	if err != nil {
		return nil, 0, err
	}
	var cps []containerProc
	for _, p := range procs {
		if p.cgroup.String != "" {
			cps = append(cps, containerProc{pid: p.pid, ppid: p.ppid, startMS: p.startMS, endMS: openEnd,
				cgroup: p.cgroup.String, command: commandOf(p.cmdline, p.comm, p.state.String), netns: uint32(p.netns.Int64)})
		}
	}
	return groupContainers(cps, s), s, nil
}

// ContainersBetween lists the containers with processes seen in [from, to].
func ContainersBetween(db *store.DB, from, to int64) ([]Container, error) {
	rows, err := db.Query(`SELECT pid, ppid, start_time, COALESCE(ended, last_seen, ?3), cgroup, cmdline, comm, COALESCE(netns, 0)
		FROM processes WHERE cgroup IS NOT NULL AND cgroup != '' AND first_seen <= ?2
		  AND COALESCE(ended, last_seen, ?3) >= ?1`, from, to, openEnd)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cps []containerProc
	for rows.Next() {
		var p containerProc
		var cmdline, comm string
		if err := rows.Scan(&p.pid, &p.ppid, &p.startMS, &p.endMS, &p.cgroup, &cmdline, &comm, &p.netns); err != nil {
			return nil, err
		}
		p.command = commandOf(cmdline, comm, "")
		cps = append(cps, p)
	}
	return groupContainers(cps, to), rows.Err()
}

// PrintContainers prints one line per container: at a moment (since: the
// start of its first process), or over a range (first and last seen).
func PrintContainers(w io.Writer, cs []Container, rangeView, noTrunc bool) {
	idw := 12
	if noTrunc {
		idw = 64
	}
	for _, c := range cs { // an LXC container's id is its name: never cut
		if !containerHex.MatchString(c.ID) {
			idw = max(idw, len(c.ID))
		}
	}
	if rangeView {
		fmt.Fprintf(w, "%-*s  %-10s  %-19s  %-19s  %5s  %7s  %s\n", idw, "CONTAINER ID", "RUNTIME", "FIRST SEEN", "LAST SEEN", "PROCS", "PID", "COMMAND")
	} else {
		fmt.Fprintf(w, "%-*s  %-10s  %-19s  %5s  %7s  %s\n", idw, "CONTAINER ID", "RUNTIME", "STARTED", "PROCS", "PID", "COMMAND")
	}
	for _, c := range cs {
		id := c.ID
		if containerHex.MatchString(id) {
			id = id[:min(idw, len(id))]
		}
		if rangeView {
			last := FormatMS(c.LastMS)
			if c.Running {
				last = "running"
			}
			fmt.Fprintf(w, "%-*s  %-10s  %-19s  %-19s  %5d  %7d  %s\n", idw, id, c.Runtime, FormatMS(c.StartMS), last, c.Procs, c.MainPID, c.Command)
		} else {
			fmt.Fprintf(w, "%-*s  %-10s  %-19s  %5d  %7d  %s\n", idw, id, c.Runtime, FormatMS(c.StartMS), c.Procs, c.MainPID, c.Command)
		}
	}
}
