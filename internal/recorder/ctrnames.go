package recorder

// Container names (the user, 2026-11-08): the snapshot source "containers",
// one line per container the runtimes know, keyed by its id:
//
//	runtime \t name \t image \t pod \t namespace \t compose project
//
// read every containerNamesMS and at the next system sample after a process
// shows up in a container not seen before. Never from a file that holds a
// container's environment (Docker's config.v2.json, the OCI config.json):
//
//   - Kubernetes (containerd, CRI-O): the kubelet's links
//     /var/log/containers/POD_NAMESPACE_CONTAINER-ID.log, names only;
//   - Docker: its API's list of running containers (GET /containers/json on
//     /var/run/docker.sock: names, image, labels; read-only, no environment);
//   - Podman (rootful): the id, names and image of its storage's
//     containers.json.
//
// LXC, LXD and Incus containers are known by their name already.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"clifr/internal/ctr"
	"clifr/internal/procfs"
)

const containerNamesMS = 300_000

var (
	k8sLogDir    = "/var/log/containers"
	dockerSocket = "/var/run/docker.sock"
	podmanStore  = "/var/lib/containers/storage/overlay-containers/containers.json"
)

// containerName is one container as its runtime names it.
type containerName struct {
	runtime, name, image, pod, namespace, project string
}

// noteContainer marks a process's container (its cgroup) as seen; a new one
// makes the next system sample read the names.
func (r *Recorder) noteContainer(cgroup string) {
	// Called for every process at every fd walk: a cgroup already looked at
	// costs one map lookup (processes of a service or container share it).
	if r.ctrCgroups[cgroup] {
		return
	}
	if r.ctrCgroups == nil || len(r.ctrCgroups) > 10_000 { // transient scopes come and go
		r.ctrCgroups = map[string]bool{}
	}
	r.ctrCgroups[cgroup] = true
	id, _ := ctr.OfProcess(cgroup)
	if id == "" || r.ctrSeen[id] {
		return
	}
	if r.ctrSeen == nil {
		r.ctrSeen = map[string]bool{}
	}
	r.ctrSeen[id], r.ctrNew = true, true
}

// readContainerNames is the snapshot source's read.
func (r *Recorder) readContainerNames() ([]procfs.SnapLine, error) {
	r.ctrNew = false
	names := map[string]containerName{}
	k8sNames(names)
	dockerNames(names)
	podmanNames(names)
	keys := make([]string, 0, len(names))
	for id := range names {
		keys = append(keys, id)
	}
	slices.Sort(keys) // a fixed order: the whole file is rewritten when it changes
	out := make([]procfs.SnapLine, 0, len(keys))
	for _, id := range keys {
		n := names[id]
		out = append(out, procfs.SnapLine{Key: id, Line: strings.Join([]string{n.runtime, clean(n.name), clean(n.image),
			clean(n.pod), clean(n.namespace), clean(n.project)}, "\t")})
	}
	return out, nil
}

// clean keeps a name on one line and field.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}

// k8sNames reads the kubelet's container log links: the names are the
// file names, nothing is opened.
func k8sNames(out map[string]containerName) {
	ents, err := os.ReadDir(k8sLogDir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n, ok := strings.CutSuffix(e.Name(), ".log")
		if !ok || len(n) < 66 || n[len(n)-65] != '-' {
			continue
		}
		id, rest := n[len(n)-64:], n[:len(n)-65]
		f := strings.SplitN(rest, "_", 3) // pod, namespace, container: none has "_" (DNS-1123)
		if !ctr.IsHexID(id) || len(f) != 3 {
			continue
		}
		out[id] = containerName{runtime: "kubernetes", name: f[2], pod: f[0], namespace: f[1]}
	}
}

// dockerNames asks dockerd for its running containers (2 s at most).
func dockerNames(out map[string]containerName) {
	if fi, err := os.Stat(dockerSocket); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return
	}
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", dockerSocket)
		}}}
	resp, err := c.Get("http://docker/containers/json")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var list []struct {
		ID     string            `json:"Id"`
		Names  []string          `json:"Names"`
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	}
	if json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 16<<20)).Decode(&list) != nil {
		return
	}
	for _, d := range list {
		if !ctr.IsHexID(d.ID) {
			continue
		}
		n := containerName{runtime: "docker", image: d.Image, project: d.Labels["com.docker.compose.project"]}
		if len(d.Names) > 0 {
			n.name = strings.TrimPrefix(d.Names[0], "/")
		}
		// A pod's container under Docker (dockershim): the kubelet's labels.
		n.pod, n.namespace = d.Labels["io.kubernetes.pod.name"], d.Labels["io.kubernetes.pod.namespace"]
		if c := d.Labels["io.kubernetes.container.name"]; c != "" {
			n.name = c
		}
		out[d.ID] = n
	}
}

// podmanNames reads rootful Podman's container list (ids, names, images).
func podmanNames(out map[string]containerName) {
	b, err := os.ReadFile(podmanStore)
	if err != nil {
		return
	}
	var list []struct {
		ID       string   `json:"id"`
		Names    []string `json:"names"`
		Metadata string   `json:"metadata"` // JSON: image-name, name
	}
	if json.Unmarshal(b, &list) != nil {
		return
	}
	for _, p := range list {
		if !ctr.IsHexID(p.ID) {
			continue
		}
		var meta struct {
			ImageName string `json:"image-name"`
		}
		json.Unmarshal([]byte(p.Metadata), &meta)
		n := containerName{runtime: "podman", image: meta.ImageName}
		if len(p.Names) > 0 {
			n.name = p.Names[0]
		}
		if _, ok := out[p.ID]; !ok {
			out[p.ID] = n
		}
	}
}
