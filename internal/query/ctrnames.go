package query

import (
	"strings"

	"clifr/internal/store"
)

// Container names recorded since 2026-11-09 (snapshots source "containers",
// recorder/ctrnames.go): "runtime\tname\timage\tpod\tnamespace\tproject" per
// container id.

// ctrNamesBackMS: how far before a window names are looked for (a whole copy
// is written every 5 minutes, and at a new container).
const ctrNamesBackMS = 10 * 60_000

type ctrName struct {
	runtime, name, image, pod, namespace, project string
}

// containerNames returns the names recorded from a little before from up
// to to, the newest per container (a container gone since keeps its name).
func containerNames(db *store.DB, from, to int64) map[string]ctrName {
	out := map[string]ctrName{}
	rows, err := db.Query(`SELECT key, line FROM snapshots WHERE source = 'containers' AND pos >= 0
		AND ts >= ?1 AND ts <= ?2 ORDER BY ts, pos`, from-ctrNamesBackMS, to)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var key, line string
		if rows.Scan(&key, &line) != nil {
			continue
		}
		f := strings.Split(line, "\t")
		for len(f) < 6 {
			f = append(f, "")
		}
		out[key] = ctrName{f[0], f[1], f[2], f[3], f[4], f[5]}
	}
	return out
}

// display is the name clifr containers shows: a pod's container as
// NAMESPACE/POD/CONTAINER, others by their name.
func (n ctrName) display() string {
	if n.pod != "" {
		return n.namespace + "/" + n.pod + "/" + n.name
	}
	return n.name
}

// nameContainers fills in the names of cs.
func nameContainers(db *store.DB, cs []Container, from, to int64) {
	names := containerNames(db, from, to)
	for i := range cs {
		c := &cs[i]
		if c.Runtime == "lxc" { // LXC, LXD, Incus: the id is the name
			c.Name = c.ID
			continue
		}
		if n, ok := names[c.ID]; ok {
			c.Name, c.Image, c.Pod, c.Namespace, c.Project = n.display(), n.image, n.pod, n.namespace, n.project
		}
	}
}
