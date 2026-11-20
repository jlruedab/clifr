package query

import (
	"fmt"
	"sort"
	"strings"

	"clifr/internal/ctr"
	"clifr/internal/store"
)

// ctrSpecMatch reports whether container id matches SPEC as ss -N and
// ps --container take it: the id, at least 4 hex digits of its start, its
// runtime name, its pod or NAMESPACE/POD/CONTAINER, or an LXC name (the id).
func ctrSpecMatch(spec, id string, names map[string]ctrName) bool {
	if spec == "" || id == "" {
		return false
	}
	if id == spec || len(spec) >= 4 && ctr.IsHexID(id) && strings.HasPrefix(id, spec) {
		return true
	}
	n, ok := names[id]
	return ok && (n.name == spec || n.display() == spec || n.pod == spec)
}

// ContainerFilter resolves ps --container SPEC over [from, to] (from = to
// for a moment): the containers matching SPEC that had processes recorded
// with a cgroup in the window. It returns a test of a process's cgroup text
// and a label for the header. Several containers may match (a pod's).
func ContainerFilter(db *store.DB, from, to int64, spec string) (func(cgroup string) bool, string, error) {
	if s, err := SnapshotAt(db, from, false); err == nil && from == to {
		from, to = s, s // alive at the sample at or before T, as ps sees them
	}
	names := containerNames(db, from, to)
	rows, err := db.Query(`SELECT DISTINCT cgroup FROM processes WHERE cgroup IS NOT NULL AND cgroup != ''
		  AND first_seen <= ?2 AND COALESCE(ended, last_seen, ?3) >= ?1`, from, to, openEnd)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	ids := map[string]string{} // matching id -> runtime
	for rows.Next() {
		var cg string
		if err := rows.Scan(&cg); err != nil {
			return nil, "", err
		}
		for _, p := range cgroupPaths(cg) {
			if id, rt := ContainerOf(p); id != "" {
				if ctrSpecMatch(spec, id, names) {
					ids[id] = rt
				}
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(ids) == 0 {
		return nil, "", fmt.Errorf("--container %s: no container %q with processes at %s (clifr containers lists them)",
			spec, spec, FormatMS(to))
	}
	var labels []string
	for id, rt := range ids {
		short := id
		if ctr.IsHexID(id) {
			short = id[:12]
		}
		if n := names[id].display(); n != "" && n != short {
			short += " " + n
		}
		labels = append(labels, short+" ("+rt+")")
	}
	sort.Strings(labels)
	label := "container " + labels[0]
	if len(labels) > 1 {
		label = fmt.Sprintf("%d containers: %s", len(labels), strings.Join(labels, ", "))
	}
	test := func(cg string) bool {
		for _, p := range cgroupPaths(cg) {
			if id, _ := ContainerOf(p); id != "" {
				_, ok := ids[id]
				return ok
			}
		}
		return false
	}
	return test, label, nil
}
