package query

import (
	"database/sql"
	"fmt"
	"strconv"

	"clifr/internal/ctr"
	"clifr/internal/store"
)

// Network namespaces (schema 10): processes.netns, tcp_conns.netns and
// tcp_keyframes.netns hold the namespace's inode number, 0 for the host's;
// NULL in older recordings, which recorded the host's only. ss and netstat
// show the host's namespace, as the real tools do on the host; ss -N picks
// another (a container's, a process's).

// NetNSOf resolves ss -N SPEC at t: a PID (the process alive at t), or a
// container (an id of at least 4 hex digits or its prefix, its name, its pod
// or NAMESPACE/POD/CONTAINER, or an LXC name, as clifr containers lists them)
// to its network namespace, with a label for the header.
func NetNSOf(db *store.DB, t int64, spec string) (ns uint32, label string, err error) {
	// Alive at the sample at or before t, as ps sees them.
	if s, err := SnapshotAt(db, t, false); err == nil {
		t = s
	}
	if pid, err := strconv.Atoi(spec); err == nil {
		var n sql.NullInt64
		var comm string
		err := db.QueryRow(`SELECT netns, comm FROM processes WHERE pid = ?1 AND first_seen <= ?2
			  AND COALESCE(ended, last_seen, ?3) >= ?2 ORDER BY first_seen DESC LIMIT 1`, pid, t, openEnd).Scan(&n, &comm)
		if err == sql.ErrNoRows {
			return 0, "", fmt.Errorf("-N %d: no process %d at %s", pid, pid, FormatMS(t))
		}
		if err != nil {
			return 0, "", err
		}
		if !n.Valid {
			return 0, "", fmt.Errorf("-N %d: the recording has no network namespaces (recorded since 2026-11-08)", pid)
		}
		return uint32(n.Int64), fmt.Sprintf("process %d (%s)", pid, comm), nil
	}
	names := containerNames(db, t, t) // a container's runtime name, pod or NAMESPACE/POD/CONTAINER
	rows, err := db.Query(`SELECT netns, cgroup FROM processes WHERE cgroup IS NOT NULL AND cgroup != ''
		  AND first_seen <= ?1 AND COALESCE(ended, last_seen, ?2) >= ?1`, t, openEnd)
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()
	ids := map[string]string{}           // matching container id -> runtime
	count := map[string]map[uint32]int{} // id -> namespace -> processes
	var noNS bool
	for rows.Next() {
		var n sql.NullInt64
		var cg string
		if err := rows.Scan(&n, &cg); err != nil {
			return 0, "", err
		}
		for _, p := range cgroupPaths(cg) {
			id, rt := ContainerOf(p)
			if id == "" {
				continue
			}
			if ctrSpecMatch(spec, id, names) {
				ids[id] = rt
				if !n.Valid {
					noNS = true
					break
				}
				if count[id] == nil {
					count[id] = map[uint32]int{}
				}
				count[id][uint32(n.Int64)]++
			}
			break
		}
	}
	if err := rows.Err(); err != nil {
		return 0, "", err
	}
	switch {
	case len(ids) == 0:
		return 0, "", fmt.Errorf("-N %s: no container or process %q with processes at %s (clifr containers lists them)", spec, spec, FormatMS(t))
	case len(ids) > 1:
		// A pod's containers share its namespace: one answer if they all do.
		common, same, first := uint32(0), true, true
		for id := range ids {
			for ns := range count[id] {
				if first {
					common, first = ns, false
				} else if ns != common {
					same = false
				}
			}
		}
		if same && !first {
			return common, fmt.Sprintf("%d containers %q", len(ids), spec), nil
		}
		return 0, "", fmt.Errorf("-N %s: %d containers match, in different namespaces; give more of the id or name", spec, len(ids))
	}
	for id, rt := range ids {
		if noNS && len(count[id]) == 0 {
			return 0, "", fmt.Errorf("-N %s: the recording has no network namespaces (recorded since 2026-11-08)", spec)
		}
		best, n := uint32(0), -1
		for ns, c := range count[id] { // the namespace of most of its processes
			if c > n || c == n && ns < best {
				best, n = ns, c
			}
		}
		short := id
		if ctr.IsHexID(id) {
			short = id[:12]
		}
		if n := names[id].display(); n != "" && n != short {
			short += " " + n
		}
		return best, fmt.Sprintf("container %s (%s)", short, rt), nil
	}
	return 0, "", nil
}

// NetNSText is a namespace for headers: "the host's" for 0.
func NetNSText(ns uint32) string {
	if ns == 0 {
		return "the host's"
	}
	return "net:[" + strconv.FormatUint(uint64(ns), 10) + "]"
}
