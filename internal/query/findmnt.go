package query

import (
	"database/sql"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"clifr/internal/store"
)

// FindmntRow is one line of findmnt: the mount with its tree prefix (empty
// with -l), and SOURCE and OPTIONS as findmnt builds them (OPTIONS as mount
// shows them).
type FindmntRow struct {
	Target  string `json:"target"`
	Source  string `json:"source"`
	FSType  string `json:"fstype"`
	Options string `json:"options"`
	MountID int    `json:"mount_id"`
	Parent  int    `json:"parent_id"` // inferred from the paths (0: the root); not recorded
	tree    string
}

// Findmnt reconstructs findmnt at t. The tree is findmnt's: each mount under
// the mount it was mounted on, children in mount id order. The parent mount
// is not recorded: it is the mount whose point is the longest prefix of this
// one's (for a mount stacked on the same point, the one before it in
// mountinfo). list: findmnt -l, mountinfo order without the tree.
func Findmnt(db *store.DB, t int64, list bool) ([]FindmntRow, error) {
	mounts, err := MountsAt(db, t)
	if err != nil {
		return nil, err
	}
	rows := make([]FindmntRow, len(mounts))
	for i, m := range mounts {
		src := m.Source
		if m.Root != "" && m.Root != "/" {
			src += "[" + m.Root + "]"
		}
		rows[i] = FindmntRow{Target: m.Point, Source: src, FSType: m.FSType, Options: MountOptions(m.Options, m.SuperOptions), MountID: m.MountID}
	}
	// candidate: p could hold m. A mount on the same point is held by one
	// before it in mountinfo (stacked); "/" only by an earlier "/".
	candidate := func(i, j int) bool {
		m, p := mounts[i].Point, mounts[j].Point
		switch {
		case i == j:
			return false
		case m == p:
			return j < i
		case m == "/":
			return false
		}
		return p == "/" || strings.HasPrefix(m, p+"/")
	}
	parent := make([]int, len(mounts)) // index, -1: a root
	for i := range mounts {
		parent[i] = -1
		for j := range mounts {
			if !candidate(i, j) {
				continue
			}
			// The deepest point; on the same point, the latest (the top of a stack).
			if b := parent[i]; b < 0 || len(mounts[j].Point) > len(mounts[b].Point) ||
				len(mounts[j].Point) == len(mounts[b].Point) && j > b {
				parent[i] = j
			}
		}
		if parent[i] >= 0 {
			rows[i].Parent = mounts[parent[i]].MountID
		}
	}
	if list {
		return rows, nil
	}
	kids := map[int][]int{}
	var roots []int
	for i := range mounts {
		if parent[i] < 0 {
			roots = append(roots, i)
		} else {
			kids[parent[i]] = append(kids[parent[i]], i)
		}
	}
	byID := func(a, b int) int { return mounts[a].MountID - mounts[b].MountID }
	slices.SortFunc(roots, byID)
	var out []FindmntRow
	var walk func(i int, prefix string, depth int, last bool)
	walk = func(i int, prefix string, depth int, last bool) {
		r := rows[i]
		next := ""
		if depth > 0 {
			if last {
				r.tree, next = prefix+"`-", prefix+"  "
			} else {
				r.tree, next = prefix+"|-", prefix+"| "
			}
		}
		out = append(out, r)
		k := kids[i]
		slices.SortFunc(k, byID)
		for n, c := range k {
			walk(c, next, depth+1, n == len(k)-1)
		}
	}
	for _, i := range roots {
		walk(i, "", 0, true)
	}
	return out, nil
}

// PrintFindmnt prints the rows like findmnt in the C locale: four columns as
// wide as their widest cell, one space apart, the last one not padded.
func PrintFindmnt(w io.Writer, rows []FindmntRow) {
	cells := [][4]string{{"TARGET", "SOURCE", "FSTYPE", "OPTIONS"}}
	for _, r := range rows {
		cells = append(cells, [4]string{r.tree + r.Target, r.Source, r.FSType, r.Options})
	}
	var width [3]int
	for _, c := range cells {
		for i := range width {
			width[i] = max(width[i], len(c[i]))
		}
	}
	for _, c := range cells {
		fmt.Fprintf(w, "%-*s %-*s %-*s %s\n", width[0], c[0], width[1], c[1], width[2], c[2], c[3])
	}
}

// MetaAt is a meta value as the recorder run that was recording at t set it
// (the meta table keeps only the newest run's), "" if none.
func MetaAt(db *store.DB, key string, t int64) string {
	var v sql.NullString
	db.QueryRow(`SELECT arg_max(value, ts) FROM read_parquet(?, union_by_name = true) WHERE key = ? AND ts <= ?`,
		filepath.Join(db.DataDir, "meta", "**", "*.parquet"), key, t).Scan(&v)
	return v.String
}
