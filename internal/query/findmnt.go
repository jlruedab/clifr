package query

import (
	"database/sql"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"clifr/internal/pqstore"
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
// (the meta table keeps only the newest run's), "" if none. A run writes its
// meta again every hour; when retention has removed the copies before t,
// the run's first copy after t stands in.
func MetaAt(db *store.DB, key string, t int64) string {
	var v sql.NullString
	db.QueryRow(`SELECT value FROM read_parquet(?1, union_by_name = true) WHERE key = ?2 AND run <= ?3 // 1000
		ORDER BY run DESC, ts <= ?3 DESC, CASE WHEN ts <= ?3 THEN -ts ELSE ts END LIMIT 1`,
		filepath.Join(pqstore.TableDir(db.DataDir, "meta"), "**", "*.parquet"), key, t).Scan(&v)
	return v.String
}

// Boot is one boot of the machine within the recording: from the meta of
// the clifrd runs in it.
type Boot struct {
	BootID   string `json:"boot_id"`
	BootMS   int64  `json:"boot_ms"`
	Kernel   string `json:"kernel_release"` // "" before schema 3
	LastMS   int64  `json:"last_sample_ms"` // the last sample recorded in it
	FirstRun int64  `json:"first_run_ms"`   // when clifrd first recorded in it
	// Crashed: clifrd's last run in it ended without a clean stop
	// (pqstore.MetaWritesStop without MetaStopMS): the system went down
	// without a shutdown, as last prints "crash" when wtmp has none.
	Crashed bool `json:"crashed"`
}

// Boots lists the boots that started at or before t, oldest first.
func Boots(db *store.DB, t int64) ([]Boot, error) {
	rows, err := db.Query(`SELECT run, min(ts), max(value) FILTER (WHERE key = 'boot_id'),
			max(value) FILTER (WHERE key = 'boot_ms'), max(value) FILTER (WHERE key = 'uname_release'),
			count(*) FILTER (WHERE key = '`+pqstore.MetaWritesStop+`') > 0, count(*) FILTER (WHERE key = '`+pqstore.MetaStopMS+`') > 0
		FROM read_parquet(?, union_by_name = true) GROUP BY run ORDER BY run`, filepath.Join(pqstore.TableDir(db.DataDir, "meta"), "**", "*.parquet"))
	if err != nil {
		return nil, err
	}
	var out []Boot
	for rows.Next() {
		var run, first int64
		var id, ms, kernel sql.NullString
		var writesStop, stopped bool
		if err := rows.Scan(&run, &first, &id, &ms, &kernel, &writesStop, &stopped); err != nil {
			rows.Close()
			return nil, err
		}
		bootMS, _ := strconv.ParseInt(ms.String, 10, 64)
		if !id.Valid || bootMS == 0 || bootMS > t {
			continue
		}
		crashed := writesStop && !stopped && run*1000 <= t // the boot's last run decides
		if n := len(out); n > 0 && out[n-1].BootID == id.String {
			if out[n-1].Kernel == "" {
				out[n-1].Kernel = kernel.String
			}
			out[n-1].Crashed = crashed
			continue
		}
		out = append(out, Boot{BootID: id.String, BootMS: bootMS, Kernel: kernel.String, FirstRun: first, Crashed: crashed})
	}
	rows.Close()
	for i := range out {
		end := int64(math.MaxInt64)
		if i+1 < len(out) {
			end = out[i+1].BootMS
		}
		var last sql.NullInt64
		db.QueryRow(`SELECT MAX(ts) FROM samples WHERE ts >= ? AND ts < ? AND ts <= ?`, out[i].BootMS, end, t).Scan(&last)
		out[i].LastMS = last.Int64
	}
	return out, nil
}

// PrintLastReboot prints boots like util-linux last reboot (with full, -F:
// full times), newest first: the boot that covers the moment (the last one)
// is "still running"; an earlier one ends at its last recorded sample (wtmp
// has the shutdown time, or "crash"). begins: when the recording starts.
func PrintLastReboot(w io.Writer, boots []Boot, begins int64, full bool) {
	login := func(ms int64) string {
		if full {
			return time.UnixMilli(ms).Format("Mon Jan _2 15:04:05 2006")
		}
		return time.UnixMilli(ms).Format("Mon Jan _2 15:04")
	}
	logout := func(ms int64) string {
		if full {
			return time.UnixMilli(ms).Format("Mon Jan _2 15:04:05 2006")
		}
		return time.UnixMilli(ms).Format("15:04")
	}
	for i := len(boots) - 1; i >= 0; i-- {
		b := boots[i]
		kernel := b.Kernel
		if kernel == "" {
			kernel = "-"
		}
		line := fmt.Sprintf("%-8.8s %-12.12s %-16.16s %s", "reboot", "system boot", kernel, login(b.BootMS))
		if i == len(boots)-1 {
			line += "   still running"
		} else {
			secs := (b.LastMS - b.BootMS) / 1000
			mins, hours, days := secs/60%60, secs/3600%24, secs/86400
			length := fmt.Sprintf(" (%02d:%02d)", hours, mins)
			if days > 0 {
				length = fmt.Sprintf("(%d+%02d:%02d)", days, hours, mins)
			}
			end := logout(b.LastMS)
			if b.Crashed {
				end = "crash"
			}
			line += " - " + end + " " + length
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintf(w, "\nwtmp begins %s\n", time.UnixMilli(begins).Format("Mon Jan _2 15:04:05 2006"))
}
