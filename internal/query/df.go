package query

import (
	"database/sql"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// ---- mount ----

// MountOptions are the options util-linux mount prints: the mount's own
// (VFS) options, then the file system's (super block) options without their
// rw/ro. It is ro if either is (a read-only file system mounted rw).
func MountOptions(vfs, super string) string {
	opts := vfs
	for _, o := range strings.Split(super, ",") {
		switch {
		case o == "ro":
			if rest, ok := strings.CutPrefix(opts, "rw"); ok && (rest == "" || rest[0] == ',') {
				opts = "ro" + rest
			}
		case o != "" && o != "rw":
			opts += "," + o
		}
	}
	return opts
}

// MountTypes is mount -t: a comma-separated list of types, all prefixed
// with "no" to exclude them instead.
type MountTypes []string

func (t MountTypes) Keep(fstype string) bool {
	if len(t) == 0 {
		return true
	}
	neg := strings.HasPrefix(t[0], "no")
	for _, x := range t {
		if strings.TrimPrefix(x, "no") == fstype && neg == strings.HasPrefix(x, "no") {
			return !neg
		}
	}
	return neg
}

// PrintMount prints the table like util-linux mount without arguments.
func PrintMount(w io.Writer, rows []MountRow) {
	for _, m := range rows {
		src, opts := m.Source, MountOptions(m.Options, m.SuperOptions)
		if m.LoopFile != "" {
			src = m.LoopFile // mount shows a loop device by its backing file
		}
		if m.UserOptions != "" {
			opts += "," + m.UserOptions
		}
		fmt.Fprintf(w, "%s on %s type %s (%s)\n", src, m.Point, m.FSType, opts)
	}
}

// ---- df ----

// DFRow is one file system as df shows it, in bytes and inodes.
type DFRow struct {
	Source        string `json:"filesystem"`
	FSType        string `json:"type"`
	Point         string `json:"mounted_on"`
	SizeBytes     int64  `json:"size_bytes"`
	UsedBytes     int64  `json:"used_bytes"`
	AvailBytes    int64  `json:"avail_bytes"`
	Inodes        int64  `json:"inodes"`
	IUsed         int64  `json:"iused"`
	IFree         int64  `json:"ifree"`
	SampleTS      int64  `json:"sample_ts_ms"`
	used, nonroot int64  // in blocks, for Use%
	dev, root     string
}

// dfDummy are the file systems df leaves out as dummies (gnulib's ME_DUMMY),
// and dfHidden those GNU coreutils 9.7 also leaves out on Linux although they
// have blocks (checked on Ubuntu 26.04: devtmpfs, squashfs).
var (
	dfDummy = map[string]bool{"autofs": true, "proc": true, "subfs": true, "debugfs": true, "devpts": true,
		"fusectl": true, "fuse.portal": true, "mqueue": true, "rpc_pipefs": true, "sysfs": true, "devfs": true,
		"kernfs": true, "ignore": true}
	dfHidden = map[string]bool{"devtmpfs": true, "squashfs": true}
)

// DFSelect holds df's selection options.
type DFSelect struct {
	All     bool     // -a: dummy, empty and duplicate file systems too
	Local   bool     // -l: no network file systems
	Exclude []string // -x TYPE
	Only    []string // -t TYPE
}

// noStatfs are the types clifrd does not measure (they have no blocks; see
// recorder.noUsage): df -a shows them with zeros.
var noStatfs = map[string]bool{"tracefs": true, "securityfs": true, "cgroup": true, "cgroup2": true,
	"pstore": true, "bpf": true, "configfs": true, "binfmt_misc": true, "nsfs": true, "hugetlbfs": true}

// dfRemote is gnulib's ME_REMOTE: a network file system (left out by -l).
func dfRemote(source, fstype string) bool {
	switch fstype {
	case "acfs", "afs", "coda", "auristorfs", "fhgfs", "gpfs", "ibrix", "ocfs2", "vxfs":
		return true
	}
	return strings.Contains(source, ":") || source == "-hosts" ||
		strings.HasPrefix(source, "//") && (fstype == "smbfs" || fstype == "smb3" || fstype == "cifs")
}

// DF reconstructs df at t: the mounts then, in mountinfo order, with the
// usage of each from the latest sample at or before t (sampled). Like df it
// leaves out dummy and empty file systems and lists a device mounted more
// than once only once, unless sel.All.
func DF(db *store.DB, t int64, sel DFSelect) ([]DFRow, error) {
	mounts, err := MountsAt(db, t)
	if err != nil {
		return nil, err
	}
	var out []DFRow
	seen := map[string]int{}            // dev -> index in out
	listAll := StyleAt(db, t).DFListAll // coreutils before 9 lists devtmpfs and squashfs
	for _, m := range mounts {
		if !sel.All && (dfDummy[m.FSType] || dfHidden[m.FSType] && !listAll) || slices.Contains(sel.Exclude, m.FSType) ||
			len(sel.Only) > 0 && !slices.Contains(sel.Only, m.FSType) || sel.Local && dfRemote(m.Source, m.FSType) {
			continue
		}
		var r DFRow
		var frsize, blocks, bfree, bavail int64
		err := db.QueryRow(`SELECT ts, frsize, blocks, bfree, bavail, files, ffree FROM fs_samples
			WHERE mount_id = ?1 AND ts >= ?2 AND ts <= ?3 ORDER BY ts DESC LIMIT 1`, m.MountID, m.since, t).
			Scan(&r.SampleTS, &frsize, &blocks, &bfree, &bavail, &r.Inodes, &r.IFree)
		switch {
		case err == sql.ErrNoRows && sel.All && (dfDummy[m.FSType] || noStatfs[m.FSType]):
			// not measured: no blocks, shown with zeros
		case err == sql.ErrNoRows:
			continue // not measured (yet)
		case err != nil:
			return nil, err
		case blocks == 0 && !sel.All:
			continue
		}
		r.Source, r.FSType, r.Point, r.dev, r.root = m.Source, m.FSType, m.Point, m.Dev, m.Root
		r.SizeBytes, r.UsedBytes, r.AvailBytes = blocks*frsize, (blocks-bfree)*frsize, bavail*frsize
		r.used, r.nonroot = blocks-bfree, blocks-bfree+bavail
		r.IUsed = r.Inodes - r.IFree
		if sel.All {
			out = append(out, r)
			continue
		}
		if i, ok := seen[r.dev]; ok && r.dev != "" {
			// GNU df keeps one entry per device: a real device name over
			// another one, else the mount point nearer the root (unless that
			// shows a deeper part of the file system).
			o := out[i]
			nearer := len(o.Point) > len(r.Point) && !(o.root != "" && r.root != "" && len(o.root) < len(r.root))
			if strings.Contains(r.Source, "/") && !strings.Contains(o.Source, "/") || nearer ||
				o.Source != r.Source && o.Point == r.Point {
				out[i] = r
			}
			continue
		}
		seen[r.dev] = len(out)
		out = append(out, r)
	}
	return out, nil
}

// DFFormat holds df's output options.
type DFFormat struct {
	Human, Type, Inodes bool
}

// dfHuman is df -h: powers of 1024, rounded up, one decimal below 10.
func dfHuman(bytes int64) string {
	if bytes == 0 {
		return "0"
	}
	v := float64(bytes)
	units := []string{"", "K", "M", "G", "T", "P", "E"}
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if v < 10 {
		if r := math.Ceil(v*10) / 10; r < 10 {
			return strconv.FormatFloat(r, 'f', 1, 64) + units[i]
		}
	}
	n := math.Ceil(v)
	if n >= 1024 && i < len(units)-1 {
		return "1.0" + units[i+1]
	}
	return strconv.FormatInt(int64(n), 10) + units[i]
}

// ceilDiv1K is a byte count in 1K blocks, rounded up like df.
func ceilDiv1K(n int64) int64 { return (n + 1023) / 1024 }

func pctUp(part, whole int64) string {
	if whole == 0 {
		return "-"
	}
	return strconv.FormatInt((part*100+whole-1)/whole, 10) + "%"
}

// PrintDF prints rows like GNU df: every column as wide as its widest cell,
// text left-aligned and numbers right-aligned, one space apart.
func PrintDF(w io.Writer, rows []DFRow, f DFFormat) {
	head := []string{"Filesystem"}
	if f.Type {
		head = append(head, "Type")
	}
	switch {
	case f.Inodes:
		head = append(head, "Inodes", "IUsed", "IFree", "IUse%")
	case f.Human:
		head = append(head, "Size", "Used", "Avail", "Use%")
	default:
		head = append(head, "1K-blocks", "Used", "Available", "Use%")
	}
	head = append(head, "Mounted on")
	table := [][]string{head}
	for _, r := range rows {
		line := []string{r.Source}
		if f.Type {
			line = append(line, r.FSType)
		}
		switch {
		case f.Inodes:
			line = append(line, strconv.FormatInt(r.Inodes, 10), strconv.FormatInt(r.IUsed, 10),
				strconv.FormatInt(r.IFree, 10), pctUp(r.IUsed, r.Inodes))
		case f.Human:
			line = append(line, dfHuman(r.SizeBytes), dfHuman(r.UsedBytes), dfHuman(r.AvailBytes), pctUp(r.used, r.nonroot))
		default:
			line = append(line, strconv.FormatInt(ceilDiv1K(r.SizeBytes), 10), strconv.FormatInt(ceilDiv1K(r.UsedBytes), 10),
				strconv.FormatInt(ceilDiv1K(r.AvailBytes), 10), pctUp(r.used, r.nonroot))
		}
		table = append(table, append(line, r.Point))
	}
	// GNU df's minimum column widths (field_data in df.c).
	width := make([]int, len(head))
	minWidth := map[string]int{"Filesystem": 14, "Type": 4, "1K-blocks": 5, "Size": 5, "Used": 5, "Available": 5,
		"Avail": 5, "Use%": 4, "Inodes": 5, "IUsed": 5, "IFree": 5, "IUse%": 5}
	for i, h := range head {
		width[i] = minWidth[h]
	}
	for _, line := range table {
		for i, c := range line {
			width[i] = max(width[i], len(c))
		}
	}
	text := 1 // Filesystem, Type: left-aligned
	if f.Type {
		text = 2
	}
	for _, line := range table {
		var b strings.Builder
		for i, c := range line {
			if i > 0 {
				b.WriteByte(' ')
			}
			switch {
			case i == len(line)-1:
				b.WriteString(c)
			case i < text:
				b.WriteString(c + strings.Repeat(" ", width[i]-len(c)))
			default:
				b.WriteString(strings.Repeat(" ", width[i]-len(c)) + c)
			}
		}
		fmt.Fprintln(w, b.String())
	}
}

// DFFor keeps the rows whose file system holds path: the longest mount
// point that is a prefix of it (df PATH).
func DFFor(rows []DFRow, path string) (DFRow, bool) {
	best, ok := DFRow{}, false
	for _, r := range rows {
		p := strings.TrimSuffix(r.Point, "/")
		if (path == r.Point || strings.HasPrefix(path, p+"/")) && (!ok || len(r.Point) > len(best.Point)) {
			best, ok = r, true
		}
	}
	return best, ok
}

// UsePct is the Use% df prints.
func (r *DFRow) UsePct() string { return pctUp(r.used, r.nonroot) }
