package query

import (
	"database/sql"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"clifr/internal/store"
)

// BlockDev is a block device as lsblk shows it, with its children: its
// partitions, then the devices it holds up (device-mapper, md), sorted by
// device number as lsblk sorts them.
type BlockDev struct {
	Name        string      `json:"name"`
	KName       string      `json:"kname"`
	MajMin      string      `json:"maj:min"`
	RM          bool        `json:"rm"`
	Size        int64       `json:"size"`
	RO          bool        `json:"ro"`
	Type        string      `json:"type"`
	FSType      string      `json:"fstype,omitempty"`
	FSVer       string      `json:"fsver,omitempty"`
	Label       string      `json:"label,omitempty"`
	UUID        string      `json:"uuid,omitempty"`
	FSAvail     *int64      `json:"fsavail,omitempty"`
	FSUsePct    string      `json:"fsuse%,omitempty"`
	MountPoints []string    `json:"mountpoints,omitempty"` // newest mount first, as lsblk lists them
	Children    []*BlockDev `json:"children,omitempty"`
	dev         uint64      // glibc's makedev: lsblk's sort key
}

// blockDevsAt returns the block devices recorded at or before t (the
// newest row of each within the loaded window), by kernel name.
func blockDevsAt(db *store.DB, t int64) (map[string]store.BlockDevRow, error) {
	rows, err := db.Query(`SELECT name, parent, gone, hidden, maj, min, size, ro, rm, scsi_type, dm_name, dm_uuid, md_level,
			loop_file, holders, slaves, fstype, fsver, label, uuid
		FROM blockdevs WHERE ts <= ? QUALIFY row_number() OVER (PARTITION BY name ORDER BY ts DESC) = 1`, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]store.BlockDevRow{}
	for rows.Next() {
		var d store.BlockDevRow
		var gone, hidden int
		if err := rows.Scan(&d.Name, &d.Parent, &gone, &hidden, &d.Maj, &d.Min, &d.Size, &d.RO, &d.RM, &d.SCSIType,
			&d.DMName, &d.DMUUID, &d.MDLevel, &d.LoopFile, &d.Holders, &d.Slaves, &d.FSType, &d.FSVer, &d.Label, &d.UUID); err != nil {
			return nil, err
		}
		if gone == 0 {
			d.Hidden = hidden == 1
			out[d.Name] = d
		}
	}
	return out, rows.Err()
}

// makedev is glibc's: lsblk sorts by it, so a minor number above 255 sorts
// after the next major numbers.
func makedev(maj, min int) uint64 {
	ma, mi := uint64(maj), uint64(min)
	return (ma&0xfff)<<8 | (mi & 0xff) | (mi&^0xff)<<12 | (ma&^0xfff)<<32
}

// scsiTypes are lsblk's names for /sys/block/*/device/type.
var scsiTypes = map[int64]string{0: "disk", 1: "tape", 2: "printer", 3: "processor", 4: "worm", 5: "rom",
	6: "scanner", 7: "mo-disk", 8: "changer", 9: "comm", 0x0c: "raid", 0x0d: "enclosure", 0x0e: "rbc", 0x11: "osd", 0x7f: "no-lun"}

func blockType(d store.BlockDevRow) string {
	switch {
	case d.Parent != "":
		return "part"
	case strings.HasPrefix(d.Name, "dm-"):
		prefix, _, _ := strings.Cut(d.DMUUID, "-")
		if prefix == "" {
			return "dm"
		}
		if len(prefix) >= 4 && strings.EqualFold(prefix[:4], "part") {
			prefix = prefix[:4] // kpartx: partN
		}
		return strings.ToLower(prefix)
	case strings.HasPrefix(d.Name, "loop"):
		return "loop"
	case strings.HasPrefix(d.Name, "md"):
		if d.MDLevel != "" {
			return strings.ToLower(d.MDLevel)
		}
		return "md"
	}
	if s, ok := scsiTypes[d.SCSIType]; ok {
		return s
	}
	return "disk"
}

// udevDecode undoes udev's \xNN encoding (ID_FS_LABEL_ENC, ID_FS_UUID_ENC).
func udevDecode(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if n, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// devPath is the device's node as lsblk names it.
func devPath(d store.BlockDevRow) string {
	if d.DMName != "" {
		return "/dev/mapper/" + d.DMName
	}
	return "/dev/" + strings.ReplaceAll(d.Name, "!", "/")
}

// LsblkAt returns the device tree at t as lsblk without arguments builds
// it: every device of /sys/block that has no slaves is a root (RAM disks,
// hidden devices and unused loop devices left out), with its partitions
// and holders below it; mount points from the mount table and swap areas at
// t, file system usage from the last statfs sample of the mount shown.
func LsblkAt(db *store.DB, t int64) ([]*BlockDev, error) {
	devs, err := blockDevsAt(db, t)
	if err != nil {
		return nil, err
	}
	if len(devs) == 0 {
		return nil, fmt.Errorf("lsblk: block devices not recorded at %s (recorded since schema 9)", FormatMS(t))
	}
	mounts, err := MountsAt(db, t)
	if err != nil {
		return nil, err
	}
	swaps, _, _ := SwapsAt(db, t)
	ok := func(d store.BlockDevRow) bool {
		return !d.Hidden && d.Maj != 1 && !(d.Size == 0 && d.Maj == 7 && d.LoopFile == "")
	}
	parts := map[string][]string{}
	for _, d := range devs {
		if d.Parent != "" {
			parts[d.Parent] = append(parts[d.Parent], d.Name)
		}
	}
	var node func(d store.BlockDevRow, parent *store.BlockDevRow, doParts bool, depth int) *BlockDev
	node = func(d store.BlockDevRow, parent *store.BlockDevRow, doParts bool, depth int) *BlockDev {
		n := &BlockDev{Name: d.Name, KName: d.Name, MajMin: fmt.Sprintf("%d:%d", d.Maj, d.Min), Size: d.Size,
			RO: d.RO == 1, Type: blockType(d), FSType: d.FSType, FSVer: d.FSVer, Label: udevDecode(d.Label),
			UUID: udevDecode(d.UUID), dev: makedev(d.Maj, d.Min)}
		if d.DMName != "" {
			n.Name = d.DMName
		}
		// RM: the device's own attribute, a partition's from its disk.
		switch {
		case d.RM >= 0:
			n.RM = d.RM == 1
		case parent != nil:
			n.RM = parent.RM == 1
		}
		// Mount points: every mount of the device, newest first, else its
		// swap area.
		path := devPath(d)
		var mine []MountRow
		for i := len(mounts) - 1; i >= 0; i-- {
			if m := mounts[i]; m.Dev == n.MajMin || m.Source == path {
				mine = append(mine, m)
				n.MountPoints = append(n.MountPoints, m.Point)
			}
		}
		if len(mine) == 0 {
			for _, s := range swaps {
				if s.Name == path {
					n.MountPoints = []string{"[SWAP]"}
				}
			}
		}
		if len(mine) > 0 {
			// lsblk's own mount point: the newest, else one of the file
			// system's root if that is a bind mount or subvolume.
			m := mine[0]
			if m.Root != "" && m.Root != "/" {
				for _, o := range mine[1:] {
					if o.Root == "" || o.Root == "/" {
						m = o
						break
					}
				}
			}
			n.fsUsage(db, m, t)
		}
		if depth > 32 { // a loop in the recorded dependencies
			return n
		}
		if doParts {
			for _, p := range parts[d.Name] {
				if pd := devs[p]; ok(pd) {
					n.Children = append(n.Children, node(pd, &d, false, depth+1))
				}
			}
		}
		if d.Holders != "" {
			for _, h := range strings.Split(d.Holders, ",") {
				if hd, found := devs[h]; found && ok(hd) {
					var hp *store.BlockDevRow
					if hd.Parent != "" {
						p := devs[hd.Parent]
						hp = &p
					}
					n.Children = append(n.Children, node(hd, hp, true, depth+1))
				}
			}
		}
		sort.SliceStable(n.Children, func(i, j int) bool { return n.Children[i].dev < n.Children[j].dev })
		return n
	}
	var roots []*BlockDev
	for _, d := range devs {
		if d.Parent == "" && d.Slaves == "" && ok(d) {
			roots = append(roots, node(d, nil, true, 0))
		}
	}
	sort.SliceStable(roots, func(i, j int) bool { return roots[i].dev < roots[j].dev })
	return roots, nil
}

// fsUsage sets FSAVAIL and FSUSE% from the mount's last statfs sample.
func (n *BlockDev) fsUsage(db *store.DB, m MountRow, t int64) {
	var frsize, blocks, bfree, bavail int64
	err := db.QueryRow(`SELECT frsize, blocks, bfree, bavail FROM fs_samples
		WHERE mount_id = ?1 AND ts >= ?2 AND ts <= ?3 ORDER BY ts DESC LIMIT 1`, m.MountID, m.since, t).
		Scan(&frsize, &blocks, &bfree, &bavail)
	if err == sql.ErrNoRows || err != nil {
		return
	}
	avail := frsize * bavail
	n.FSAvail = &avail
	if blocks == 0 {
		n.FSUsePct = "-"
	} else {
		n.FSUsePct = fmt.Sprintf("%.0f%%", float64(blocks-bfree)/float64(blocks)*100)
	}
}

// LsblkOptions: -f (file systems), -b (bytes), -n (no header), the
// recorded util-linux (V232: RHEL 8's 2.32, one MOUNTPOINT, -f without
// FSVER, FSAVAIL and FSUSE%), and ASCII tree glyphs (a non-UTF-8 locale).
type LsblkOptions struct {
	FS, Bytes, NoHeadings, V232, ASCII bool
}

// lsblkCol is a column: its header, libsmartcols width hint (an absolute
// one, >= 1, widens a column whose data are as wide as its header) and
// alignment.
type lsblkCol struct {
	name  string
	hint  int
	right bool
}

// PrintLsblk prints the tree as lsblk (libsmartcols) does into a pipe.
func PrintLsblk(w io.Writer, roots []*BlockDev, o LsblkOptions) {
	mp := lsblkCol{"MOUNTPOINTS", 0, false}
	if o.V232 {
		mp.name = "MOUNTPOINT"
	}
	cols := []lsblkCol{{"NAME", 0, false}, {"MAJ:MIN", 6, false}, {"RM", 1, true}, {"SIZE", 5, true}, {"RO", 1, true}, {"TYPE", 4, false}, mp}
	if o.FS {
		cols = []lsblkCol{{"NAME", 0, false}, {"FSTYPE", 0, false}, {"FSVER", 0, false}, {"LABEL", 0, false}, {"UUID", 36, false},
			{"FSAVAIL", 5, true}, {"FSUSE%", 3, true}, mp}
		if o.V232 {
			cols = []lsblkCol{cols[0], cols[1], cols[3], cols[4], mp}
		}
	}
	size := func(b int64) string {
		if o.Bytes {
			return strconv.FormatInt(b, 10)
		}
		return utilHuman(b)
	}
	flag := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	branch, right, vert := "├─", "└─", "│ "
	if o.ASCII {
		branch, right, vert = "|-", "`-", "| "
	}
	type line struct {
		cells []string
		more  []string // further mount points, on lines of their own
		cont  string   // the tree art of those lines
	}
	var lines []line
	var walk func(n *BlockDev, art string, last, root bool)
	walk = func(n *BlockDev, art string, last, root bool) {
		prefix, childArt := "", ""
		if !root {
			prefix = art + branch
			childArt = art + vert
			if last {
				prefix, childArt = art+right, art+"  "
			}
		}
		mounts := n.MountPoints
		if o.V232 && len(mounts) > 1 {
			mounts = mounts[:1]
		}
		first := ""
		if len(mounts) > 0 {
			first = mounts[0]
		}
		var cells []string
		for _, c := range cols {
			v := ""
			switch c.name {
			case "NAME":
				v = prefix + n.Name
			case "MAJ:MIN":
				maj, min, _ := strings.Cut(n.MajMin, ":")
				v = fmt.Sprintf("%3s:%-3s", maj, min)
			case "RM":
				v = flag(n.RM)
			case "SIZE":
				v = size(n.Size)
			case "RO":
				v = flag(n.RO)
			case "TYPE":
				v = n.Type
			case "MOUNTPOINT", "MOUNTPOINTS":
				v = first
			case "FSTYPE":
				v = n.FSType
			case "FSVER":
				v = n.FSVer
			case "LABEL":
				v = n.Label
			case "UUID":
				v = n.UUID
			case "FSAVAIL":
				if n.FSAvail != nil {
					if *n.FSAvail == 0 {
						v = "0"
					} else {
						v = size(*n.FSAvail)
					}
				}
			case "FSUSE%":
				v = n.FSUsePct
			}
			cells = append(cells, v)
		}
		l := line{cells: cells}
		if len(mounts) > 1 {
			l.more = mounts[1:]
			// Continuation lines: the tree art of the line itself (a vertical
			// line where it has later siblings), then one for its children.
			l.cont = childArt
			if root {
				l.cont = ""
			}
			if len(n.Children) > 0 {
				l.cont += vert
			}
		}
		lines = append(lines, l)
		for i, c := range n.Children {
			walk(c, childArt, i == len(n.Children)-1, false)
		}
	}
	for _, r := range roots {
		walk(r, "", false, true)
	}
	width := make([]int, len(cols))
	for i, c := range cols {
		head := utf8.RuneCountInString(c.name)
		if o.NoHeadings {
			head = 1
		}
		data := 0
		for _, l := range lines {
			data = max(data, utf8.RuneCountInString(l.cells[i]))
			if i == len(cols)-1 {
				for _, m := range l.more {
					data = max(data, utf8.RuneCountInString(m))
				}
			}
		}
		width[i] = scolsWidth(head, data, c.hint)
	}
	print := func(cells []string) {
		var b strings.Builder
		for i, v := range cells {
			pad := width[i] - utf8.RuneCountInString(v)
			switch {
			case cols[i].right:
				b.WriteString(strings.Repeat(" ", max(pad, 0)) + v)
			case i == len(cols)-1:
				b.WriteString(v)
			default:
				b.WriteString(v + strings.Repeat(" ", max(pad, 0)))
			}
			if i < len(cols)-1 {
				b.WriteByte(' ')
			}
		}
		fmt.Fprintln(w, b.String())
	}
	if !o.NoHeadings {
		head := make([]string, len(cols))
		for i, c := range cols {
			head[i] = c.name
		}
		print(head)
	}
	for _, l := range lines {
		print(l.cells)
		for _, m := range l.more {
			cells := make([]string, len(cols))
			cells[0] = l.cont
			cells[len(cols)-1] = m
			print(cells)
		}
	}
}

// AddMountLabels sets each mount's file system label (mount -l), from the
// block device with its device number as recorded at t.
func AddMountLabels(db *store.DB, t int64, rows []MountRow) error {
	devs, err := blockDevsAt(db, t)
	if err != nil {
		return err
	}
	if len(devs) == 0 {
		return fmt.Errorf("mount -l: labels not recorded at %s (recorded since schema 9)", FormatMS(t))
	}
	label := map[string]string{}
	for _, d := range devs {
		if d.Label != "" {
			label[fmt.Sprintf("%d:%d", d.Maj, d.Min)] = udevDecode(d.Label)
		}
	}
	for i := range rows {
		rows[i].Label = label[rows[i].Dev]
	}
	return nil
}
