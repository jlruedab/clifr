package query

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// Lock is a file lock as lslocks shows it.
type Lock struct {
	Command string `json:"command"`
	PID     int    `json:"pid"`
	Type    string `json:"type"`
	Size    int64  `json:"size"`
	Sized   bool   `json:"-"` // the file was found (Size is its size)
	Mode    string `json:"mode"`
	M       int    `json:"m"`
	Start   int64  `json:"start"`
	End     int64  `json:"end"`
	Path    string `json:"path"`
}

// LocksAt returns the locks of /proc/locks at the system sample at or
// before t in lslocks' order (the reverse of the file's), with the commands
// of the process sample at or before t. old: util-linux before 2.41, which
// does not look for the holder of an OFD lock (pid -1, "(undefined)"),
// so its path is the fallback: the mount point of its device and "...".
func LocksAt(db *store.DB, t int64, old bool) ([]Lock, error) {
	lines, _, ok, err := FileAt(db, "locks", t)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("lslocks: locks not recorded at %s (recorded since schema 9)", FormatMS(t))
	}
	comm := map[int]string{}
	if s, err := SnapshotAt(db, t, false); err == nil {
		if procs, err := processesAt(db, s, s); err == nil {
			for _, p := range procs {
				comm[p.pid] = p.comm
			}
		}
	}
	var mounts []MountRow
	var out []Lock
	for i := len(lines) - 1; i >= 0; i-- {
		parts := strings.Split(lines[i], "\t")
		for len(parts) < 5 {
			parts = append(parts, "")
		}
		f := strings.Fields(parts[0])
		blocked := len(f) > 0 && f[0] == "->"
		if blocked {
			f = f[1:]
		}
		if len(f) < 7 {
			continue
		}
		l := Lock{Type: f[0], Mode: f[2], Path: parts[1]}
		if blocked {
			l.Mode += "*"
		}
		if strings.HasPrefix(f[1], "M") {
			l.M = 1
		}
		l.PID, _ = strconv.Atoi(f[3])
		if f[5] != "EOF" {
			l.Start, _ = strconv.ParseInt(f[5], 10, 64)
		}
		if f[6] != "EOF" {
			l.End, _ = strconv.ParseInt(f[6], 10, 64)
		}
		l.Size, _ = strconv.ParseInt(parts[2], 10, 64)
		l.Sized = parts[2] != ""
		switch {
		case l.PID > 0:
			if c, found := comm[l.PID]; found {
				l.Command = c
			} else {
				l.Command = "(unknown)"
			}
		case parts[3] != "" && !old && !blocked:
			l.PID, _ = strconv.Atoi(parts[3])
			l.Command = parts[4]
		default:
			l.Command, l.Path, l.Size, l.Sized = "(undefined)", "", 0, false
		}
		if l.Path == "" {
			// lslocks' fallback: the newest mount of the device, and "...".
			if mounts == nil {
				mounts, _ = MountsAt(db, t)
			}
			dev := f[4][:strings.LastIndexByte(f[4], ':')]
			if ma, mi, ok := strings.Cut(dev, ":"); ok {
				a, _ := strconv.ParseUint(ma, 16, 32)
				b, _ := strconv.ParseUint(mi, 16, 32)
				want := fmt.Sprintf("%d:%d", a, b)
				for j := len(mounts) - 1; j >= 0; j-- {
					if mounts[j].Dev == want {
						l.Path = mounts[j].Point + "..."
						break
					}
				}
			}
			l.Size, l.Sized = 0, false
		}
		out = append(out, l)
	}
	return out, nil
}

// PrintLslocks prints the locks as lslocks (libsmartcols) does into a pipe;
// nothing at all without locks. zeroSize: util-linux 2.32 prints the size
// of every file it found, an empty one as 0B (later versions leave 0
// empty).
func PrintLslocks(w io.Writer, locks []Lock, bytes, noHeadings, zeroSize bool) {
	if len(locks) == 0 {
		return
	}
	cols := []lsblkCol{{"COMMAND", 15, false}, {"PID", 5, true}, {"TYPE", 5, true}, {"SIZE", 4, true}, {"MODE", 5, false},
		{"M", 1, false}, {"START", 10, true}, {"END", 10, true}, {"PATH", 0, false}}
	rows := make([][]string, len(locks))
	for i, l := range locks {
		size := ""
		if l.Size != 0 || zeroSize && l.Sized {
			if bytes {
				size = strconv.FormatInt(l.Size, 10)
			} else {
				size = utilHuman(l.Size)
			}
		}
		rows[i] = []string{l.Command, strconv.Itoa(l.PID), l.Type, size, l.Mode, strconv.Itoa(l.M),
			strconv.FormatInt(l.Start, 10), strconv.FormatInt(l.End, 10), l.Path}
	}
	width := make([]int, len(cols))
	for i, c := range cols {
		head := len(c.name)
		if noHeadings {
			head = 1
		}
		data := 0
		for _, r := range rows {
			data = max(data, len(r[i]))
		}
		width[i] = scolsWidth(head, data, c.hint)
	}
	print := func(cells []string) {
		var b strings.Builder
		for i, v := range cells {
			switch {
			case cols[i].right:
				fmt.Fprintf(&b, "%*s", width[i], v)
			case i == len(cols)-1:
				b.WriteString(v)
			default:
				fmt.Fprintf(&b, "%-*s", width[i], v)
			}
			if i < len(cols)-1 {
				b.WriteByte(' ')
			}
		}
		fmt.Fprintln(w, b.String())
	}
	if !noHeadings {
		head := make([]string, len(cols))
		for i, c := range cols {
			head[i] = c.name
		}
		print(head)
	}
	for _, r := range rows {
		print(r)
	}
}
