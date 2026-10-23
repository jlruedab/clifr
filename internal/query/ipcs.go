package query

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// IPC is the System V IPC objects of /proc/sysvipc at a moment: the
// fields of each line by the files' own column names.
type IPC struct {
	Msg, Sem, Shm []map[string]int64
	pageBytes     int64
}

// IPCAt returns /proc/sysvipc/{msg,sem,shm} at the system sample at or
// before t.
func IPCAt(db *store.DB, t int64) (*IPC, error) {
	out := &IPC{pageBytes: PageBytes(db)}
	for _, src := range []struct {
		name string
		dst  *[]map[string]int64
	}{{"sysvipc/msg", &out.Msg}, {"sysvipc/sem", &out.Sem}, {"sysvipc/shm", &out.Shm}} {
		lines, _, ok, err := FileAt(db, src.name, t)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("ipcs: not recorded at %s (recorded since schema 9)", FormatMS(t))
		}
		if len(lines) == 0 {
			continue
		}
		head := strings.Fields(lines[0])
		for _, l := range lines[1:] {
			f := strings.Fields(l)
			m := map[string]int64{}
			for i, name := range head {
				if i < len(f) {
					base := 10
					if name == "perms" {
						base = 8
					}
					m[name], _ = strconv.ParseInt(f[i], base, 64)
				}
			}
			*src.dst = append(*src.dst, m)
		}
	}
	return out, nil
}

// IPCSOptions: which objects (-q, -m, -s; all without any) and -u.
type IPCSOptions struct {
	Msg, Shm, Sem, Summary bool
}

// PrintIPCS prints ipcs [-q|-m|-s] [-u] as util-linux does (the same in
// 2.32 to 2.41). Owners are the user names of the machine running clifr.
func PrintIPCS(w io.Writer, ipc *IPC, o IPCSOptions) {
	if !o.Msg && !o.Shm && !o.Sem {
		o.Msg, o.Shm, o.Sem = true, true, true
	}
	owner := func(m map[string]int64) string {
		name := UserName(int(m["uid"]), false)
		if len(name) > 10 {
			name = name[:10]
		}
		return fmt.Sprintf("%-10s", name)
	}
	key := func(m map[string]int64) string { return fmt.Sprintf("0x%08x ", uint32(m["key"])) }
	fmt.Fprintln(w)
	if o.Msg {
		if o.Summary {
			var queues, msgs, bytes int64
			for _, m := range ipc.Msg {
				queues, msgs, bytes = queues+1, msgs+m["qnum"], bytes+m["cbytes"]
			}
			fmt.Fprintf(w, "------ Messages Status --------\nallocated queues = %d\nused headers = %d\nused space = %d bytes\n", queues, msgs, bytes)
		} else {
			fmt.Fprintln(w, "------ Message Queues --------")
			fmt.Fprintf(w, "%-10s %-10s %-10s %-10s %-12s %-12s\n", "key", "msqid", "owner", "perms", "used-bytes", "messages")
			for _, m := range ipc.Msg {
				fmt.Fprintf(w, "%s%-10d %s %-10o %-12d %-12d\n", key(m), m["msqid"], owner(m), m["perms"]&0o777, m["cbytes"], m["qnum"])
			}
		}
		fmt.Fprintln(w)
	}
	if o.Shm {
		if o.Summary {
			var pages, rss, swap int64
			for _, m := range ipc.Shm {
				pages += (m["size"] + ipc.pageBytes - 1) / ipc.pageBytes
				rss, swap = rss+m["rss"], swap+m["swap"]
			}
			fmt.Fprintf(w, "------ Shared Memory Status --------\nsegments allocated %d\npages allocated %d\npages resident  %d\n"+
				"pages swapped   %d\nSwap performance: 0 attempts\t 0 successes\n", len(ipc.Shm), pages, rss/ipc.pageBytes, swap/ipc.pageBytes)
		} else {
			fmt.Fprintln(w, "------ Shared Memory Segments --------")
			fmt.Fprintf(w, "%-10s %-10s %-10s %-10s %-10s %-10s %-12s\n", "key", "shmid", "owner", "perms", "bytes", "nattch", "status")
			for _, m := range ipc.Shm {
				dest, locked := " ", " "
				if m["perms"]&0o1000 != 0 { // SHM_DEST
					dest = "dest"
				}
				if m["perms"]&0o2000 != 0 { // SHM_LOCKED
					locked = "locked"
				}
				fmt.Fprintf(w, "%s%-10d %s %-10o %-10d %-10d %-6s %-6s\n", key(m), m["shmid"], owner(m), m["perms"]&0o777,
					m["size"], m["nattch"], dest, locked)
			}
		}
		fmt.Fprintln(w)
	}
	if o.Sem {
		if o.Summary {
			var sems int64
			for _, m := range ipc.Sem {
				sems += m["nsems"]
			}
			fmt.Fprintf(w, "------ Semaphore Status --------\nused arrays = %d\nallocated semaphores = %d\n", len(ipc.Sem), sems)
		} else {
			fmt.Fprintln(w, "------ Semaphore Arrays --------")
			fmt.Fprintf(w, "%-10s %-10s %-10s %-10s %-10s\n", "key", "semid", "owner", "perms", "nsems")
			for _, m := range ipc.Sem {
				fmt.Fprintf(w, "%s%-10d %s %-10o %-10d\n", key(m), m["semid"], owner(m), m["perms"]&0o777, m["nsems"])
			}
		}
		fmt.Fprintln(w)
	}
}

// PageBytes is the recorded host's page size (4096 if not recorded).
func PageBytes(db *store.DB) int64 {
	if kb := metaInt(db, "page_kb"); kb > 0 {
		return kb * 1024
	}
	return 4096
}
