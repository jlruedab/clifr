// lsipc, following util-linux's sys-utils/lsipc.c and ipcutils.c (2.32,
// 2.37, 2.39, 2.41; GPL-2.0-or-later; packaging/notices/util-linux.txt):
// its columns, default column sets, the global summary and the pretty
// output of --id; the table layout is libsmartcols' into a pipe (swaps.go).

package query

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"clifr/internal/store"
)

// LsipcOpts are lsipc's options.
type LsipcOpts struct {
	Kind     string // "" the global summary, or "msg", "shm", "sem"
	Global   bool   // -g with -q/-m/-s: that kind's summary lines
	Bytes    bool   // -b
	Creator  bool   // -c
	Times    bool   // -t
	NumPerms bool   // -P
	ID       int    // -i (-1: all)
	Cols     []string
	ColsAdd  bool // -o +LIST: added to the columns (else they replace them)
	NoHead   bool
	Raw      bool   // -r
	Export   bool   // -e
	Newline  bool   // -n
	TimeMode string // --time-format: short, full, iso
	Version  string // ToolStyle.Lsipc: "" 2.41, "2.39", "2.37", "2.32"
}

// lsipcCol is one of lsipc's columns: its name, pretty name (--id) and
// whether it is right-aligned.
type lsipcCol struct {
	name, pretty string
	right        bool
}

// lsipcCols in coldescs' order (the order --id prints them).
var lsipcCols = []lsipcCol{
	{"KEY", "Key", false}, {"ID", "ID", false}, {"OWNER", "Owner", true}, {"PERMS", "Permissions", true},
	{"CUID", "Creator UID", true}, {"CUSER", "Creator user", false}, {"CGID", "Creator GID", true},
	{"CGROUP", "Creator group", false}, {"UID", "UID", true}, {"USER", "User name", false}, {"GID", "GID", true},
	{"GROUP", "Group name", false}, {"CTIME", "Last change", true},
	{"NAME", "Name", false}, {"MTIME", "Last action", true}, // 2.41 (POSIX)
	{"USEDBYTES", "Bytes used", true}, {"MSGS", "Messages", false}, {"SEND", "Msg sent", true},
	{"RECV", "Msg received", true}, {"LSPID", "Msg sender", true}, {"LRPID", "Msg receiver", true},
	{"SIZE", "Segment size", true}, {"NATTCH", "Attached processes", true}, {"STATUS", "Status", false},
	{"ATTACH", "Attach time", true}, {"DETACH", "Detach time", true}, {"COMMAND", "Creator command", false},
	{"CPID", "Creator PID", true}, {"LPID", "Last user PID", true},
	{"NSEMS", "Semaphores", true}, {"OTIME", "Last operation", true},
	{"RESOURCE", "Resource", false}, {"DESCRIPTION", "Description", false}, {"USED", "Used", true},
	{"USE%", "Use", true}, {"LIMIT", "Limit", true},
}

// lsipcKindCols: the columns of each kind beyond the shared ones (KEY ..
// CTIME): lsipc sets no others and refuses them with -o.
var lsipcKindCols = map[string]string{
	"msg": " USEDBYTES MSGS SEND RECV LSPID LRPID ",
	"shm": " SIZE NATTCH STATUS ATTACH DETACH COMMAND CPID LPID ",
	"sem": " NSEMS OTIME ",
	"":    " RESOURCE DESCRIPTION USED USE% LIMIT ",
}

// LsipcApplies reports whether column name applies to kind ("" global).
func LsipcApplies(name, kind string) bool {
	for _, c := range lsipcCols[:13] {
		if c.name == name {
			return kind != ""
		}
	}
	return strings.Contains(lsipcKindCols[kind], " "+name+" ")
}

func lsipcColOf(name string) (lsipcCol, bool) {
	for _, c := range lsipcCols {
		if c.name == name {
			return c, true
		}
	}
	return lsipcCol{}, false
}

// IPCLimits are the System V (and POSIX message queue) limits lsipc reads
// from /proc/sys, as the sysctl snapshot recorded them (every minute).
type IPCLimits struct {
	MsgMNI, MsgMax, MsgMNB                 uint64
	ShmMNI, ShmAll, ShmMax, ShmMin         uint64
	SemMSL, SemMNS, SemOPM, SemMNI, SemVMX uint64
	MqMNI, MqMax, MqMNB                    uint64
}

// IPCLimitsAt reads the limits from the sysctl snapshot at or before t.
func IPCLimitsAt(db *store.DB, t int64) (IPCLimits, bool, error) {
	lines, _, ok, err := FileAt(db, "sysctl", t)
	if err != nil || !ok {
		return IPCLimits{}, false, err
	}
	v := map[string]string{}
	for _, l := range lines {
		if k, val, found := strings.Cut(l, " = "); found {
			v[k] = val
		}
	}
	u := func(k string) uint64 { n, _ := strconv.ParseUint(strings.TrimSpace(v[k]), 10, 64); return n }
	lim := IPCLimits{MsgMNI: u("kernel.msgmni"), MsgMax: u("kernel.msgmax"), MsgMNB: u("kernel.msgmnb"),
		ShmMNI: u("kernel.shmmni"), ShmAll: u("kernel.shmall"), ShmMax: u("kernel.shmmax"), ShmMin: 1, SemVMX: 32767,
		MqMNI: u("fs.mqueue.queues_max"), MqMax: u("fs.mqueue.msgsize_max"), MqMNB: u("fs.mqueue.msg_max")}
	if f := strings.Fields(v["kernel.sem"]); len(f) == 4 {
		p := func(s string) uint64 { n, _ := strconv.ParseUint(s, 10, 64); return n }
		lim.SemMSL, lim.SemMNS, lim.SemOPM, lim.SemMNI = p(f[0]), p(f[1]), p(f[2]), p(f[3])
	}
	return lim, true, nil
}

// LsipcTable is what lsipc prints: the columns and each row's cells ("" a
// cell libsmartcols leaves empty; nil cells are not set: --id leaves them
// out).
type LsipcTable struct {
	Cols []string
	Rows [][]*string `json:"-"`
	// Pretty: --id's output (one object, "Name: value" lines).
	Pretty bool `json:"-"`
	// MqUsedUnknown: 2.41's POSIX queue count (/dev/mqueue) is not recorded.
	MqUsedUnknown bool `json:"-"`
	// Objects for --json: each row by column name.
	Objects []map[string]string `json:"objects"`
}

// cmdAt is the command line of the process pid alive at t ("" when none
// recorded: lsipc's pid_get_cmdline gives nothing for a process gone).
func cmdAt(db *store.DB, pid int64, t int64) *string {
	var c string
	err := db.QueryRow(`SELECT cmdline FROM processes WHERE pid = ? AND first_seen <= ? AND COALESCE(last_seen, ?) >= ?
		ORDER BY first_seen DESC LIMIT 1`, pid, t, t, t).Scan(&c)
	if err != nil || c == "" {
		return nil
	}
	return &c
}

// lsipcTime is make_time: short (today HH:MM, this year MonDD, else
// YYYY-MonDD), full (asctime) or iso.
func lsipcTime(mode string, sec, now int64) string {
	t, n := time.Unix(sec, 0), time.Unix(now/1000, 0)
	switch mode {
	case "full":
		return t.Format("Mon Jan _2 15:04:05 2006")
	case "iso":
		return t.Format("2006-01-02T15:04:05-07:00")
	}
	switch {
	case t.YearDay() == n.YearDay() && t.Year() == n.Year():
		return t.Format("15:04")
	case t.Year() == n.Year():
		return t.Format("Jan02")
	}
	return t.Format("2006-Jan02")
}

// strmode is xstrmode for permission bits: rw-r--r--.
func strmode(m int64) string {
	const s = "rwxrwxrwx"
	b := []byte("---------")
	for i := 0; i < 9; i++ {
		if m&(1<<(8-i)) != 0 {
			b[i] = s[i]
		}
	}
	return string(b)
}

// LsipcAt builds lsipc's table at t (the System V objects at the system
// sample at or before t, the limits as last read).
func LsipcAt(db *store.DB, t int64, o LsipcOpts) (*LsipcTable, error) {
	ipc, err := IPCAt(db, t)
	if err != nil {
		return nil, err
	}
	tb := &LsipcTable{Pretty: o.ID >= 0 && !o.Raw && !o.Export && !o.Newline}
	mode := o.TimeMode
	if mode == "" {
		mode = "short"
		if tb.Pretty {
			mode = "full"
		}
	}
	str := func(s string) *string { return &s }
	if o.Kind == "" || o.Global {
		lim, ok, err := IPCLimitsAt(db, t)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("lsipc: the IPC limits (sysctl) are not recorded at %s (recorded since schema 9)", FormatMS(t))
		}
		// -g with -q, -m or -s: that kind's columns stay before the
		// summary's (lsipc adds both), only the summary's are filled.
		tb.Cols = append(lsipcDefault(o.Kind, o), "RESOURCE", "DESCRIPTION", "LIMIT", "USED", "USE%")
		tb.Cols = o.withCols(tb.Cols)
		human := o.Version != "2.32" // 2.37+: byte limits as sizes
		add := func(res, desc string, used, limit uint64, usage, bytes bool) {
			v := map[string]*string{"RESOURCE": str(res), "DESCRIPTION": str(desc), "USED": str("-"), "USE%": str("-")}
			if bytes && human && !o.Bytes {
				v["LIMIT"] = str(utilHuman(int64(limit)))
			} else {
				v["LIMIT"] = str(strconv.FormatUint(limit, 10))
			}
			if usage {
				if bytes && human && !o.Bytes {
					v["USED"] = str(utilHuman(int64(used)))
				} else {
					v["USED"] = str(strconv.FormatUint(used, 10))
				}
				v["USE%"] = str(fmt.Sprintf("%2.2f%%", float64(used)/float64(limit)*100))
			}
			r := make([]*string, len(tb.Cols))
			for i, c := range tb.Cols {
				r[i] = v[c]
			}
			tb.Rows = append(tb.Rows, r)
		}
		v241 := o.Version == ""
		if o.Kind == "" || o.Kind == "msg" {
			if v241 {
				add("MSGMNI", "Number of System V message queues", uint64(len(ipc.Msg)), lim.MsgMNI, true, false)
				add("MSGMAX", "Max size of System V message (bytes)", 0, lim.MsgMax, false, true)
				add("MSGMNB", "Default max size of System V queue (bytes)", 0, lim.MsgMNB, false, true)
			} else {
				add("MSGMNI", "Number of message queues", uint64(len(ipc.Msg)), lim.MsgMNI, true, false)
				add("MSGMAX", "Max size of message (bytes)", 0, lim.MsgMax, false, true)
				add("MSGMNB", "Default max size of queue (bytes)", 0, lim.MsgMNB, false, true)
			}
		}
		if o.Kind == "" && v241 { // POSIX message queues: their number is not recorded
			add("MQUMNI", "Number of POSIX message queues", 0, lim.MqMNI, false, false)
			add("MQUMAX", "Max size of POSIX message (bytes)", 0, lim.MqMax, false, true)
			add("MQUMNB", "Number of messages in POSIX message queue", 0, lim.MqMNB, false, false)
			tb.MqUsedUnknown = true
		}
		if o.Kind == "" || o.Kind == "shm" {
			var size uint64
			for _, m := range ipc.Shm {
				size += uint64(m["size"])
			}
			add("SHMMNI", "Shared memory segments", uint64(len(ipc.Shm)), lim.ShmMNI, true, false)
			add("SHMALL", "Shared memory pages", size/uint64(ipc.pageBytes), lim.ShmAll, true, false)
			add("SHMMAX", "Max size of shared memory segment (bytes)", 0, lim.ShmMax, false, true)
			add("SHMMIN", "Min size of shared memory segment (bytes)", 0, lim.ShmMin, false, true)
		}
		if o.Kind == "" || o.Kind == "sem" {
			var n uint64
			for _, m := range ipc.Sem {
				n += uint64(m["nsems"])
			}
			add("SEMMNI", "Number of semaphore identifiers", uint64(len(ipc.Sem)), lim.SemMNI, true, false)
			add("SEMMNS", "Total number of semaphores", n, lim.SemMNS, true, false)
			add("SEMMSL", "Max semaphores per semaphore set.", 0, lim.SemMSL, false, false)
			add("SEMOPM", "Max number of operations per semop(2)", 0, lim.SemOPM, false, false)
			add("SEMVMX", "Semaphore max value", 0, lim.SemVMX, false, false)
		}
		tb.objects()
		return tb, nil
	}

	// The objects of one kind.
	var objs []map[string]int64
	idKey := map[string]string{"msg": "msqid", "shm": "shmid", "sem": "semid"}[o.Kind]
	objs = map[string][]map[string]int64{"msg": ipc.Msg, "shm": ipc.Shm, "sem": ipc.Sem}[o.Kind]
	tb.Cols = lsipcDefault(o.Kind, o)
	if tb.Pretty && len(o.Cols) == 0 && !o.Creator && !o.Times {
		tb.Cols = nil
		for _, c := range lsipcCols {
			tb.Cols = append(tb.Cols, c.name)
		}
	} else {
		if o.Creator {
			tb.Cols = append(tb.Cols, "CUID", "CGID", "UID", "GID")
		}
		if o.Times {
			switch o.Kind {
			case "msg":
				tb.Cols = append(tb.Cols, "SEND", "RECV", "CTIME")
			case "shm": // COMMAND stays last
				tb.Cols = append(tb.Cols[:len(tb.Cols)-1], "ATTACH", "DETACH", "COMMAND")
			case "sem":
				tb.Cols = append(tb.Cols, "OTIME", "CTIME")
			}
		}
		tb.Cols = o.withCols(tb.Cols)
	}
	found := false
	for _, m := range objs {
		if o.ID >= 0 && m[idKey] != int64(o.ID) {
			continue
		}
		found = true
		tm := func(k string) *string {
			if m[k] == 0 {
				return nil
			}
			return str(lsipcTime(mode, m[k], t))
		}
		row := make([]*string, len(tb.Cols))
		for i, c := range tb.Cols {
			if !LsipcApplies(c, o.Kind) {
				continue
			}
			switch c {
			case "KEY":
				row[i] = str(fmt.Sprintf("0x%08x", uint32(m["key"])))
			case "ID":
				row[i] = str(strconv.FormatInt(m[idKey], 10))
			case "OWNER":
				row[i] = str(UserName(int(m["uid"]), false))
			case "PERMS":
				switch {
				case !o.NumPerms:
					row[i] = str(strmode(m["perms"] & 0777))
				case o.Kind == "msg": // lsipc.c sets no value for a queue's -P (2.32 to 2.41)
				default:
					row[i] = str(fmt.Sprintf("%#o", m["perms"]&0777))
				}
			case "CUID":
				row[i] = str(strconv.FormatInt(m["cuid"], 10))
			case "CGID":
				row[i] = str(strconv.FormatInt(m["cgid"], 10))
			case "UID":
				row[i] = str(strconv.FormatInt(m["uid"], 10))
			case "GID":
				row[i] = str(strconv.FormatInt(m["gid"], 10))
			case "CUSER":
				if n := UserName(int(m["cuid"]), false); n != strconv.FormatInt(m["cuid"], 10) {
					row[i] = str(n)
				}
			case "USER":
				if n := UserName(int(m["uid"]), false); n != strconv.FormatInt(m["uid"], 10) {
					row[i] = str(n)
				}
			case "CGROUP":
				if n := GroupName(int(m["cgid"])); n != strconv.FormatInt(m["cgid"], 10) {
					row[i] = str(n)
				}
			case "GROUP":
				if n := GroupName(int(m["gid"])); n != strconv.FormatInt(m["gid"], 10) {
					row[i] = str(n)
				}
			case "CTIME":
				row[i] = tm("ctime")
			case "USEDBYTES": // 2.32: a number
				row[i] = str(lsipcSize(m["cbytes"], o.Bytes || o.Version == "2.32"))
			case "MSGS":
				row[i] = str(strconv.FormatInt(m["qnum"], 10))
			case "SEND":
				row[i] = tm("stime")
			case "RECV":
				row[i] = tm("rtime")
			case "LSPID":
				row[i] = str(strconv.FormatInt(m["lspid"], 10))
			case "LRPID":
				row[i] = str(strconv.FormatInt(m["lrpid"], 10))
			case "SIZE":
				row[i] = str(lsipcSize(m["size"], o.Bytes))
			case "NATTCH":
				row[i] = str(strconv.FormatInt(m["nattch"], 10))
			case "STATUS":
				row[i] = str(shmStatus(m["perms"]))
			case "ATTACH":
				row[i] = tm("atime")
			case "DETACH":
				row[i] = tm("dtime")
			case "CPID":
				row[i] = str(strconv.FormatInt(m["cpid"], 10))
			case "LPID":
				row[i] = str(strconv.FormatInt(m["lpid"], 10))
			case "COMMAND":
				row[i] = cmdAt(db, m["cpid"], t)
			case "NSEMS":
				row[i] = str(strconv.FormatInt(m["nsems"], 10))
			case "OTIME":
				row[i] = tm("otime")
			}
		}
		tb.Rows = append(tb.Rows, row)
	}
	if o.ID >= 0 && !found {
		return nil, fmt.Errorf("lsipc: id %d not found", o.ID)
	}
	tb.objects()
	return tb, nil
}

// lsipcDefault: the columns -q, -m or -s set (none for the summary alone).
func lsipcDefault(kind string, o LsipcOpts) []string {
	switch kind {
	case "msg":
		return []string{"KEY", "ID", "PERMS", "OWNER", "USEDBYTES", "MSGS", "LSPID", "LRPID"}
	case "shm":
		return []string{"KEY", "ID", "PERMS", "OWNER", "SIZE", "NATTCH", "STATUS", "CTIME", "CPID", "LPID", "COMMAND"}
	case "sem":
		return []string{"KEY", "ID", "PERMS", "OWNER", "NSEMS"}
	}
	return nil
}

// withCols applies -o: its columns replace cols, or (+LIST) follow them.
func (o LsipcOpts) withCols(cols []string) []string {
	if len(o.Cols) == 0 {
		return cols
	}
	if o.ColsAdd {
		return append(cols, o.Cols...)
	}
	return append([]string(nil), o.Cols...)
}

func lsipcSize(n int64, bytes bool) string {
	if bytes {
		return strconv.FormatInt(n, 10)
	}
	return utilHuman(n)
}

// shmStatus is the STATUS column: dest, locked, hugetlb, noreserve, the
// comma only after dest (as lsipc.c sets it).
func shmStatus(perms int64) string {
	var b strings.Builder
	comma := false
	if perms&01000 != 0 { // SHM_DEST
		b.WriteString("dest")
		comma = true
	}
	for _, f := range []struct {
		bit  int64
		name string
	}{{02000, "locked"}, {04000, "hugetlb"}, {010000, "noreserve"}} {
		if perms&f.bit != 0 {
			if comma {
				b.WriteByte(',')
			}
			b.WriteString(f.name)
		}
	}
	return b.String()
}

func (tb *LsipcTable) objects() {
	tb.Objects = []map[string]string{}
	for _, r := range tb.Rows {
		m := map[string]string{}
		for i, c := range tb.Cols {
			if r[i] != nil {
				m[strings.ToLower(c)] = *r[i]
			}
		}
		tb.Objects = append(tb.Objects, m)
	}
}

// PrintLsipc prints the table as lsipc does into a pipe: libsmartcols'
// layout, -r raw, -e/-n export, or --id's "Name:   value" lines.
func PrintLsipc(w io.Writer, tb *LsipcTable, o LsipcOpts) {
	if tb.Pretty {
		for _, r := range tb.Rows {
			for i, c := range tb.Cols {
				if r[i] == nil {
					continue
				}
				col, _ := lsipcColOf(c)
				fmt.Fprintf(w, "%s:%*c%-36s\n", col.pretty, 35-len(col.pretty), ' ', *r[i])
			}
		}
		return
	}
	cell := func(r []*string, i int) string {
		if r[i] == nil {
			return ""
		}
		return scolsEncode(*r[i])
	}
	if o.Export || o.Newline {
		sep := " "
		if o.Newline {
			sep = "\n"
		}
		for _, r := range tb.Rows {
			var parts []string
			for i, c := range tb.Cols {
				parts = append(parts, fmt.Sprintf("%s=%q", c, cell(r, i)))
			}
			fmt.Fprintln(w, strings.Join(parts, sep))
		}
		return
	}
	// Before util-linux 2.41 the header sets the widths even when not
	// printed (--noheadings); 2.41's libsmartcols leaves it out.
	rows := [][]string{tb.Cols}
	if o.NoHead && o.Version == "" {
		rows = rows[:0]
	}
	for _, r := range tb.Rows {
		cells := make([]string, len(tb.Cols))
		for i := range tb.Cols {
			cells[i] = cell(r, i)
		}
		rows = append(rows, cells)
	}
	if len(tb.Rows) == 0 {
		return // libsmartcols prints nothing for an empty table
	}
	var b strings.Builder
	printScols(&b, rows, func(i int) bool { c, _ := lsipcColOf(tb.Cols[i]); return c.right }, o.Raw)
	out := b.String()
	if o.NoHead && o.Version != "" {
		_, out, _ = strings.Cut(out, "\n")
	}
	io.WriteString(w, out)
}

// LsipcColumn reports whether name is one of lsipc's columns.
func LsipcColumn(name string) (string, bool) {
	c, ok := lsipcColOf(name)
	return c.name, ok
}
