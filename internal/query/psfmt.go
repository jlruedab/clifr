package query

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"clifr/internal/procfs"
)

// The ps formats besides aux: the default (PID TTY TIME CMD), -f and -o,
// with procps's column names, headings and widths.

type psCol struct {
	head  string
	width int
	right bool
	cut   string // text cut to the width when not the last column: "" no, "-" plainly, "+" ending in "+"
	val   func(r *PSRow) string
}

func dash(ok bool, s func() string) string {
	if !ok {
		return "-"
	}
	return s()
}

// psCPUTime is procps's TIME: [DD-]HH:MM:SS.
func psCPUTime(secs int64) string {
	if d := secs / 86400; d > 0 {
		return fmt.Sprintf("%d-%02d:%02d:%02d", d, secs%86400/3600, secs%3600/60, secs%60)
	}
	return fmt.Sprintf("%02d:%02d:%02d", secs/3600, secs%3600/60, secs%60)
}

// psElapsed is procps's ELAPSED: [[DD-]HH:]MM:SS.
func psElapsed(secs int64) string {
	switch {
	case secs >= 86400:
		return fmt.Sprintf("%d-%02d:%02d:%02d", secs/86400, secs%86400/3600, secs%3600/60, secs%60)
	case secs >= 3600:
		return fmt.Sprintf("%02d:%02d:%02d", secs/3600, secs%3600/60, secs%60)
	}
	return fmt.Sprintf("%02d:%02d", secs/60, secs%60)
}

var psCols map[string]psCol

func init() {
	sampled := func(r *PSRow) bool { return r.CPUTicks >= 0 }
	num := func(f func(r *PSRow) int64) func(r *PSRow) string {
		return func(r *PSRow) string { return strconv.FormatInt(f(r), 10) }
	}
	elapsed := func(r *PSRow) int64 { return r.ElapsedS }
	user := psCol{"USER", 8, false, "+", func(r *PSRow) string { return UserName(r.UIDNum, false) }}
	comm := psCol{"COMMAND", 15, false, "-", func(r *PSRow) string { return r.CommName }}
	args := psCol{"COMMAND", 27, false, "-", func(r *PSRow) string { return r.args }}
	tty := psCol{"TT", 8, false, "", func(r *PSRow) string { return r.TTY }}
	psCols = map[string]psCol{
		"pid":  {"PID", 7, true, "", num(func(r *PSRow) int64 { return int64(r.PID) })},
		"ppid": {"PPID", 7, true, "", num(func(r *PSRow) int64 { return int64(r.PPID) })},
		"uid":  {"UID", 5, true, "", num(func(r *PSRow) int64 { return int64(r.UIDNum) })},
		"user": user, "euser": user, "uname": user,
		"comm": comm, "ucomm": comm,
		"args": args, "command": args,
		"cmd": {"CMD", 27, false, "-", args.val},
		"rss": {"RSS", 5, true, "", func(r *PSRow) string {
			return dash(sampled(r), func() string { return strconv.FormatInt(r.RSS, 10) })
		}},
		"vsz": {"VSZ", 6, true, "", func(r *PSRow) string {
			return dash(sampled(r), func() string { return strconv.FormatInt(r.VSZ, 10) })
		}},
		"%cpu": {"%CPU", 4, true, "", func(r *PSRow) string { return r.CPU }},
		"%mem": {"%MEM", 4, true, "", func(r *PSRow) string { return r.Mem }},
		"c": {"C", 2, true, "", func(r *PSRow) string {
			return dash(sampled(r), func() string { return strconv.FormatUint(min(r.permille/10, 99), 10) })
		}},
		"ni": {"NI", 3, true, "", func(r *PSRow) string {
			return dash(sampled(r), func() string { return strconv.Itoa(r.Nice) })
		}},
		"nlwp": {"NLWP", 4, true, "", func(r *PSRow) string {
			return dash(sampled(r), func() string { return strconv.Itoa(r.Threads) })
		}},
		"s": {"S", 1, false, "", func(r *PSRow) string {
			return dash(sampled(r), func() string { return r.Stat[:1] })
		}},
		"stat": {"STAT", 4, false, "", func(r *PSRow) string { return r.Stat }},
		"lstart": {"STARTED", 24, true, "", func(r *PSRow) string {
			return time.UnixMilli(r.startDisp).Format("Mon Jan _2 15:04:05 2006")
		}},
		"start": {"STARTED", 8, true, "", func(r *PSRow) string {
			if r.nowMS-r.startDisp < 24*3600*1000 {
				return time.UnixMilli(r.startDisp).Format("15:04:05")
			}
			return time.UnixMilli(r.startDisp).Format("Jan 02")
		}},
		"stime":  {"STIME", 5, false, "", func(r *PSRow) string { return psStart(r.startDisp, r.nowMS) }},
		"etime":  {"ELAPSED", 11, true, "", func(r *PSRow) string { return psElapsed(elapsed(r)) }},
		"etimes": {"ELAPSED", 7, true, "", num(elapsed)},
		"time": {"TIME", 8, true, "", func(r *PSRow) string {
			return dash(sampled(r), func() string { return psCPUTime(r.CPUTicks / procfs.ClockTicks) })
		}},
		"tty": tty, "tt": tty, "tname": tty,
	}
	for alias, key := range map[string]string{"pcpu": "%cpu", "pmem": "%mem", "rssize": "rss", "vsize": "vsz",
		"nice": "ni", "thcount": "nlwp", "state": "s", "start_time": "stime", "cputime": "time", "euid": "uid"} {
		psCols[alias] = psCols[key]
	}
	psCols["rsz"] = psCol{"RSZ", 5, true, "", psCols["rss"].val}
	PSDefault, _ = ParsePSFormat("pid,tty=TTY,time,comm=CMD")
	PSFull, _ = ParsePSFormat("user=UID,pid,ppid,c,stime,tty=TTY,time,args=CMD")
}

// PSFormat is a parsed ps -o list (or the default and -f formats).
type PSFormat []psCol

// ParsePSFormat parses "pid,user:20,args=COMMAND LINE" (comma or space
// separated; KEY:WIDTH sets the width, KEY=HEADING the heading, which takes
// the rest of the item).
func ParsePSFormat(spec string) (PSFormat, error) {
	var f PSFormat
	for _, item := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' }) {
		key, head, hasHead := strings.Cut(item, "=")
		key, width, hasWidth := strings.Cut(key, ":")
		c, ok := psCols[strings.ToLower(key)]
		if !ok {
			return nil, fmt.Errorf("ps: unknown or unsupported output column %q", key)
		}
		if hasWidth {
			n, err := strconv.Atoi(width)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("ps: bad width in %q", item)
			}
			c.width = n
		}
		if hasHead {
			c.head = head
		}
		f = append(f, c)
	}
	if len(f) == 0 {
		return nil, fmt.Errorf("ps: empty output format")
	}
	return f, nil
}

// PSDefault is ps's format without -f or -o; PSFull is -f (set up in init,
// after the columns).
var PSDefault, PSFull PSFormat

// PrintPSFormat prints rows in format f. Like procps, a value wider than its
// column pushes the rest of the line right and later padding takes it back;
// the last column is never cut.
func PrintPSFormat(w io.Writer, rows []PSRow, f PSFormat) {
	line := func(cell func(i int, c psCol) string) {
		var b strings.Builder
		debt := 0
		for i, c := range f {
			v := cell(i, c)
			last := i == len(f)-1
			if !last && c.cut != "" && len(v) > c.width {
				if c.cut == "+" {
					v = v[:c.width-1] + "+"
				} else {
					v = v[:c.width]
				}
			}
			if i > 0 {
				b.WriteByte(' ')
			}
			pad := c.width - len(v) - debt
			debt = 0
			if pad < 0 {
				debt, pad = -pad, 0
			}
			switch {
			case c.right:
				b.WriteString(strings.Repeat(" ", pad) + v)
			case last:
				b.WriteString(v)
			default:
				b.WriteString(v + strings.Repeat(" ", pad))
			}
		}
		fmt.Fprintln(w, b.String()) // a command line may end in spaces of its own
	}
	line(func(i int, c psCol) string { return c.head })
	for k := range rows {
		line(func(i int, c psCol) string { return c.val(&rows[k]) })
	}
}

