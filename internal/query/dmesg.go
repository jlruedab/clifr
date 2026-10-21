package query

import (
	"database/sql"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"clifr/internal/store"
)

// Kmsg is a kernel log record with what dmesg -T needs: the clocks of the
// buffer's state recorded last before the moment asked for.
type Kmsg struct {
	TS     int64  `json:"read_ms"`
	Seq    int64  `json:"seq"`
	Prio   int    `json:"prio"`
	MonoUS int64  `json:"mono_us"`
	Caller string `json:"caller,omitempty"`
	Msg    string `json:"msg"` // as /dev/kmsg escapes it
	BootUS int64  `json:"-"`
	SuspUS int64  `json:"-"`
}

// KmsgAt is the kernel log as dmesg would have printed it at t: the
// records of the boot running at t, written by then and not yet pushed out
// of the buffer (the oldest record left, recorded at most 10 s after
// records arrive). A record read again by a later clifrd run of the same boot
// counts once.
func KmsgAt(db *store.DB, t int64) ([]Kmsg, error) {
	var boot string
	var oldest, bootUS, suspUS sql.NullInt64
	err := db.QueryRow(`SELECT boot_id, seq, boot_us, susp_us FROM kmsg WHERE kind = 'ring' AND ts <= ? ORDER BY ts DESC LIMIT 1`, t).
		Scan(&boot, &oldest, &bootUS, &suspUS)
	if err != nil {
		return nil, fmt.Errorf("the kernel log is not recorded at or before %s (recorded since schema 6)", FormatMS(t))
	}
	return kmsgQuery(db, `boot_id = ? AND ts <= ? AND seq >= ?`, []any{boot, t, oldest.Int64}, bootUS.Int64, suspUS.Int64)
}

// KmsgBetween is the records read from a to b (all boots), each with the
// clocks of its own boot.
func KmsgBetween(db *store.DB, a, b int64) ([]Kmsg, error) {
	rows, err := db.Query(`SELECT boot_id, arg_max(boot_us, ts), arg_max(susp_us, ts) FROM kmsg WHERE kind = 'ring' AND ts <= ?
		GROUP BY boot_id ORDER BY min(ts)`, b)
	if err != nil {
		return nil, err
	}
	type clocks struct {
		id         string
		boot, susp int64
	}
	var boots []clocks
	for rows.Next() {
		var c clocks
		if err := rows.Scan(&c.id, &c.boot, &c.susp); err != nil {
			rows.Close()
			return nil, err
		}
		boots = append(boots, c)
	}
	rows.Close()
	var out []Kmsg
	for _, c := range boots {
		k, err := kmsgQuery(db, `boot_id = ? AND ts <= ?`, []any{c.id, b}, c.boot, c.susp)
		if err != nil {
			return nil, err
		}
		for _, r := range k {
			if r.TS >= a {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

func kmsgQuery(db *store.DB, where string, args []any, bootUS, suspUS int64) ([]Kmsg, error) {
	rows, err := db.Query(`SELECT seq, min(ts), arg_min(prio, ts), arg_min(mono_us, ts), arg_min(caller, ts), arg_min(msg, ts)
		FROM kmsg WHERE kind = 'msg' AND `+where+` GROUP BY seq ORDER BY seq`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Kmsg
	for rows.Next() {
		k := Kmsg{BootUS: bootUS, SuspUS: suspUS}
		if err := rows.Scan(&k.Seq, &k.TS, &k.Prio, &k.MonoUS, &k.Caller, &k.Msg); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// DmesgOptions: -T (ctime), -t (no time), -x (decode).
type DmesgOptions struct {
	Ctime, NoTime, Decode bool
}

var (
	kmsgFacilities = []string{"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
		"authpriv", "ftp", "res0", "res1", "res2", "res3", "local0", "local1", "local2", "local3", "local4", "local5",
		"local6", "local7"}
	kmsgLevels = []string{"emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"}
)

// recordTime is when a record was written as dmesg -T computes it: the boot
// time plus the suspended time plus the kernel's timestamp, in µs since
// util-linux 2.41 (2.37: whole seconds each; 2.32: no suspended time).
func recordTime(k Kmsg, st ToolStyle) time.Time {
	switch st.DmesgTime {
	case "2.32":
		return time.Unix(floorDiv(k.BootUS, 1e6)+k.MonoUS/1e6, 0)
	case "2.37":
		return time.Unix(floorDiv(k.BootUS, 1e6)+k.SuspUS/1e6+k.MonoUS/1e6, 0)
	}
	return time.Unix(floorDiv(k.BootUS+k.SuspUS+k.MonoUS, 1e6), 0)
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && a < 0 {
		q--
	}
	return q
}

// callerWidth: the PRINTK_CALLER field's width in util-linux 2.41, the
// length of /proc/sys/kernel/pid_max with its newline ("4194304\n", what
// systemd sets since 243).
const callerWidth = 8

// PrintDmesg prints records like util-linux dmesg (without colors: as into
// a pipe).
func PrintDmesg(w io.Writer, recs []Kmsg, o DmesgOptions, st ToolStyle) {
	var b strings.Builder
	for _, k := range recs {
		msg := unhexmangle(k.Msg)
		if msg == "" {
			b.WriteString("\n")
			continue
		}
		indent := 0
		if o.Decode && k.Prio>>3 < len(kmsgFacilities) {
			s := fmt.Sprintf("%-6s:%-6s: ", kmsgFacilities[k.Prio>>3], kmsgLevels[k.Prio&7])
			b.WriteString(s)
			indent += len(s)
		}
		switch {
		case o.NoTime:
		case o.Ctime:
			s := "[" + recordTime(k, st).In(time.Local).Format("Mon Jan _2 15:04:05 2006") + "] "
			b.WriteString(s)
			indent += len(s)
		default:
			s := fmt.Sprintf("[%5d.%06d] ", k.MonoUS/1e6, k.MonoUS%1e6)
			b.WriteString(s)
			indent += len(s)
		}
		if k.Caller != "" && st.DmesgCaller {
			s := fmt.Sprintf("[%*s] ", callerWidth, k.Caller)
			b.WriteString(s)
			indent += len(s)
		}
		safeWrite(&b, msg, indent)
		b.WriteString("\n")
	}
	io.WriteString(w, b.String())
}

// unhexmangle decodes the \xNN escapes of /dev/kmsg.
func unhexmangle(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' && isHex(s[i+2]) && isHex(s[i+3]) {
			b.WriteByte(unhex(s[i+2])<<4 | unhex(s[i+3]))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c >= 'a':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// safeWrite is dmesg's safe_fwrite in a UTF-8 locale: what is not printable
// (nor space) as \xNN per byte; a line break followed by more text indented
// under the message.
func safeWrite(b *strings.Builder, s string, indent int) {
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case s[i] == 0, r == utf8.RuneError && n <= 1, !unicode.IsPrint(r) && !unicode.IsSpace(r):
			for _, c := range []byte(s[i : i+max(n, 1)]) {
				fmt.Fprintf(b, `\x%02x`, c)
			}
		case r == '\n' && i+1 < len(s) && indent > 0:
			b.WriteString("\n" + strings.Repeat(" ", indent))
		default:
			b.WriteString(s[i : i+n])
		}
		i += max(n, 1)
	}
}
