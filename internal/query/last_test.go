package query

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// TestLastUtilLinux: util-linux last 2.32.1, 2.37.2 and 2.37.4 on a wtmp with
// a crashed boot, a shut-down one and a running one; logouts, a reused
// terminal, a crash, a shutdown, a process alive (pid 1) and a dead one
// (testdata/who/README).
func TestLastUtilLinux(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.UTC
	for _, f := range []string{"last-2.32.1.txt", "last-2.37.2.txt", "last-2.37.4.txt"} {
		data, err := os.ReadFile("testdata/who/" + f)
		if err != nil {
			t.Fatal(err)
		}
		secs := strings.Split(string(data), "=== ")
		now, _ := strconv.ParseInt(strings.Fields(secs[0])[1], 10, 64)
		var recs []WtmpRec
		cases := map[string]string{}
		var order []string
		for _, sec := range secs[1:] {
			head, body, _ := strings.Cut(sec, "\n")
			if head != "WTMP" {
				cases[head], order = body, append(order, head)
				continue
			}
			b, err := hex.DecodeString(strings.TrimSpace(body))
			if err != nil {
				t.Fatal(err)
			}
			le := binary.LittleEndian
			cs := func(b []byte) string { return string(bytes.TrimRight(b, "\x00")) }
			for i := 0; i+384 <= len(b); i += 384 {
				r := b[i : i+384]
				w := WtmpRec{Type: int(int16(le.Uint16(r))), PID: int(int32(le.Uint32(r[4:]))), Line: cs(r[8:40]),
					User: cs(r[44:76]), Host: cs(r[76:332]), TimeMS: int64(int32(le.Uint32(r[340:]))) * 1000, seq: i}
				if w.Line == "~" { // last's own reading of the pseudo-users
					switch w.User {
					case "shutdown":
						w.Type = wtShutdown
					case "reboot":
						w.Type = UtBootTime
					}
				}
				var a [16]byte
				copy(a[:], r[348:364])
				if a != [16]byte{} {
					if [12]byte(a[4:]) == [12]byte{} {
						w.Addr = netip.AddrFrom4([4]byte(a[:4])).String()
					} else {
						w.Addr = netip.AddrFrom16(a).String()
					}
				}
				recs = append(recs, w)
			}
		}
		if len(recs) != 16 || len(order) != 14 {
			t.Fatalf("%s: %d records, %d cases", f, len(recs), len(order))
		}
		alive := func(pid int) bool { return pid == 1 }
		for _, c := range order {
			var o LastOptions
			tt := now * 1000
			args := strings.Fields(c)
			for i := 0; i < len(args); i++ {
				switch a := args[i]; a {
				case "-F":
					o.Full = true
				case "-R":
					o.NoHost = true
				case "-a":
					o.HostLast = true
				case "-i":
					o.IP = true
				case "-w":
					o.Wide = true
				case "-n":
					i++
					o.Max, _ = strconv.Atoi(args[i])
				case "-t": // last -t NOW-2d: currentdate stays now, the records up to it
					tt = (now - 2*86400) * 1000
				case "-s":
					o.Since = (now - 3*86400) * 1000
				default:
					o.Names = append(o.Names, a)
				}
			}
			rows := LastAt(recs, tt, 0, o, alive)
			var b bytes.Buffer
			PrintLast(&b, rows, recs[0].TimeMS, tt, o)
			if got := b.String(); got != cases[c] {
				t.Errorf("%s: last %s:\n got:\n%s\nwant:\n%s", f, c, got, cases[c])
			}
		}
	}
}

// TestLoginRecords: wtmp's records from the recorded utmp and logind
// histories: a logout from a dead record, one seen gone, none across a
// reboot.
func TestLoginRecords(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.UTC
	const s = int64(1795000000) // seconds
	ut := func(typ, pid int, line, user, host string, sec int64) string {
		return strings.Join([]string{strconv.Itoa(typ), strconv.Itoa(pid), line, "", user, host, "0", "0", "0",
			strconv.FormatInt(sec, 10), "0", ""}, "\t")
	}
	row := func(ts int64, key string, pos int, whole bool, line string) store.SnapshotRow {
		return store.SnapshotRow{TS: ts * 1000, Source: "utmp", Key: key, Pos: pos, Full: whole, Line: line}
	}
	b := &store.Batch{Sample: store.Sample{TS: s * 1000}, Snapshots: []store.SnapshotRow{
		row(s, "#0", 0, true, ut(UtBootTime, 0, "~", "reboot", "6.8", s-100)),
		row(s, "#1", 1, true, ut(UtUserProcess, 11, "pts/0", "alice", "10.0.0.5", s-50)), // before the recording
		row(s+600, "#1", 1, false, ut(UtDeadProcess, 11, "pts/0", "", "", s+590)),        // logout: the dead record's time
		row(s+700, "#0", 0, true, ut(UtBootTime, 0, "~", "reboot", "6.8", s-100)),
		row(s+700, "#1", 1, true, ut(UtUserProcess, 12, "pts/0", "bob", "", s+695)),
		row(s+700, "#2", 2, true, ut(UtUserProcess, 13, "pts/1", "carol", "", s+699)),
		row(s+900, "#0", 0, true, ut(UtBootTime, 0, "~", "reboot", "6.8", s-100)), // carol gone: seen at s+900
		row(s+900, "#1", 1, true, ut(UtUserProcess, 12, "pts/0", "bob", "", s+695)),
		row(s+2000, "#0", 0, true, ut(UtBootTime, 0, "~", "reboot", "6.9", s+1900)), // rebooted: bob has no logout
		row(s+2000, "#1", 1, true, ut(UtUserProcess, 21, "tty1", "dave", "", s+1950)),
	}}
	db := testrec.Open(t, nil, b)
	boots := []Boot{{BootMS: (s - 100) * 1000, Kernel: "6.8", LastMS: (s + 1500) * 1000, Crashed: true},
		{BootMS: (s + 1900) * 1000, Kernel: "6.9", LastMS: (s + 2000) * 1000}}
	recs, ok, err := LoginRecords(db, (s+2000)*1000, boots)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	rows := LastAt(recs, (s+2000)*1000, (s+1900)*1000, LastOptions{}, func(pid int) bool { return pid == 21 })
	var got []string
	for _, r := range rows {
		end := r.End
		if r.LogoutMS > 0 {
			end += " " + strconv.FormatInt(r.LogoutMS/1000-s, 10)
		}
		got = append(got, r.User+" "+r.Line+" "+end)
	}
	// the first boot crashed: "crash" at its last sample (util-linux would
	// run it on, "still running"); bob's login open then: crash
	want := []string{"dave tty1 still logged in", "reboot system boot still running 2000",
		"carol pts/1 logout 900", "bob pts/0 crash 1900", "alice pts/0 logout 590",
		"reboot system boot crash 1500"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestLoginRecordsLogind: without utmp, logind's user sessions: a login at
// REALTIME, a logout when clifrd saw the session gone; manager sessions left
// out.
func TestLoginRecordsLogind(t *testing.T) {
	const s = int64(1795000000)
	row := func(ts int64, key string, pos int, line string) store.SnapshotRow {
		return store.SnapshotRow{TS: ts * 1000, Source: "logind", Key: key, Pos: pos, Full: true, Line: line}
	}
	sess := func(id, class, tty, seat string, leader int, start int64) string {
		l := "ID=" + id + "\tUID=1000\tUSER=testusr\tCLASS=" + class + "\tLEADER=" + strconv.Itoa(leader) +
			"\tREALTIME=" + strconv.FormatInt(start*1_000_000, 10)
		if tty != "" {
			l += "\tTTY=" + tty
		}
		if seat != "" {
			l += "\tSEAT=" + seat
		}
		return l
	}
	b := &store.Batch{Sample: store.Sample{TS: s * 1000}, Snapshots: []store.SnapshotRow{
		row(s, "1", 0, sess("1", "manager", "", "", 5, s-30)),
		row(s, "3", 1, sess("3", "user", "", "seat0", 6, s-20)),
		row(s+100, "1", 0, sess("1", "manager", "", "", 5, s-30)),
		row(s+100, "3", 1, sess("3", "user", "", "seat0", 6, s-20)),
		row(s+100, "7", 2, sess("7", "user", "pts/2", "", 7, s+90)),
		row(s+200, "1", 0, sess("1", "manager", "", "", 5, s-30)),
		row(s+200, "3", 1, sess("3", "user", "", "seat0", 6, s-20)),
	}}
	db := testrec.Open(t, nil, b)
	boots := []Boot{{BootMS: (s - 100) * 1000, Kernel: "6.8", LastMS: (s + 200) * 1000}}
	recs, ok, err := LoginRecords(db, (s+300)*1000, boots)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	var got []string
	for _, r := range LastAt(recs, (s+300)*1000, (s-100)*1000, LastOptions{}, func(pid int) bool { return pid == 6 }) {
		got = append(got, r.User+" "+r.Line+" "+r.End)
	}
	if want := "testusr pts/2 logout|testusr seat0 still logged in|reboot system boot still running"; strings.Join(got, "|") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}
