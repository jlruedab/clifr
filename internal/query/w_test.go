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
)

// wCapture is a reference capture of procps 3.3's w (testdata/who/README).
type wCapture struct {
	now   int64
	cases [][2]string // options, output
	s     *Sessions
	procs []wProc
}

func readWCapture(t *testing.T, path string) wCapture {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c wCapture
	c.s = &Sessions{TTY: map[string]TTYInfo{}, HaveUtmp: true, Source: "utmp"}
	secs := strings.Split(string(data), "=== ")
	c.now, _ = strconv.ParseInt(strings.Fields(secs[0])[1], 10, 64)
	for _, sec := range secs[1:] {
		head, body, _ := strings.Cut(sec, "\n")
		switch head {
		case "PROCS":
			for _, l := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
				f := strings.SplitN(l, "\t", 11)
				n := func(i int) int { v, _ := strconv.Atoi(f[i]); return v }
				comm, cmd, _ := strings.Cut(f[10], "|")
				p := wProc{pid: n(0), ppid: n(1), tty: n(2), pgrp: n(3), tpgid: n(4), euid: n(5), ruid: n(6),
					start: int64(n(7)), ticks: int64(n(8))}
				p.cmd4 = commandOf(cmd, comm, f[9])
				p.cmd3 = procpsSafe(comm)
				if cmd != "" {
					p.cmd3 = procpsSafe(cmd)
				}
				c.procs = append(c.procs, p)
			}
		case "TTYS":
			for _, l := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
				f := strings.Split(l, "\t")
				at, _ := strconv.ParseInt(f[1], 10, 64)
				mode, _ := strconv.ParseInt(f[2], 8, 64)
				maj, _ := strconv.ParseInt(f[3], 16, 64)
				mi, _ := strconv.ParseInt(f[4], 16, 64)
				c.s.TTY[f[0]] = TTYInfo{AtimeMS: at * 1000, Mode: int(mode), TTYNr: int(mi&0xff | maj<<8 | (mi&^0xff)<<12)}
			}
		case "LOGIND":
			c.s.HaveLogind, c.s.HaveUtmp, c.s.Source = true, false, "logind"
			for _, l := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
				c.s.Logind = append(c.s.Logind, parseLogindLine(l))
			}
		case "UTMP":
			b, err := hex.DecodeString(strings.TrimSpace(body))
			if err != nil {
				t.Fatal(err)
			}
			le := binary.LittleEndian
			cs := func(b []byte) string { return string(bytes.TrimRight(b, "\x00")) }
			for i := 0; i+384 <= len(b); i += 384 {
				r := b[i : i+384]
				e := UtmpEntry{Type: int(int16(le.Uint16(r))), PID: int(int32(le.Uint32(r[4:]))), Line: cs(r[8:40]), ID: cs(r[40:44]),
					User: cs(r[44:76]), Host: cs(r[76:332]), TimeMS: int64(int32(le.Uint32(r[340:]))) * 1000, UID: -1, TTYMode: -1}
				var a [16]byte
				copy(a[:], r[348:364])
				if a != [16]byte{} {
					if [12]byte(a[4:]) == [12]byte{} {
						e.Addr = netip.AddrFrom4([4]byte(a[:4])).String()
					} else {
						e.Addr = netip.AddrFrom16(a).String()
					}
				}
				c.s.Utmp = append(c.s.Utmp, e)
			}
		default:
			c.cases = append(c.cases, [2]string{head, body})
		}
	}
	return c
}

func wOptsOf(args string) WOptions {
	var o WOptions
	for _, f := range strings.Fields(args) {
		if !strings.HasPrefix(f, "-") {
			o.User = f
			continue
		}
		for _, ch := range f[1:] {
			switch ch {
			case 'h':
				o.NoHeader = true
			case 'u':
				o.NoCurrent = true
			case 's':
				o.Short = true
			case 'f':
				o.ToggleFrom = true
			case 'o':
				o.OldStyle = true
			case 'i':
				o.IPAddr = true
			case 'p':
				o.PIDs = true
			}
		}
	}
	return o
}

// TestW33: procps 3.3.15 and 3.3.17's w on real pty sessions in containers.
func TestW33(t *testing.T) {
	saved, savedUsers := time.Local, recordedUsers
	defer func() { time.Local, recordedUsers = saved, savedUsers }()
	time.Local = time.UTC
	recordedUsers = map[int]string{0: "root", 1: "bin", 65534: "nobody"}
	for _, f := range []string{"w-3.3.15.txt", "w-3.3.17-rocky9.txt", "w-3.3.17-ubuntu.txt"} {
		c := readWCapture(t, "testdata/who/"+f)
		if len(c.cases) < 10 || len(c.procs) < 5 || len(c.s.Utmp) != 6 {
			t.Fatalf("%s: %d cases, %d processes, %d utmp records", f, len(c.cases), len(c.procs), len(c.s.Utmp))
		}
		for _, cs := range c.cases {
			o := wOptsOf(cs[0])
			o.NoFromDefault = strings.Contains(f, "rocky9")
			rep := &WReport{Procps3: true, Now: c.now * 1000, Lines: wLines(c.s, c.procs, c.now*1000, true, o)}
			var b bytes.Buffer
			PrintW(&b, rep, o)
			got, want := b.String(), cs[1]
			if !o.NoHeader { // the uptime line is the container host's: compare the rest
				_, got, _ = strings.Cut(got, "\n")
				_, want, _ = strings.Cut(want, "\n")
			}
			// JCPU of an X display line sums the processes without a terminal,
			// the capture script among them: it moves between w and the dump
			mask := func(s string) string {
				var out []string
				for _, l := range strings.Split(s, "\n") {
					if strings.HasPrefix(l, "root     :0 ") && len(l) > 57 {
						l = l[:44] + "  ?.??s" + l[51:]
					}
					out = append(out, l)
				}
				return strings.Join(out, "\n")
			}
			got, want = mask(got), mask(want)
			if got != want {
				t.Errorf("%s: w %s:\n got:\n%s\nwant:\n%s", f, cs[0], got, want)
			}
		}
	}
}

// TestW404: Ubuntu 26.04's procps 4.0.4 (Debian patches) from logind's
// sessions, captured on a desktop with a machinectl login (trimmed to the
// sessions' processes, the user renamed).
func TestW404(t *testing.T) {
	saved, savedUsers := time.Local, recordedUsers
	defer func() { time.Local, recordedUsers = saved, savedUsers }()
	time.Local = time.FixedZone("ACDT", 37800)
	recordedUsers = map[int]string{1000: "testusr"}
	c := readWCapture(t, "testdata/who/w-4.0.4-ubuntu.txt")
	if len(c.cases) < 10 || len(c.s.Logind) != 3 {
		t.Fatalf("%d cases, %d sessions", len(c.cases), len(c.s.Logind))
	}
	for _, cs := range c.cases {
		o := wOptsOf(cs[0])
		rep := &WReport{Now: c.now * 1000, Lines: wLines(c.s, c.procs, c.now*1000, false, o)}
		var b bytes.Buffer
		PrintW(&b, rep, o)
		got, want := b.String(), cs[1]
		if !o.NoHeader {
			_, got, _ = strings.Cut(got, "\n")
			_, want, _ = strings.Cut(want, "\n")
		}
		if got != want {
			t.Errorf("w %s:\n got:\n%s\nwant:\n%s", cs[0], got, want)
		}
	}
	if n := c.s.UserCount(false); n != 2 {
		t.Errorf("users %d, want 2 (uptime's)", n)
	}
}
