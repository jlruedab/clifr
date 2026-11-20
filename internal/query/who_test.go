package query

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// whoGolden reads a reference file: "NOW sec", a version line, then
// "=== LOCALE|OPTIONS" sections.
func whoGolden(t *testing.T, path string) (now int64, cases [][3]string) {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, sec := range strings.Split(string(data), "=== ")[1:] {
		head, body, _ := strings.Cut(sec, "\n")
		loc, o, _ := strings.Cut(head, "|")
		cases = append(cases, [3]string{loc, o, body})
	}
	f := strings.Fields(string(data))
	now, _ = strconv.ParseInt(f[1], 10, 64)
	return now, cases
}

func whoOpts(loc, flags string, uutils bool) WhoOptions {
	var o WhoOptions
	for _, f := range strings.Fields(flags) {
		for _, c := range f[1:] {
			switch c {
			case 'a':
				o.All = true
			case 'b':
				o.Boot = true
			case 'd':
				o.Dead = true
			case 'H':
				o.Heading = true
			case 'l':
				o.Login = true
			case 'p':
				o.Process = true
			case 'q':
				o.Count = true
			case 'r':
				o.RunLevel = true
			case 's':
				o.Short = true
			case 't':
				o.Time = true
			case 'T':
				o.Mesg = true
			case 'u':
				o.Users = true
			}
		}
	}
	o.ISO = loc != "C"
	o.UID = uutils
	return o
}

// TestWhoGNU: GNU who 8.30/8.32 on a utmp with every record type.
func TestWhoGNU(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.UTC
	now, cases := whoGolden(t, "testdata/who/gnu-8.32.txt")
	lines, err := os.ReadFile("testdata/who/utmp-lines.txt")
	if err != nil {
		t.Fatal(err)
	}
	s := &Sessions{Source: "utmp"}
	tty := map[string][2]int64{"tty7": {now - 30, 0o620}, "tty8": {now - 7500, 0o600}, "ttyS9": {now - 3*86400, 0o620}}
	for _, l := range strings.Split(strings.TrimRight(string(lines), "\n"), "\n") {
		e, ok := parseUtmpLine(l)
		if !ok {
			t.Fatalf("bad line %q", l)
		}
		if v, ok := tty[e.Line]; ok {
			e.TTYAtimeMS, e.TTYMode = v[0]*1000+999, int(v[1])
		}
		s.Entries = append(s.Entries, e)
	}
	for _, c := range cases {
		var b bytes.Buffer
		PrintWho(&b, s, whoOpts(c[0], c[1], false), now*1000+500, func(pid int) bool { return pid == 1 })
		if b.String() != c[2] {
			t.Errorf("LC_ALL=%s who %s:\n got:\n%s\nwant:\n%s", c[0], c[1], b.String(), c[2])
		}
	}
}

// TestWhoUutils: Ubuntu 26.04's who from logind's sessions.
func TestWhoUutils(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.FixedZone("ACDT", 37800)
	now, cases := whoGolden(t, "testdata/who/uutils-0.10.0.txt")
	data, err := os.ReadFile("testdata/who/uutils-logind.txt")
	if err != nil {
		t.Fatal(err)
	}
	s := &Sessions{Source: "logind"}
	var boot int64
	tty := map[string][2]int64{}
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		switch {
		case strings.HasPrefix(l, "BOOT "):
			boot, _ = strconv.ParseInt(l[5:], 10, 64)
		case strings.HasPrefix(l, "TTY "):
			f := strings.Split(l[4:], "\t")
			at, _ := strconv.ParseInt(f[1], 10, 64)
			mode, _ := strconv.ParseInt(f[2], 8, 64)
			tty[f[0]] = [2]int64{at, mode}
		case strings.HasPrefix(l, "ID="):
			s.Logind = append(s.Logind, parseLogindLine(l))
		}
	}
	s.Entries = uutilsRecords(s.Logind, boot)
	for i := range s.Entries {
		if v, ok := tty[s.Entries[i].Line]; ok {
			s.Entries[i].TTYAtimeMS, s.Entries[i].TTYMode = v[0], int(v[1])
		}
	}
	for _, c := range cases {
		var b bytes.Buffer
		PrintWho(&b, s, whoOpts(c[0], c[1], true), now*1000, nil)
		if b.String() != c[2] {
			t.Errorf("LC_ALL=%s who %s:\n got:\n%s\nwant:\n%s", c[0], c[1], b.String(), c[2])
		}
	}
}

func TestWhoISO(t *testing.T) {
	for _, c := range []struct {
		env          map[string]string
		gnu, uutils_ bool
	}{
		{map[string]string{}, false, true},
		{map[string]string{"LANG": "en_US.UTF-8"}, true, true},
		{map[string]string{"LANG": "C"}, false, false},
		{map[string]string{"LC_ALL": "POSIX", "LANG": "en_US.UTF-8"}, false, true},
		{map[string]string{"LC_TIME": "C.UTF-8"}, true, true},
	} {
		for _, k := range []string{"LC_ALL", "LC_TIME", "LANG"} {
			if v, ok := c.env[k]; ok {
				t.Setenv(k, v)
			} else {
				t.Setenv(k, "")
				os.Unsetenv(k)
			}
		}
		if g, u := WhoISO(false), WhoISO(true); g != c.gnu || u != c.uutils_ {
			t.Errorf("%v: gnu %v uutils %v, want %v %v", c.env, g, u, c.gnu, c.uutils_)
		}
	}
}
