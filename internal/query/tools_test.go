package query

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

func TestHumanSize(t *testing.T) {
	// Values from free -h (procps-ng 4.0.4) on the test machine.
	for kb, want := range map[int64]string{63964028: "61Gi", 9566804: "9.1Gi", 44232428: "42Gi", 1302548: "1.2Gi",
		11100100: "10Gi", 54397224: "51Gi", 8388604: "8.0Gi", 0: "0B", 512: "512Ki", 1500: "1.5Mi"} {
		if got := humanSize(kb * 1024); got != want {
			t.Errorf("%d kB: %q, want %q", kb, got, want)
		}
	}
}

func TestPSTimes(t *testing.T) {
	for secs, want := range map[int64]string{2: "00:00:02", 3725: "01:02:05", 90061: "1-01:01:01"} {
		if got := psCPUTime(secs); got != want {
			t.Errorf("TIME %d: %q, want %q", secs, got, want)
		}
	}
	for secs, want := range map[int64]string{5: "00:05", 16189: "04:29:49", 90061: "1-01:01:01"} {
		if got := psElapsed(secs); got != want {
			t.Errorf("ELAPSED %d: %q, want %q", secs, got, want)
		}
	}
}

func TestPSFormat(t *testing.T) {
	if _, err := ParsePSFormat("pid,wchan"); err == nil {
		t.Error("wchan accepted")
	}
	f, err := ParsePSFormat("pid,user,rss,vsz,stat,args")
	if err != nil {
		t.Fatal(err)
	}
	rows := []PSRow{{PID: 3974, RSS: 94156, VSZ: 2906796, Stat: "Ssl", uid: 0, args: "dockerd", ticks: 1},
		{PID: 765, RSS: 1, VSZ: 2, Stat: "S", uid: 0, args: "x ", ticks: 1}}
	var b strings.Builder
	PrintPSFormat(&b, rows, f)
	// A VSZ wider than its column pushes STAT right; the next padding takes it
	// back (as procps prints it), and a trailing space of the command stays.
	want := "    PID USER       RSS    VSZ STAT COMMAND\n" +
		"   3974 root     94156 2906796 Ssl dockerd\n" +
		"    765 root         1      2 S    x \n"
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
	long := []PSRow{{PID: 1, uid: 0, args: strings.Repeat("a", 40), comm: "c"}}
	f, _ = ParsePSFormat("args,comm")
	b.Reset()
	PrintPSFormat(&b, long, f)
	if lines := strings.Split(b.String(), "\n"); lines[1] != strings.Repeat("a", 27)+" c" {
		t.Errorf("args not cut to 27 when not last: %q", lines[1])
	}
}

func TestProgramName(t *testing.T) {
	for _, c := range []struct{ cmdline, comm, want string }{
		{"/usr/lib/postgresql/18/bin/postgres -D /var/lib/x", "postgres", "postgres"},
		{"sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", "sshd", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"},
		{"python3 x.py", "python3", "python3"},
		{"", "kthreadd", "kthreadd"},
	} {
		if got := programName(c.cmdline, c.comm); got != c.want {
			t.Errorf("%q: %q, want %q", c.cmdline, got, c.want)
		}
	}
}

func TestNetstatAddr(t *testing.T) {
	a := netip.MustParseAddr
	for _, c := range []struct {
		addr  netip.Addr
		inet6 bool
		port  int
		wide  bool
		want  string
	}{
		{a("127.0.0.1"), false, 5432, false, "127.0.0.1:5432"},
		{a("0.0.0.0"), false, 0, false, "0.0.0.0:*"},
		{a("::"), true, 22, false, ":::22"},
		{a("::ffff:192.168.1.12"), true, 1716, false, "192.168.1.12:1716"},
		{a("fe80::1234:5678:9abc:def0"), true, 45174, false, "fe80::1234:5678:9:45174"},
		{a("fe80::1234:5678:9abc:def0"), true, 45174, true, "fe80::1234:5678:9abc:def0:45174"},
		{netip.Addr{}, true, 0, false, ":::*"},
	} {
		if got := netstatAddr(c.addr, c.inet6, c.port, c.wide); got != c.want {
			t.Errorf("%v %d: %q, want %q", c.addr, c.port, got, c.want)
		}
	}
}

func TestSocketSelection(t *testing.T) {
	v4, v6 := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("::1")
	rows := []SSRow{
		{Proto: "tcp", State: "LISTEN", laddr: v4}, {Proto: "tcp", State: "ESTAB", laddr: v4},
		{Proto: "tcp", State: "TIME-WAIT", laddr: v4}, {Proto: "tcp", State: "ESTAB", laddr: v6},
		{Proto: "udp", State: "UNCONN", laddr: v4}, {Proto: "udp", State: "ESTAB", laddr: v4},
	}
	count := func(keep func(*SSRow) bool) int {
		n := 0
		for i := range rows {
			if keep(&rows[i]) {
				n++
			}
		}
		return n
	}
	for _, c := range []struct {
		name string
		keep func(*SSRow) bool
		want int
	}{
		{"ss", SSView{}.Keep, 3}, // ESTAB v4, ESTAB v6, udp ESTAB: not LISTEN, UNCONN, TIME-WAIT
		{"ss -a", SSView{All: true}.Keep, 6},
		{"ss -l", SSView{Listening: true}.Keep, 2},
		{"ss -6", SSView{V6: true}.Keep, 1},
		{"netstat", NetstatView{}.Keep, 4}, // TIME-WAIT included
		{"netstat -l", NetstatView{Listening: true}.Keep, 2},
		{"netstat -a -4", NetstatView{All: true, V4: true}.Keep, 5},
	} {
		if got := count(c.keep); got != c.want {
			t.Errorf("%s: %d rows, want %d", c.name, got, c.want)
		}
	}
}

func TestLsofSelect(t *testing.T) {
	rows := []LsofRow{{PID: 1, User: "root", Command: "systemd", Type: "REG"},
		{PID: 2, User: "postgres", Command: "postgres", Type: "IPv4"},
		{PID: 3, User: "postgres", Command: "postgres", Type: "REG"}}
	for _, c := range []struct {
		sel  LsofSelect
		want string
	}{
		{LsofSelect{}, "1 2 3"},
		{LsofSelect{PIDs: []int{1}, Inet: true}, "1 2"}, // ORed, like lsof
		{LsofSelect{Users: []string{"postgres"}, Inet: true, And: true}, "2"},
		{LsofSelect{Commands: []string{"sys"}}, "1"},
	} {
		var got []string
		for _, r := range c.sel.Filter(append([]LsofRow(nil), rows...)) {
			got = append(got, strconv.Itoa(r.PID))
		}
		if strings.Join(got, " ") != c.want {
			t.Errorf("%+v: %v, want %s", c.sel, got, c.want)
		}
	}
}
