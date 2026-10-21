package query

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestSockFilter(t *testing.T) {
	row := func(l, r string, lp, rp int) *SSRow {
		return &SSRow{laddr: netip.MustParseAddr(l), raddr: netip.MustParseAddr(r), LPort: lp, RPort: rp}
	}
	cases := []struct {
		args []string
		row  *SSRow
		want bool
	}{
		{[]string{"dst", "10.0.0.5"}, row("10.0.0.1", "10.0.0.5", 1, 2), true},
		{[]string{"dst", "10.0.0.0/24", "and", "dport", "=", ":443"}, row("1.1.1.1", "10.0.0.9", 1, 443), true},
		{[]string{"dst", "10.0.0.0/24", "and", "dport", "=", ":443"}, row("1.1.1.1", "10.0.0.9", 1, 80), false},
		{[]string{"sport", "=", ":22"}, row("1.1.1.1", "2.2.2.2", 22, 5), true},
		{[]string{"dst", "127.0.0.1:5432"}, row("::ffff:127.0.0.1", "::ffff:127.0.0.1", 1, 5432), true},
		{[]string{"dst", "[::1]:80"}, row("::1", "::1", 1, 80), true},
		{[]string{"dport = :443"}, row("1.1.1.1", "10.0.0.9", 1, 443), true}, // quoted as one argument
	}
	for _, c := range cases {
		f, err := ParseSockFilter(c.args)
		if err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if got := f.Match(c.row); got != c.want {
			t.Errorf("%v: got %v", c.args, got)
		}
	}
	if _, err := ParseSockFilter([]string{"state", "established"}); err == nil {
		t.Error("unsupported filter should fail")
	}
}

func TestPeakOverlap(t *testing.T) {
	if p := peakOverlap([]interval{{0, 10}, {5, 15}, {10, 20}, {16, 30}}); p != 3 {
		t.Errorf("peak = %d, want 3 (all three touch t=10)", p)
	}
	if p := peakOverlap(nil); p != 0 {
		t.Errorf("empty peak = %d", p)
	}
}

func TestPSFormatting(t *testing.T) {
	if s := tenths(1234); s != "123" {
		t.Errorf("tenths(1234) = %s", s)
	}
	if s := tenths(5); s != "0.5" {
		t.Errorf("tenths(5) = %s", s)
	}
	if c := commandOf("bash -c 'a\nb'", "bash", "S"); c != "bash -c 'a?b'" {
		t.Errorf("control chars: %q", c)
	}
	if c := commandOf("", "kworker/0:1", "I"); c != "[kworker/0:1]" {
		t.Errorf("kernel thread: %q", c)
	}
}

func TestFmtAddrDual(t *testing.T) {
	any6, any4 := netip.IPv6Unspecified(), netip.IPv4Unspecified()
	for _, c := range []struct {
		a      netip.Addr
		ifname string
		v6only bool
		want   string
	}{
		{any6, "", false, "*"}, // also accepts IPv4: ss prints "*"
		{any6, "", true, "[::]"},
		{any6, "eth0", false, "*%eth0"},
		{any4, "", false, "0.0.0.0"},
		{netip.MustParseAddr("::1"), "", false, "[::1]"},
	} {
		if got := fmtAddrDual(c.a, c.ifname, c.v6only); got != c.want {
			t.Errorf("fmtAddrDual(%v, %q, %v) = %q, want %q", c.a, c.ifname, c.v6only, got, c.want)
		}
	}
}

func TestPSStartByDay(t *testing.T) {
	at := func(y int, m time.Month, d, h, min int) int64 {
		return time.Date(y, m, d, h, min, 0, 0, time.Local).UnixMilli()
	}
	now := at(2026, 10, 22, 8, 20)
	for start, want := range map[int64]string{
		at(2026, 10, 22, 0, 5):   "00:05",
		at(2026, 10, 21, 8, 48):  "Oct21", // 23.5 hours ago, but yesterday
		at(2026, 1, 3, 9, 0):     "Jan03",
		at(2025, 12, 31, 23, 59): " 2025",
	} {
		if got := psStart(start, now); got != want {
			t.Errorf("psStart(%s) = %q, want %q", time.UnixMilli(start), got, want)
		}
	}
}

func TestPSLongAndLabel(t *testing.T) {
	rows := []PSRow{
		{PID: 1, UIDNum: 0, Nice: 0, VSZ: 28816, RSS: 19564, Stat: "Ss", TTY: "?", Time: "0:10", args: "/sbin/init",
			CPU: "0.0", Mem: "0.0", Known: true, Flags: 4, Priority: 20, Wchan: psWchan("ep_poll", false), Label: "unconfined"},
		{PID: 18, PPID: 2, Stat: "S", TTY: "?", Time: "0:09", args: "[migration/0]", CPU: "0.0", Mem: "0.0",
			Known: true, Flags: 1, Priority: -100, Policy: 1, RTPriority: 99, Wchan: psWchan("smpboot_thread_fn", false),
			Label: "/usr/sbin/cupsd (enforce)"},
		{PID: 9266, Nice: 19, Stat: "SN", TTY: "?", Time: "0:00", args: "idle", CPU: "0.0", Mem: "0.0",
			Known: true, Policy: 5, Wchan: psWchan("__skb_wait_for_more_packets", false)},
	}
	var b strings.Builder
	PrintPSFormat(&b, rows, PSLong)
	want := `F   UID     PID    PPID PRI  NI    VSZ   RSS WCHAN  STAT TTY        TIME COMMAND
4     0       1       0  20   0  28816 19564 ep_pol Ss   ?          0:10 /sbin/init
1     0      18       2 -100  -      0     0 smpboo S    ?          0:09 [migration/0]
0     0    9266       0   0   -      0     0 skb_wa SN   ?          0:00 idle
`
	if b.String() != want {
		t.Errorf("ps alx:\n%s\nwant:\n%s", b.String(), want)
	}
	cls := ParsePSFormatMust(t, "pid,cls,rtprio,ni")
	b.Reset()
	PrintPSFormat(&b, rows, cls)
	if want := "    PID CLS RTPRIO  NI\n      1  TS      -   0\n     18  FF     99   -\n   9266 IDL      0   -\n"; b.String() != want {
		t.Errorf("cls/rtprio/ni:\n%s\nwant:\n%s", b.String(), want)
	}
	b.Reset()
	PrintPSFormat(&b, rows[:2], PSAuxLabel)
	if got := strings.Split(b.String(), "\n")[2]; !strings.HasPrefix(got, "/usr/sbin/cupsd (enforce)       root          18") {
		t.Errorf("ps auxZ line %q", got)
	}
	if psWchan("do_wait", true) != "wait" || psWchan("do_wait", false) != "do_wait" || psWchan("0", false) != "-" {
		t.Errorf("psWchan")
	}
}

func ParsePSFormatMust(t *testing.T, s string) PSFormat {
	f, err := ParsePSFormat(s)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
