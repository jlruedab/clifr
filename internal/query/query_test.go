package query

import (
	"net/netip"
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
	at := func(y int, m time.Month, d, h, min int) int64 { return time.Date(y, m, d, h, min, 0, 0, time.Local).UnixMilli() }
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
