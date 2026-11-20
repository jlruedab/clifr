package verify

import "testing"

func TestParseSystemOutput(t *testing.T) {
	up := parseUptime(" 18:11:47 up 2 days,  9:21,  1 user,  load average: 0.58, 0.56, 1.49\n")
	if r := up[""]; r["up_min"] != "3441" || r["load1"] != "0.58" || r["load15"] != "1.49" || r["users"] != "1" {
		t.Errorf("uptime = %v", up)
	}
	if r := parseUptime(" 18:11:47 up 5 min,  load average: 0.00, 0.01, 0.05\n")[""]; r["up_min"] != "5" || r["load5"] != "0.01" || r["users"] != "" {
		t.Errorf("uptime without users = %v", r)
	}
	vm := parseColumns("procs -----------memory---------- ---swap-- -----io---- -system-- -------cpu-------\n"+
		" r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st gu\n"+
		" 0  0      0 34907428 721740 14261188    0    0   284   527 39457   89  8  4 88  0  0  0\n", " r  b", "", 0)
	if r := vm[""]; r["free"] != "34907428" || r["in"] != "39457" || r["gu"] != "0" {
		t.Errorf("vmstat = %v", vm)
	}
	mp := parseColumns("Linux 7.0.0-38-generic (host) \t10/12/26 \t_x86_64_\t(22 CPU)\n\n"+
		"18:11:47     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle\n"+
		"18:11:47     all    7.91    0.11    3.41    0.13    0.00    0.09    0.00    0.00    0.00   88.35\n"+
		"18:11:47       0   13.56    0.07    5.10    0.08    0.00    0.08    0.00    0.00    0.00   81.11\n", "%usr", "CPU", 1)
	if len(mp) != 2 || mp["all"]["%usr"] != "7.91" || mp["0"]["%idle"] != "81.11" {
		t.Errorf("mpstat = %v", mp)
	}
	io := parseColumns("Linux 7.0.0-38-generic (host)\n\nDevice            r/s     rkB/s  %util\ndm-0             6.77    174.67   1.29\nloop0            0.03      0.08   0.00\n\n", "Device", "Device", 0)
	if len(io) != 2 || io["dm-0"]["rkB/s"] != "174.67" || io["loop0"]["%util"] != "0.00" {
		t.Errorf("iostat = %v", io)
	}
	for _, c := range []struct {
		real, clifr string
		want        bool
	}{{"7.91", "7.91", true}, {"7.91", "7.93", true}, {"7.91", "8.20", false}, {"19238.46", "19100.00", true}, {"0.00", "0.05", false}, {"x", "1", false}} {
		if near(c.real, c.clifr, 0.01, 0.02) != c.want {
			t.Errorf("near(%s, %s) != %v", c.real, c.clifr, c.want)
		}
	}
}
