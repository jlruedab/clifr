package query

import (
	"slices"
	"testing"
)

// TestAtopFormats: atop's value formats, with values from its real output
// (2.12.1, bench/results/atop-captures-20261121).
func TestAtopFormats(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{atopVal(134423456, 8, false, 0), "134423e3"}, // CPL csw
		{atopVal(136970123, 7, false, 0), "13697e4"},  // CPL intr
		{atopVal(22, 6, false, 0), "    22"},
		{atopVal(999999999, 8, false, 0), "999999e3"}, // no rounding up without room
		{atopVal(1234567890, 8, false, 0), "123457e4"},
		{atopVal(4000, 6, true, 10), " 400/s"},
		{atopElapsed(21332), "5h55m32s"},
		{atopElapsed(59), "59s"},
		{atopElapsed(86400 + 61), "1d0h1m1s"},
		{atopCPU(1035000), "17m15s"},
		{atopCPU(3620), " 3.62s"},
		{atopCPU(36620), "36.62s"},
		{atopCPU(386000), " 6m26s"},
		{atopCPU(6000 * 1000), " 1h40m"},
		{atopCPU(6000 * 60 * 1000), " 4d04h"},
		{atopMem(61<<30, atopB, false, 0), " 61.0G"},
		{atopMem(0, atopMB, false, 0), "  0.0M"},
		{atopMem(1503238553, atopB, false, 0), "  1.4G"},
		{atopMem(112513843, atopB, false, 0), "107.3M"},
		{atopMem(0, atopB, false, 0), "    0B"},
		{atopMem(1536, atopB, true, 1), "1.5K/s"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

// TestAtopSysLine: five boxes fill 80 columns; fewer are spread with blank
// boxes; the lowest priorities go first, the first of equal ones.
func TestAtopSysLine(t *testing.T) {
	box := func(s string, p int) atopItem { return atopItem{text: s, prio: p} }
	cpl := []atopItem{box("numcpu    22", 7), atopBlank, box("avg1    1.92", 4), box("avg5    1.02", 3),
		box("avg15   0.80", 2), atopBlank, box("csw 134423e3", 6), box("intr 13697e4", 5)}
	want := "CPL | numcpu    22 | avg1    1.92 | avg5    1.02 | csw 134423e3 | intr 13697e4 |"
	if got := atopSysLine("CPL", cpl, 80); got != want {
		t.Errorf("CPL:\n got %q\nwant %q", got, want)
	}
	three := []atopItem{box("aaaaaaaaaaaa", 3), box("bbbbbbbbbbbb", 2), box("cccccccccccc", 1)}
	want = "XYZ | aaaaaaaaaaaa |              | bbbbbbbbbbbb | cccccccccccc |              |"
	if got := atopSysLine("XYZ", three, 80); got != want {
		t.Errorf("three boxes:\n got %q\nwant %q", got, want)
	}
	names, prios := atopDefs("CPLNUMCPU:7BLANKBOX:0 CPLAVG1:4  NUMAMIGRATE:5PGMIGRATE:6PAGPGIN:6 ")
	if !slices.Equal(names, []string{"CPLNUMCPU", "BLANKBOX", "CPLAVG1", "NUMAMIGRATE", "PGMIGRATE", "PAGPGIN"}) ||
		!slices.Equal(prios, []int{7, 0, 4, 5, 6, 6}) {
		t.Errorf("defs: %v %v", names, prios)
	}
}
