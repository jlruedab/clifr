package rtnl

import "testing"

// The machine's own interfaces: lo is always there, with its address and
// statistics.
func TestDump(t *testing.T) {
	links, err := Dump()
	if err != nil {
		t.Skip(err) // no rtnetlink here
	}
	var lo *Link
	for i := range links {
		if links[i].Name == "lo" {
			lo = &links[i]
		}
	}
	if lo == nil {
		t.Fatalf("no lo among %d links", len(links))
	}
	if lo.Index != 1 || lo.Type != 772 || lo.MTU <= 0 || len(lo.Address) != 6 || len(lo.Stats) != statsWithOtherhost || lo.Qdisc == "" {
		t.Errorf("lo: %+v", *lo)
	}
}
