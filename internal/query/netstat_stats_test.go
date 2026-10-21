package query

import "testing"

// net-tools looks counters up by binary search in a table that is not quite
// sorted: "Forwarding" is listed before "ForwDatagrams" but sorts after it,
// so the search misses it and netstat prints "Forwarding: 1".
func TestStatFind(t *testing.T) {
	if _, ok := statFind(ipStats, "Forwarding"); ok {
		t.Error("Forwarding found: net-tools' search misses it")
	}
	for _, name := range []string{"InReceives", "ForwDatagrams", "DefaultTTL", "ReasmTimeout"} {
		if _, ok := statFind(ipStats, name); !ok {
			t.Errorf("%s not found", name)
		}
	}
	if _, ok := statFind(icmp6Stats, "Icmp6OutRouterAdvertisements"); ok {
		t.Error("Icmp6OutRouterAdvertisements found: the table's entry has a trailing space")
	}
}
