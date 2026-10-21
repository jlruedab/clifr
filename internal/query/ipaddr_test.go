package query

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// A snapshot of two addresses, then a new one, a change of the first (a
// lifetime refresh) and the removal of the second.
func TestAddrsAt(t *testing.T) {
	base := int64(1_790_000_000_000)
	ip := func(s string) []byte { return netip.MustParseAddr(s).AsSlice() }
	a := func(ts int64, action string, seq int, local string, prefix int, valid int64) store.AddrRow {
		fam := 2
		if strings.Contains(local, ":") {
			fam = 10
		}
		return store.AddrRow{TS: ts, Action: action, Seq: seq, Family: fam, PrefixLen: prefix, Index: 2, Flags: 0x80,
			Local: ip(local), Address: ip(local), Metric: -1, Proto: -1, Valid: valid, Preferred: valid}
	}
	db := testrec.Open(t, nil,
		&store.Batch{Sample: store.Sample{TS: base}, Addrs: []store.AddrRow{
			a(base, "present", 0, "192.168.1.12", 24, 3600), a(base, "present", 1, "10.0.0.5", 8, lifetimeForever)}},
		&store.Batch{Sample: store.Sample{TS: base + 30_000}, Addrs: []store.AddrRow{
			a(base+10_000, "add", 1, "172.16.0.1", 16, lifetimeForever),
			a(base+20_000, "add", 2, "192.168.1.12", 24, 7200),
			a(base+25_000, "del", 3, "10.0.0.5", 8, lifetimeForever)}})
	got := func(at int64) string {
		list, err := AddrsAt(db, at)
		if err != nil {
			t.Fatal(err)
		}
		var s []string
		for _, x := range list {
			v := "forever"
			if x.Valid != lifetimeForever {
				v = strconv.FormatInt(x.Valid, 10)
			}
			s = append(s, ipString(x.Family, x.Local)+"/"+v)
		}
		return strings.Join(s, " ")
	}
	for at, want := range map[int64]string{
		base + 5_000:  "192.168.1.12/3595 10.0.0.5/forever",
		base + 15_000: "192.168.1.12/3585 10.0.0.5/forever 172.16.0.1/forever",
		base + 22_000: "192.168.1.12/7198 10.0.0.5/forever 172.16.0.1/forever",
		base + 30_000: "192.168.1.12/7190 172.16.0.1/forever",
	} {
		if g := got(at); g != want {
			t.Errorf("+%ds: %s, want %s", (at-base)/1000, g, want)
		}
	}
}
