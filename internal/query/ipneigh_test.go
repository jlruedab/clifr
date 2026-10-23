package query

import (
	"strings"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

func TestPrintIPNeigh(t *testing.T) {
	links := []store.LinkRow{{Index: 2, Name: "eth0", Type: 1}}
	const at = 100_000
	ns := []store.NeighRow{
		{Family: 2, Index: 2, State: 0x04, Dst: []byte{192, 168, 1, 1}, LLAddr: []byte{0x30, 0x74, 0x96, 0x5b, 0x55, 0x99}, HasLLAddr: true,
			Probes: 1, UsedMS: at - 41_500, ConfirmedMS: at - 41_000, UpdatedMS: at - 16_999},
		{Family: 2, Index: 2, State: 0x20, Dst: []byte{192, 168, 1, 6}, Probes: 6, RefCnt: 1, UsedMS: at - 5000, ConfirmedMS: at - 6000, UpdatedMS: at - 7000},
		{Family: 2, Index: 2, State: 0x40, Dst: []byte{224, 0, 0, 251}, LLAddr: []byte{1, 0, 0x5e, 0, 0, 0xfb}, HasLLAddr: true}, // NOARP: not shown
		{Family: 10, Index: 2, State: 0x04, Flags: 0x80, Dst: []byte{0xfe, 0x80, 15: 1}, LLAddr: []byte{0x30, 0x74, 0x96, 0x5b, 0x55, 0x99},
			HasLLAddr: true, Probes: 1, UsedMS: at - 36_000, ConfirmedMS: at - 36_000, UpdatedMS: at - 14_000},
	}
	for _, c := range []struct {
		o    IPNeighOptions
		want string
	}{
		{IPNeighOptions{}, "" +
			"192.168.1.1 dev eth0 lladdr 30:74:96:5b:55:99 STALE \n" +
			"192.168.1.6 dev eth0 FAILED \n" +
			"fe80::1 dev eth0 lladdr 30:74:96:5b:55:99 router STALE \n"},
		{IPNeighOptions{Stats: true}, "" +
			"192.168.1.1 dev eth0 lladdr 30:74:96:5b:55:99  used 41/41/16probes 1 STALE \n" +
			"192.168.1.6 dev eth0  ref 1 used 5/6/7probes 6 FAILED \n" +
			"fe80::1 dev eth0 lladdr 30:74:96:5b:55:99 router  used 36/36/14probes 1 STALE \n"},
		{IPNeighOptions{Old: true}, "" +
			"192.168.1.1 dev eth0 lladdr 30:74:96:5b:55:99 STALE\n" +
			"192.168.1.6 dev eth0  FAILED\n" +
			"fe80::1 dev eth0 lladdr 30:74:96:5b:55:99 router STALE\n"},
		{IPNeighOptions{Old: true, Stats: true, Family: 2}, "" +
			"192.168.1.1 dev eth0 lladdr 30:74:96:5b:55:99 used 41/41/16 probes 1 STALE\n" +
			"192.168.1.6 dev eth0  ref 1 used 5/6/7 probes 6 FAILED\n"},
		{IPNeighOptions{Dev: "eth0", Family: 10}, "fe80::1 lladdr 30:74:96:5b:55:99 router STALE \n"},
	} {
		var b strings.Builder
		PrintIPNeigh(&b, ns, links, c.o, at)
		if b.String() != c.want {
			t.Errorf("%+v: got\n%q\nwant\n%q", c.o, b.String(), c.want)
		}
	}
}

func TestNetnsAt(t *testing.T) {
	db := testrec.Open(t, nil, &store.Batch{Sample: store.Sample{TS: 1000}, Snapshots: []store.SnapshotRow{
		{TS: 1000, Source: "netns", Key: "clifr-b", Pos: 0, Full: true, Line: "clifr-b 7"},
		{TS: 1000, Source: "netns", Key: "clifr a", Pos: 1, Full: true, Line: "clifr a -1"},
	}})
	ns, err := NetnsAt(db, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	PrintIPNetns(&b, ns)
	if want := "clifr-b (id: 7)\nclifr a\n"; b.String() != want {
		t.Errorf("got %q, want %q", b.String(), want)
	}
}
