package query

import (
	"strings"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

func TestFileAt(t *testing.T) {
	full := func(ts int64, lines ...string) []store.SnapshotRow {
		var out []store.SnapshotRow
		for i, l := range lines {
			out = append(out, store.SnapshotRow{TS: ts, Source: "modules", Key: strings.Fields(l)[0], Pos: i, Full: true, Line: l})
		}
		if len(lines) == 0 {
			out = append(out, store.SnapshotRow{TS: ts, Source: "modules", Pos: -1, Full: true})
		}
		return out
	}
	b1 := &store.Batch{Sample: store.Sample{TS: 1000}, Snapshots: full(1000, "b 1 0 - Live 0x0", "a 2 1 c, Live 0x0")}
	b2 := &store.Batch{Sample: store.Sample{TS: 2000}, Snapshots: []store.SnapshotRow{{TS: 2000, Source: "modules", Key: "a", Pos: 1, Line: "a 2 0 - Live 0x0"}}}
	b3 := &store.Batch{Sample: store.Sample{TS: 3000}, Snapshots: full(3000, "c 3 0 - Live 0x0", "b 1 0 - Live 0x0", "a 2 0 - Live 0x0")}
	b4 := &store.Batch{Sample: store.Sample{TS: 4000}, Snapshots: full(4000)}
	db := testrec.Open(t, nil, b1, b2, b3, b4)
	for _, c := range []struct {
		t    int64
		want string
		ok   bool
	}{
		{999, "", false},
		{1500, "b 1 0 - Live 0x0|a 2 1 c, Live 0x0", true},
		{2500, "b 1 0 - Live 0x0|a 2 0 - Live 0x0", true},
		{3000, "c 3 0 - Live 0x0|b 1 0 - Live 0x0|a 2 0 - Live 0x0", true},
		{4000, "", true},
	} {
		lines, _, ok, err := FileAt(db, "modules", c.t)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(lines, "|"); got != c.want || ok != c.ok {
			t.Errorf("at %d: %q %v, want %q %v", c.t, got, ok, c.want, c.ok)
		}
	}
}

func TestUtilHuman(t *testing.T) {
	for _, c := range []struct {
		b    int64
		want string
	}{
		{0, "0B"}, {512, "512B"}, {1024, "1K"}, {1536, "1.5K"}, {8589930496, "8G"}, {1159168, "1.1M"},
		{2147483648, "2G"}, {1048575, "1024K"}, {10 * 1024 * 1024 * 1024 * 1024, "10T"},
	} {
		if got := utilHuman(c.b); got != c.want {
			t.Errorf("%d: %q, want %q", c.b, got, c.want)
		}
	}
}

func TestPrintSwapon(t *testing.T) {
	swaps := []Swap{{Name: "/swap.img", Type: "file", SizeKB: 8388604, UsedKB: 1132, Priority: -1},
		{Name: "/dev/dm-1", Type: "partition", SizeKB: 2097148, Priority: -2}}
	var b strings.Builder
	PrintSwapon(&b, swaps, SwapColumns, false, false, false)
	want := "NAME      TYPE      SIZE USED PRIO\n" +
		"/swap.img file        8G 1.1M   -1\n" +
		"/dev/dm-1 partition   2G   0B   -2\n"
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
	b.Reset()
	PrintSwapon(&b, swaps[:1], SwapColumns, true, false, false)
	want = "NAME      TYPE       SIZE    USED PRIO\n/swap.img file 8589930496 1159168   -1\n"
	if b.String() != want {
		t.Errorf("--bytes: got\n%s\nwant\n%s", b.String(), want)
	}
	b.Reset()
	PrintSwapSummary(&b, []Swap{{Name: "/swapfile", Type: "file", SizeKB: 65532, Priority: -2}}, nil, true)
	want = "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n/swapfile                              \tfile    \t65532\t0\t-2\n"
	if b.String() != want {
		t.Errorf("summary 2.32: got %q, want %q", b.String(), want)
	}
	b.Reset()
	PrintSwapon(&b, nil, SwapColumns, false, false, false)
	if b.String() != "" {
		t.Errorf("no swap: %q", b.String())
	}
}

func TestPrintLsmod(t *testing.T) {
	db := testrec.Open(t, nil, &store.Batch{Sample: store.Sample{TS: 1000}, Snapshots: []store.SnapshotRow{
		{TS: 1000, Source: "modules", Key: "udp_diag", Pos: 0, Full: true, Line: "udp_diag 12288 0 - Live 0x0000000000000000"},
		{TS: 1000, Source: "modules", Key: "inet_diag", Pos: 1, Full: true, Line: "inet_diag 24576 2 udp_diag,tcp_diag, Live 0x0000000000000000"},
		{TS: 1000, Source: "modules", Key: "vboxdrv", Pos: 2, Full: true, Line: "vboxdrv 741376 2 vboxnetadp,vboxnetflt, Live 0x0000000000000000 (OE)"},
		{TS: 1000, Source: "modules", Key: "ip_tables", Pos: 3, Full: true, Line: "ip_tables 32768 0 [permanent], Live 0x0000000000000000"},
	}})
	mods, err := ModulesAt(db, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	PrintLsmod(&b, mods)
	want := "Module                  Size  Used by\n" +
		"udp_diag               12288  0\n" +
		"inet_diag              24576  2 tcp_diag,udp_diag\n" +
		"vboxdrv               741376  2 vboxnetadp,vboxnetflt\n" +
		"ip_tables              32768  0\n"
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
}
