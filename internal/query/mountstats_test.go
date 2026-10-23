package query

import (
	"strings"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

func TestPyTimedelta(t *testing.T) {
	for s, want := range map[int64]string{0: "0:00:00", 3725: "1:02:05", 86400 + 61: "1 day, 0:01:01", 3*86400 + 7: "3 days, 0:00:07"} {
		if got := pyTimedelta(s); got != want {
			t.Errorf("%d: %q, want %q", s, got, want)
		}
	}
}

func TestMountstats(t *testing.T) {
	lines := []string{
		"device localhost:/srv/clifr mounted on /mnt/nfs with fstype nfs4 statvers=1.1",
		"opts:	rw,vers=4.2,rsize=1048576",
		"age:	3725",
		"caps:	caps=0x3ffbffff,wtmult=512",
		"nfsv4:	bm0=0xfdffbfff,acl=0x3",
		"sec:	flavor=1,pseudoflavor=1",
		"events:	1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27",
		"bytes:	100 200 0 0 300 400 1 2",
		"RPC iostats version: 1.1  p/v: 100003/4 (nfs)",
		"xprt:	tcp 832 1 1 0 0 40 40 0 40 0 2 0 0",
		"per-op statistics",
		"NULL: 1 1 0 44 24 0 0 0 0",
		"READ: 0 0 0 0 0 0 0 0 0",
		"WRITE: 20 22 1 1000 2000 10 30 50 0",
		"GETATTR: 20 20 0 400 800 0 20 40 2",
	}
	var rows []store.SnapshotRow
	for i, l := range lines {
		rows = append(rows, store.SnapshotRow{TS: 1000, Source: "mountstats", Key: "/mnt/nfs " + string(rune('a'+i)), Pos: i, Full: true, Line: l})
	}
	db := testrec.Open(t, nil, &store.Batch{Sample: store.Sample{TS: 1000}, Snapshots: rows})
	mounts, err := MountstatsAt(db, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	PrintMountstats(&b, mounts, MountstatsOptions{RPC: true})
	want := "Stats for localhost:/srv/clifr mounted on /mnt/nfs:\n\n" +
		"RPC statistics:\n  40 RPC requests sent, 40 RPC replies received (0 XIDs not found)\n  average backlog queue length: 0\n\n" +
		"WRITE:\n\t20 ops (50%) \t2 retrans (10%) \t1 major timeouts\n" +
		"\tavg bytes sent per op: 50\tavg bytes received per op: 100\n" +
		"\tbacklog wait: 0.500000 \tRTT: 1.500000 \ttotal execute time: 2.500000 (milliseconds)\n" +
		"GETATTR:\n\t20 ops (50%) \t2 errors (10%)\n" +
		"\tavg bytes sent per op: 20\tavg bytes received per op: 40\n" +
		"\tbacklog wait: 0.000000 \tRTT: 1.000000 \ttotal execute time: 2.000000 (milliseconds)\n" +
		"NULL:\n\t1 ops (2%) \n" +
		"\tavg bytes sent per op: 44\tavg bytes received per op: 24\n" +
		"\tbacklog wait: 0.000000 \tRTT: 0.000000 \ttotal execute time: 0.000000 (milliseconds)\n\n"
	if b.String() != want {
		t.Errorf("-r: got\n%q\nwant\n%q", b.String(), want)
	}
	b.Reset()
	PrintMountstats(&b, mounts, MountstatsOptions{NFS: true, V233: true})
	if strings.Contains(b.String(), "mount age") || !strings.Contains(b.String(), "  NFS security flavor: 1  pseudoflavor: 0\n") {
		t.Errorf("-n 2.3.3: %q", b.String())
	}
}
