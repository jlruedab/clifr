package query

import (
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// TestDFStatfsStuck: a mount whose statfs stopped answering (guard event
// statfs_stuck) is marked in df with the time it stopped, until statfs_ok or
// a newer usage row; the other mounts are not.
func TestDFStatfsStuck(t *testing.T) {
	base := int64(1_790_000_000_000)
	m := func(seq, id int, point, src, fstype string) store.MountEvent {
		return store.MountEvent{TS: base, Action: "present", MountID: id, Point: point, Source: src, FSType: fstype,
			Options: "rw", SuperOptions: "rw", Dev: "0:" + point, Root: "/", Seq: seq}
	}
	fs := func(ts int64, id int, bfree int64) store.FSSample {
		return store.FSSample{TS: ts, MountID: id, FrSize: 4096, Blocks: 1000, BFree: bfree, BAvail: bfree, Files: 100, FFree: 50}
	}
	stuckAt := base + 31_000
	db := testrec.Open(t, nil,
		&store.Batch{Sample: store.Sample{TS: base},
			Mounts:    []store.MountEvent{m(1, 2, "/", "/dev/vda4", "xfs"), m(2, 9, "/mnt/nfs", "127.0.0.1:/srv/nfs", "nfs4")},
			FSSamples: []store.FSSample{fs(base, 2, 500), fs(base, 9, 800)}},
		&store.Batch{Sample: store.Sample{TS: base + 30_000},
			Guard: []store.GuardEvent{{TS: stuckAt, Kind: "statfs_stuck",
				Detail: "/mnt/nfs: statfs not answering after 1s (nfs4 127.0.0.1:/srv/nfs)"}},
			FSSamples: []store.FSSample{fs(base+30_000, 2, 400)}},
		&store.Batch{Sample: store.Sample{TS: base + 60_000}, FSSamples: []store.FSSample{fs(base+60_000, 2, 300)}},
		&store.Batch{Sample: store.Sample{TS: base + 90_000},
			Guard: []store.GuardEvent{{TS: base + 89_000, Kind: "statfs_ok",
				Detail: "/mnt/nfs: statfs answered after 58s (nfs4 127.0.0.1:/srv/nfs)"}},
			FSSamples: []store.FSSample{fs(base+89_000, 9, 700)}})

	check := func(at, wantStuck, wantNFSSample int64) {
		t.Helper()
		rows, err := DF(db, at, DFSelect{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("at +%d s: %d rows, want 2", (at-base)/1000, len(rows))
		}
		for _, r := range rows {
			switch r.Point {
			case "/":
				if r.StatfsStuck != 0 {
					t.Errorf("at +%d s: / marked stuck", (at-base)/1000)
				}
			case "/mnt/nfs":
				if r.StatfsStuck != wantStuck || r.SampleTS != wantNFSSample {
					t.Errorf("at +%d s: /mnt/nfs stuck %d, sample %d; want %d, %d", (at-base)/1000,
						r.StatfsStuck, r.SampleTS, wantStuck, wantNFSSample)
				}
			}
		}
	}
	check(base+10_000, 0, base)
	check(base+60_000, stuckAt, base)
	check(base+90_000, 0, base+89_000)
}
