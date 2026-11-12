package query

import (
	"strings"
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

// TestDFHourlySnapshot: the recorder writes the whole mount table again
// hourly; an unchanging file system's usage row of the same hour may come a
// few seconds before that snapshot. df still shows it (it vanished until its
// next usage row: Rocky 8 VM, 2026-11-12), but not with a usage row from
// before a mount that only the newer snapshot has, nor from before a
// different mount with the same id.
func TestDFHourlySnapshot(t *testing.T) {
	base := int64(1_790_000_000_000)
	hour := int64(3_600_000)
	m := func(ts int64, seq, id int, point, src string) store.MountEvent {
		return store.MountEvent{TS: ts, Action: "present", MountID: id, Point: point, Source: src, FSType: "xfs",
			Options: "rw", SuperOptions: "rw", Dev: "0:" + point, Root: "/", Seq: seq}
	}
	fs := func(ts int64, id int) store.FSSample {
		return store.FSSample{TS: ts, MountID: id, FrSize: 4096, Blocks: 1000, BFree: 500, BAvail: 500, Files: 100, FFree: 50}
	}
	snap := base + hour
	db := testrec.Open(t, nil,
		&store.Batch{Sample: store.Sample{TS: base},
			Mounts:    []store.MountEvent{m(base, 1, 2, "/", "/dev/vda4"), m(base, 2, 3, "/boot", "/dev/vda3")},
			FSSamples: []store.FSSample{fs(base, 2), fs(base, 3)}},
		// the hourly usage rows, 3 s before the hourly snapshot; mount 4
		// had a row under another mount point (the id was reused)
		&store.Batch{Sample: store.Sample{TS: snap - 3000},
			FSSamples: []store.FSSample{fs(snap-3000, 2), fs(snap-3000, 3), fs(snap-3000, 4)}},
		&store.Batch{Sample: store.Sample{TS: snap},
			Mounts: []store.MountEvent{m(snap, 1, 2, "/", "/dev/vda4"), m(snap, 2, 3, "/boot", "/dev/vda3"),
				m(snap, 3, 4, "/data", "/dev/vdb1")}})
	rows, err := DF(db, snap+60_000, DFSelect{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, r := range rows {
		got[r.Point] = r.SampleTS
	}
	if got["/"] != snap-3000 || got["/boot"] != snap-3000 {
		t.Errorf("df after the hourly snapshot: %v; want / and /boot with the usage of %d", got, snap-3000)
	}
	if _, ok := got["/data"]; ok {
		t.Errorf("/data shown with a usage row from before it was in the table: %v", got)
	}
}

// After retention, the oldest hour kept may begin with samples from the end
// of the deleted hour (a flush that straddles the hour is filed under the
// later one), before that hour's copies of the mounts: the recording kept
// starts at the oldest snapshot. There no earlier snapshot has the mounts,
// and df shows their usage rows written at the snapshot's time.
func TestCompleteFrom(t *testing.T) {
	hour := int64(3_600_000)
	base := int64(1_790_000_000_000) / hour * hour
	m := store.MountEvent{TS: base, Action: "present", MountID: 2, Point: "/", Source: "/dev/vda4", FSType: "xfs",
		Options: "rw", SuperOptions: "rw", Dev: "252:4", Root: "/", Seq: 1}
	db := testrec.Open(t, nil,
		&store.Batch{Sample: store.Sample{TS: base - 60_000}},
		&store.Batch{Sample: store.Sample{TS: base - 30_000}},
		&store.Batch{Sample: store.Sample{TS: base}, Mounts: []store.MountEvent{m},
			FSSamples: []store.FSSample{{TS: base, MountID: 2, FrSize: 4096, Blocks: 1000, BFree: 500, BAvail: 500}}},
		&store.Batch{Sample: store.Sample{TS: base + 30_000}})
	if got := CompleteFrom(db); got != base {
		t.Fatalf("CompleteFrom = %d, want %d", got, base)
	}
	if err := Covered(db, base-30_000); err == nil || !strings.Contains(err.Error(), "before the recording kept") {
		t.Errorf("Covered before the oldest snapshot: %v", err)
	}
	if err := Covered(db, base+30_000); err != nil {
		t.Errorf("Covered after it: %v", err)
	}
	rows, err := DF(db, base+30_000, DFSelect{})
	if err != nil || len(rows) != 1 || rows[0].Point != "/" {
		t.Errorf("df in the oldest hour: %+v, %v", rows, err)
	}
}
