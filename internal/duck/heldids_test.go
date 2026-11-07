package duck

import (
	"testing"
	"time"

	"clifr/internal/pqstore"
	"clifr/internal/store"
)

// Recordings made before 2026-11-07 reuse fds_held ids in every run. Two
// runs here give id 7 to different fds: the first run's closed, the second
// run's still open. Both are loaded (one row per id and first_seen); before,
// the closed row hid the open fd. Versions of one fd still collapse to one
// row (the closed one).
func TestHeldIDsReusedAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	write := func(batches ...*store.Batch) {
		pq, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range batches {
			if err := pq.Write(b); err != nil {
				t.Fatal(err)
			}
		}
		if err := pq.Close(); err != nil {
			t.Fatal(err)
		}
	}
	const a, b, c = 1_790_000_000_000, 1_790_000_100_000, 1_790_000_200_000
	// Run 1: id 7 (fd 3) seen at a, closed at b; id 8 (fd 4) open, flushed, then closed.
	write(&store.Batch{Sample: store.Sample{TS: a},
		HeldInserts: []store.HeldFD{{ID: 7, PID: 10, StartTime: 1, FD: 3, Target: "/old", FirstSeen: a},
			{ID: 8, PID: 10, StartTime: 1, FD: 4, Target: "/eight", FirstSeen: a}}},
		&store.Batch{Sample: store.Sample{TS: b}, HeldCloses: []store.Close{{ID: 7, LastSeen: b}, {ID: 8, LastSeen: b}}})
	time.Sleep(1100 * time.Millisecond) // the next run starts in a later second
	// Run 2: id 7 again, another fd, still open.
	write(&store.Batch{Sample: store.Sample{TS: c},
		HeldInserts: []store.HeldFD{{ID: 7, PID: 20, StartTime: 2, FD: 5, Target: "/new", FirstSeen: c}}})

	dk, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer dk.Close()
	if _, err := dk.Prepare("fds_held"); err != nil {
		t.Fatal(err)
	}
	rows, err := dk.DB.Query(`SELECT id, target, first_seen FROM fds_held ORDER BY id, first_seen`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var id, first int64
		var target string
		rows.Scan(&id, &target, &first)
		got = append(got, target)
	}
	if len(got) != 3 || got[0] != "/old" || got[1] != "/new" || got[2] != "/eight" {
		t.Errorf("fds_held rows: %v, want /old, /new (both id 7) and /eight", got)
	}
}
