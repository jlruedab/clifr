package pqstore

import (
	"testing"
	"time"

	"clifr/internal/store"
)

// back moves a store's run start d seconds into the past (runs are Unix
// seconds: stores opened in one test share one otherwise).
func back(s *Store, d int64) {
	s.run -= d
	for i := range s.meta {
		s.meta[i].Run = s.run
	}
}

// TestPrevRun: a run that stopped cleanly says so to the next one; one that
// only flushed (a crash) does not, and the next run sees its last sample; a
// run from before the stop marker is not judged.
func TestPrevRun(t *testing.T) {
	dir := t.TempDir()
	ts := time.Now().Add(-time.Minute).UnixMilli()

	old, _ := Open(dir, Options{})
	back(old, 300)
	old.meta = old.meta[:0] // before writes_stop existed
	delete(old.metaAll, MetaWritesStop)
	old.SetMeta("boot_id", "A")
	old.Write(&store.Batch{Sample: store.Sample{TS: ts - 60000}})
	old.Flush()
	if p, ok := mustOpen(t, dir, 200).PrevRun(); !ok || p.Known {
		t.Errorf("a run without the marker: %+v %v", p, ok)
	}

	crashed := mustOpen(t, dir, 200)
	crashed.SetMeta("boot_id", "A")
	crashed.Write(&store.Batch{Sample: store.Sample{TS: ts}})
	crashed.Flush() // and no Close
	next := mustOpen(t, dir, 100)
	p, ok := next.PrevRun()
	if !ok || !p.Known || p.Clean || p.BootID != "A" || p.LastSampleMS != ts || p.Run != crashed.run {
		t.Errorf("after a crash: %+v %v (want run %d, last sample %d)", p, ok, crashed.run, ts)
	}
	next.SetMeta("boot_id", "B")
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	p, ok = mustOpen(t, dir, 0).PrevRun()
	if !ok || !p.Clean || p.BootID != "B" || p.StopMS == 0 {
		t.Errorf("after a clean stop: %+v %v", p, ok)
	}
}

// mustOpen opens a store whose run started d seconds ago.
func mustOpen(t *testing.T, dir string, d int64) *Store {
	t.Helper()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if d > 0 {
		back(s, d)
		s.prev = readPrevRun(dir, s.run)
	}
	return s
}
