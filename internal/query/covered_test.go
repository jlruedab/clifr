package query

import (
	"strings"
	"testing"
	"time"

	"clifr/internal/duck"
	"clifr/internal/pqstore"
	"clifr/internal/store"
	"clifr/internal/testrec"
)

// Samples every 30 s, a 10-minute gap, then more; nothing after the last.
func TestCovered(t *testing.T) {
	base := int64(1_790_000_000_000)
	var batches []*store.Batch
	for _, off := range []int64{0, 30, 60, 660, 690} {
		batches = append(batches, &store.Batch{Sample: store.Sample{TS: base + off*1000}})
	}
	db := testrec.Open(t, []string{"interval_s", "30", "flush_interval_s", "300"}, batches...)
	for _, c := range []struct {
		off  int64
		want string // "" = covered
	}{
		{-10, ""}, // before the start: SnapshotAt's error
		{45, ""},
		{100, ""},           // 40 s after a sample: within 2.5 intervals
		{300, "no samples"}, // in the gap
		{700, ""},
		{800, "after the end of the recording"},
	} {
		err := Covered(db, base+c.off*1000)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("+%ds: %v", c.off, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("+%ds: %v, want %q", c.off, err, c.want)
		}
	}
	if err := Covered(db, base+800_000); !strings.Contains(err.Error(), "every 5m0s") {
		t.Errorf("flush interval not named: %v", err)
	}
}

// A moment after a run's last sample and before the next run's first is not
// covered, however short the gap: clifrd had stopped (2026-11-13: ps --at
// 11:50 showed the processes of the boot that ended at 11:48:53). A run is
// named by its start second, before its samples, as clifrd's runs are.
func TestCoveredBetweenRuns(t *testing.T) {
	dir := t.TempDir()
	s0 := time.Now().Truncate(time.Second).UnixMilli()
	run := func(startOff int64, boot string, offs ...int64) {
		time.Sleep(time.Until(time.UnixMilli(s0 + startOff)))
		s, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		s.SetMeta("interval_s", "1")
		s.SetMeta("boot_id", boot)
		for _, off := range offs {
			s.Write(&store.Batch{Sample: store.Sample{TS: s0 + off}})
		}
		s.Close()
	}
	run(0, "boot-a", 1000, 2000)
	run(3000, "boot-b", 3500, 4500)
	run(5000, "boot-b", 5500) // clifrd restarted, same boot
	db, err := duck.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	between := func(prev, next int64, why string) string {
		return "between two runs: clifrd's last sample was " + FormatMS(s0+prev) + ", the next " + FormatMS(s0+next) + " (" + why + ")"
	}
	for _, c := range []struct {
		off  int64
		want string // "" = covered
	}{
		{1500, ""},
		{2000, ""}, // the first run's last sample
		{2500, between(2000, 3500, "after a reboot")}, // within 2.5 intervals of it, but the run ended
		{4000, ""},
		{5200, between(4500, 5500, "clifrd restarted")},
	} {
		err := Covered(db, s0+c.off)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("+%dms: %v", c.off, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("+%dms: %v, want %q", c.off, err, c.want)
		}
	}
}
