package query

import (
	"strings"
	"testing"

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
