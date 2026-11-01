package query

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"clifr/internal/duck"
	"clifr/internal/pqstore"
	"clifr/internal/store"
	"clifr/internal/testrec"
)

// The data kept per day comes from finished hour files and the time recorded
// in them: not from flush parts, nor from hours partly without samples.
func TestKeptPerDay(t *testing.T) {
	dir := t.TempDir()
	file := func(table, day, name string, size int) {
		p := filepath.Join(dir, table, day, name+".parquet")
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	file("samples", "2026-10-30", "10", 600)
	file("processes", "2026-10-30", "10", 1800)
	file("samples", "2026-10-30", "11", 300)  // half recorded: a suspend
	file("samples", "2026-10-30", "12-05", 9) // the hour still in parts
	file("samples", "2026-10-30", "12-10", 9)
	file("processes", "open", "1792903518", 5000)
	hour := func(h int) int64 { return time.Date(2026, 10, 30, h, 0, 0, 0, time.UTC).UnixMilli() }
	var ts []int64
	for t := hour(10); t <= hour(11)+1_800_000; t += 30_000 {
		ts = append(ts, t)
	}
	ts = append(ts, hour(12)+300_000, hour(12)+330_000)
	// 2,400 bytes in hour 10 and 300 in the first half of hour 11: 1.5 hours
	// recorded, 1,800 bytes per hour.
	if got := keptPerDay(dir, ts, 75_000); got != 1800*24 {
		t.Errorf("kept per day %d, want %d", got, 1800*24)
	}
	if got := keptPerDay("", ts, 75_000); got != 0 {
		t.Errorf("no data directory: %d", got)
	}
}

// The recorder's CPU average leaves out time without samples (a suspend),
// and computing it does not wait on DuckDB's single connection.
func TestComputeStatsGap(t *testing.T) {
	base := int64(1_790_000_000_000)
	var batches []*store.Batch
	add := func(ts, cpuUS int64) {
		batches = append(batches, &store.Batch{Sample: store.Sample{TS: ts, CPUUS: cpuUS, RSSKB: 1000}})
	}
	add(base, 0)
	add(base+30_000, 300_000)              // 1% of one core over 30 s
	add(base+10*3_600_000, 300_000)        // 10 h suspended: no CPU
	add(base+10*3_600_000+30_000, 600_000) // 1% again
	db := testrec.Open(t, []string{"interval_s", "30"}, batches...)
	done := make(chan *Stats, 1)
	go func() {
		st, err := ComputeStats(db)
		if err != nil {
			t.Error(err)
		}
		done <- st
	}()
	select {
	case st := <-done:
		if st != nil && (st.CPUPctOneCore < 0.99 || st.CPUPctOneCore > 1.01) {
			t.Errorf("CPU %.4f%% of one core, want 1%%", st.CPUPctOneCore)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("ComputeStats did not return")
	}
}

// A later run with a shorter interval does not make the gaps of an earlier
// one's samples look like outages.
func TestIntervalOverRuns(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour).Truncate(time.Second).UnixMilli()
	run := func(interval string, samples ...int64) {
		s, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		s.SetMeta("interval_s", interval)
		for _, ts := range samples {
			s.Write(&store.Batch{Sample: store.Sample{TS: ts}})
		}
		s.Close()
	}
	run("30", base, base+30_000, base+60_000)
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second))) // runs are named by their start second
	run("2", base+600_000, base+602_000)
	db, err := duck.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if iv := IntervalMS(db); iv != 30_000 {
		t.Errorf("interval %d ms, want the longest run's 30000", iv)
	}
	if err := Covered(db, base+45_000); err != nil {
		t.Errorf("between two samples of the 30 s run: %v", err)
	}
	if err := Covered(db, base+300_000); err == nil {
		t.Error("the gap between the runs was not reported")
	}
}
