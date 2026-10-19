package main

import (
	"runtime/debug"
	"runtime/metrics"
	"time"
)

// GOGC bounds for tuneGC: Go's default, and the fixed value the recorder
// used before (less memory, more collections).
const (
	gcPercentMax = 100
	gcPercentMin = 50
)

// gcPercentFor is the GOGC that keeps the heap goal, live × (1 + GOGC/100),
// at about target, within [gcPercentMin, gcPercentMax].
func gcPercentFor(live, target uint64) int {
	if live == 0 || 2*live <= target {
		return gcPercentMax
	}
	p := int(100 * (float64(target)/float64(live) - 1))
	return max(gcPercentMin, min(p, gcPercentMax))
}

// tuneGC adjusts GOGC to the live heap every interval until stop is closed.
// GOGC=50 cost about 0.4% of one core in collections at the busy load and
// GOGC=100 about 120 MiB more memory. Go's default while the heap goal stays
// under target, then less down to 50. Unlike a memory limit (GOMEMLIMIT),
// this never collects continuously when the live heap itself is large: a
// 384 MiB limit took 7 of 11% of one core in collections with 100,000
// connections.
func tuneGC(target uint64, interval time.Duration, stop <-chan struct{}) {
	s := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	cur := gcPercentMax
	debug.SetGCPercent(cur)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		metrics.Read(s)
		if s[0].Value.Kind() != metrics.KindUint64 {
			return
		}
		if p := gcPercentFor(s[0].Value.Uint64(), target); p != cur {
			cur = p
			debug.SetGCPercent(p)
		}
	}
}
