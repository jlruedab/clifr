package main

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"runtime/metrics"
	"slices"
	"strconv"
	"strings"
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

// softLimitShare: the Go memory limit clifrd sets, as a share of its
// cgroup's memory limit.
const softLimitShare = 0.8

// cgroupMemoryMax is the smallest memory limit on the cgroup that
// /proc/self/cgroup names and its ancestors (cgroup v2 memory.max, or v1's
// memory controller's memory.limit_in_bytes), 0 if there is none. sysRoot is
// /sys/fs/cgroup (a directory for tests).
func cgroupMemoryMax(cgroup, sysRoot string) uint64 {
	var dir, file string
	for _, l := range strings.Split(cgroup, "\n") {
		f := strings.SplitN(l, ":", 3)
		if len(f) != 3 {
			continue
		}
		switch {
		case f[0] == "0" && f[1] == "" && dir == "":
			dir, file = filepath.Join(sysRoot, f[2]), "memory.max"
		case slices.Contains(strings.Split(f[1], ","), "memory"):
			dir, file = filepath.Join(sysRoot, "memory", f[2]), "memory.limit_in_bytes"
		}
	}
	if dir == "" {
		return 0
	}
	var min uint64
	for d := dir; strings.HasPrefix(d, sysRoot); d = filepath.Dir(d) {
		b, err := os.ReadFile(filepath.Join(d, file))
		if err == nil {
			// "max", or v1's "unlimited" (a page-rounded 2^63).
			if n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil && n < 1<<60 && (min == 0 || n < min) {
				min = n
			}
		}
		if d == sysRoot {
			break
		}
	}
	return min
}

// setSoftLimit sets Go's memory limit to softLimitShare of the cgroup's
// limit (the unit's MemoryMax), so that the heap and its uncollected garbage
// stay below the hard limit: with only GOGC the heap may grow to 1.5 to 2
// times the live heap before a collection, and in the attack test
// (2026-11-10) that took the recorder to 700 of 768 MiB while the memory
// guard kept the live heap near its 384 MiB. The live heap stays far below
// this limit (the guard), so the collector does not run continuously as it
// did with a limit near the live heap (see tuneGC). It returns the limit set
// (0: none).
func setSoftLimit(cgroup string) int64 {
	max := cgroupMemoryMax(cgroup, "/sys/fs/cgroup")
	if max == 0 {
		return 0
	}
	limit := int64(float64(max) * softLimitShare)
	debug.SetMemoryLimit(limit)
	return limit
}
