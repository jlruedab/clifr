package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGCPercentFor(t *testing.T) {
	const M = 1 << 20
	for _, c := range []struct {
		live uint64
		want int
	}{
		{0, 100}, {100 * M, 100}, {192 * M, 100}, {256 * M, 50}, {240 * M, 60}, {1000 * M, 50},
	} {
		if got := gcPercentFor(c.live, 384*M); got != c.want {
			t.Errorf("live %d MiB: GOGC %d, want %d", c.live/M, got, c.want)
		}
	}
}

// TestCgroupMemoryMax: the smallest limit on the recorder's cgroup and its
// ancestors, for cgroup v2 and v1; none when unlimited.
func TestCgroupMemoryMax(t *testing.T) {
	root := t.TempDir()
	put := func(rel, v string) {
		os.MkdirAll(filepath.Join(root, filepath.Dir(rel)), 0o755)
		os.WriteFile(filepath.Join(root, rel), []byte(v+"\n"), 0o644)
	}
	put("system.slice/memory.max", "2147483648")
	put("system.slice/clifrd.service/memory.max", "805306368")
	put("other.slice/memory.max", "1073741824")
	put("other.slice/x.service/memory.max", "max")
	put("memory/system.slice/clifrd.service/memory.limit_in_bytes", "9223372036854771712")
	put("memory/system.slice/memory.limit_in_bytes", "536870912")
	for _, c := range []struct {
		cgroup string
		want   uint64
	}{
		{"0::/system.slice/clifrd.service", 805306368},
		{"0::/other.slice/x.service", 1073741824}, // the parent's
		{"0::/nolimit.slice/y.service", 0},
		// v1 (RHEL 8): the memory controller's line; unlimited is a huge number.
		{"12:memory:/system.slice/clifrd.service\n1:name=systemd:/system.slice/clifrd.service", 536870912},
		{"", 0},
	} {
		if got := cgroupMemoryMax(c.cgroup, root); got != c.want {
			t.Errorf("%q: %d, want %d", c.cgroup, got, c.want)
		}
	}
}
