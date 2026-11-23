package recorder

import (
	"os"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/procfs"
)

// memBlocksMS: how often /sys/devices/system/memory is read (lsmem): memory
// hotplug is rare and a 1 TB machine with 128 MiB blocks has 8,192 of them.
const memBlocksMS = 600_000

// readMemBlocks is what lsmem reads under /sys/devices/system/memory: the
// block size ("block_size_bytes\tHEX"), whether the kernel has valid_zones
// ("zones\t1"), and the blocks as ranges of consecutive ones with the same
// attributes, "first\tlast\tstate\tremovable\tnode\tzones" (node -1: none;
// zones as valid_zones reads, "" without it), keyed by the first block.
// lsmem merges or splits by its columns: these ranges are never coarser.
func readMemBlocks() ([]procfs.SnapLine, error) {
	const base = "/sys/devices/system/memory/"
	bs, err := os.ReadFile(base + "block_size_bytes")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := []procfs.SnapLine{{Key: "block_size_bytes", Line: "block_size_bytes\t" + strings.TrimSpace(string(bs))}}
	_, zerr := os.Stat(base + "memory0/valid_zones")
	if zerr == nil {
		out = append(out, procfs.SnapLine{Key: "zones", Line: "zones\t1"})
	}
	ents, err := os.ReadDir(base)
	if err != nil {
		return out, err
	}
	var idx []int
	for _, e := range ents {
		if n, err := strconv.Atoi(strings.TrimPrefix(e.Name(), "memory")); err == nil && strings.HasPrefix(e.Name(), "memory") {
			idx = append(idx, n)
		}
	}
	sort.Ints(idx)
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	type blk struct {
		first, last int
		attrs       string
	}
	var cur *blk
	flush := func() {
		if cur != nil {
			k := strconv.Itoa(cur.first)
			out = append(out, procfs.SnapLine{Key: "r" + k, Line: k + "\t" + strconv.Itoa(cur.last) + "\t" + cur.attrs})
		}
	}
	for _, n := range idx {
		dir := base + "memory" + strconv.Itoa(n) + "/"
		node := "-1"
		if des, err := os.ReadDir(dir); err == nil {
			for _, d := range des {
				if v, ok := strings.CutPrefix(d.Name(), "node"); ok {
					if _, err := strconv.Atoi(v); err == nil {
						node = v
						break
					}
				}
			}
		}
		zones := ""
		if zerr == nil {
			zones = read(dir + "valid_zones")
		}
		attrs := read(dir+"state") + "\t" + read(dir+"removable") + "\t" + node + "\t" + zones
		if cur != nil && cur.last+1 == n && cur.attrs == attrs {
			cur.last = n
			continue
		}
		flush()
		cur = &blk{first: n, last: n, attrs: attrs}
	}
	flush()
	return out, nil
}
