package recorder

import (
	"os"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/procfs"
)

// readNUMA reads what numastat shows of each NUMA node, in node order:
// "nodeN numastat <line>" for each line of its numastat file, "nodeN
// meminfo <line>" for its meminfo, and "nodeN hugepages <size kB> <nr>
// <free> <surplus>" for each huge page size (numastat 2.0.19 sums these for
// the HugePages_* rows).
func readNUMA() ([]procfs.SnapLine, error) {
	const base = "/sys/devices/system/node/"
	ents, err := os.ReadDir(base)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var nodes []int
	for _, e := range ents {
		if n, err := strconv.Atoi(strings.TrimPrefix(e.Name(), "node")); err == nil && strings.HasPrefix(e.Name(), "node") {
			nodes = append(nodes, n)
		}
	}
	sort.Ints(nodes)
	var out []procfs.SnapLine
	add := func(key, line string) { out = append(out, procfs.SnapLine{Key: key, Line: line}) }
	for _, n := range nodes {
		node := "node" + strconv.Itoa(n)
		for _, file := range []string{"numastat", "meminfo"} {
			b, err := os.ReadFile(base + node + "/" + file)
			if err != nil {
				continue
			}
			for i, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
				add(node+" "+file+" "+strconv.Itoa(i), node+" "+file+" "+l)
			}
		}
		hp, _ := os.ReadDir(base + node + "/hugepages")
		for _, h := range hp {
			size, ok := strings.CutPrefix(h.Name(), "hugepages-")
			if !ok {
				continue
			}
			size = strings.TrimSuffix(size, "kB")
			line := node + " hugepages " + size
			for _, f := range []string{"nr_hugepages", "free_hugepages", "surplus_hugepages"} {
				b, _ := os.ReadFile(base + node + "/hugepages/" + h.Name() + "/" + f)
				v := strings.TrimSpace(string(b))
				if v == "" {
					v = "0"
				}
				line += " " + v
			}
			add(node+" hugepages "+size, line)
		}
	}
	return out, nil
}
