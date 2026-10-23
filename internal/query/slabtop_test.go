package query

import (
	"strings"
	"testing"
)

func TestSlabSort3(t *testing.T) {
	// procps 3.3's merge sort takes the later half's cache on a tie.
	in := []Slab{{Name: "a", Objs: 5}, {Name: "b", Objs: 7}, {Name: "c", Objs: 5}, {Name: "d", Objs: 0}, {Name: "e", Objs: 0}}
	var got []string
	for _, s := range slabSort3(in) {
		got = append(got, s.Name)
	}
	if strings.Join(got, "") != "bcaed" {
		t.Errorf("3.3 order %v, want b c a e d", got)
	}
}

func TestSlabUse(t *testing.T) {
	// The two single-precision formulas truncate differently for some counts.
	diff := 0
	for a := uint32(1); a < 1000; a++ {
		if slabUse(a, 1000, true) != slabUse(a, 1000, false) {
			diff++
		}
	}
	if slabUse(99, 100, true) != 99 || diff == 0 {
		t.Errorf("use(99/100) %d, formulas differing for %d counts", slabUse(99, 100, true), diff)
	}
}

func TestPrintNumastat(t *testing.T) {
	nodes := []NUMANode{{Node: 0, Numastat: []string{"numa_hit 1000", "numa_miss 0"},
		Meminfo: []string{"Node 0 MemTotal:       2048 kB", "Node 0 HugePages_Total:     0"}}}
	var b strings.Builder
	PrintNumastat(&b, nodes, NumastatOptions{}, 4096)
	want := "                           node0\nnuma_hit                    1000\nnuma_miss                      0\n"
	if b.String() != want {
		t.Errorf("compat: got\n%q\nwant\n%q", b.String(), want)
	}
	b.Reset()
	PrintNumastat(&b, nodes, NumastatOptions{Meminfo: true}, 4096)
	want = "\nPer-node system memory usage (in MBs):\n" +
		"                          Node 0           Total\n" +
		"                 --------------- ---------------\n" +
		"MemTotal                    2.00            2.00\n" +
		"HugePages_Total             0.00            0.00\n"
	if b.String() != want {
		t.Errorf("-m: got\n%q\nwant\n%q", b.String(), want)
	}
}
