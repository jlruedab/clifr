package query

import (
	"strings"
	"testing"
)

func TestLsmem(t *testing.T) {
	m, err := newLsmem(1, []string{"block_size_bytes\t8000000", "zones\t1", "0\t0\tonline\t1\t0\tNone",
		"1\t15\tonline\t1\t0\tDMA32", "16\t17\toffline\t0\t0\tNormal"})
	if err != nil {
		t.Fatal(err)
	}
	out := func(o LsmemOpts) string {
		var b strings.Builder
		PrintLsmem(&b, m, o)
		return b.String()
	}
	// The default columns do not split by zone: blocks 0-15 merge.
	want := "RANGE                                  SIZE   STATE REMOVABLE BLOCK\n" +
		"0x0000000000000000-0x000000007fffffff    2G  online       yes  0-15\n" +
		"0x0000000080000000-0x000000008fffffff  256M offline           16-17\n\n" +
		"Memory block size:                128M\nTotal online memory:                2G\nTotal offline memory:             256M\n"
	if got := out(LsmemOpts{}); got != want {
		t.Errorf("lsmem:\n%s\nwant:\n%s", got, want)
	}
	if got := out(LsmemOpts{Cols: []string{"BLOCK", "ZONES"}, Summary: "never"}); got != "BLOCK  ZONES\n    0   None\n 1-15  DMA32\n16-17 Normal\n" {
		t.Errorf("-o BLOCK,ZONES:\n%s", got)
	}
	if got := out(LsmemOpts{Summary: "only", Version: "2.37"}); !strings.HasPrefix(got, "Memory block size:       128M\n") {
		t.Errorf("2.37 --summary:\n%q", got)
	}
}
