package query

import (
	"strings"
	"testing"
)

// TestVmstatHeaders: the header again every 21 lines (vmstat into a pipe),
// once with -n; procps 3.3 has no gu column; -S converts memory.
func TestVmstatHeaders(t *testing.T) {
	rows := make([]VMStatRow, 23)
	for i := range rows {
		rows[i] = VMStatRow{TS: int64(i) * 1000, Free: 2048, GU: 1}
	}
	count := func(o VmstatOpts) (heads int, last string) {
		var b strings.Builder
		PrintVMStatOpts(&b, rows, o)
		lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
		for _, l := range lines {
			if strings.HasPrefix(l, "procs") {
				heads++
			}
		}
		return heads, lines[len(lines)-1]
	}
	if n, _ := count(VmstatOpts{}); n != 2 {
		t.Errorf("23 lines: %d headers, want 2 (lines 1 and 22)", n)
	}
	if n, _ := count(VmstatOpts{OneHead: true}); n != 1 {
		t.Errorf("-n: %d headers, want 1", n)
	}
	if _, last := count(VmstatOpts{Version: "3.3.17"}); !strings.HasSuffix(last, " 0  0") || len(strings.Fields(last)) != 17 {
		t.Errorf("3.3.17 line %q: want 17 columns, no gu", last)
	}
	if _, last := count(VmstatOpts{Unit: 'M'}); strings.Fields(last)[3] != "2" {
		t.Errorf("-S M: free %q, want 2", strings.Fields(last)[3])
	}
}

// TestVmstatDiskHeaders: procps 4.0.4 counts every device of /proc/diskstats
// (partitions too) for its header, 3.3 the disks it prints.
func TestVmstatDiskHeaders(t *testing.T) {
	var rep VMStatDisks
	for i := 0; i < 30; i++ {
		rep.Disks = append(rep.Disks, VMStatDisk{Name: "d", part: i%2 == 1}) // 15 disks, 15 partitions
	}
	heads := func(o VmstatOpts) int {
		var b strings.Builder
		PrintVMStatDisks(&b, []VMStatDisks{rep}, o)
		return strings.Count(b.String(), "disk- ")
	}
	// 4.0.4: devices 0 and 21 are multiples of 21; 21 is a partition (odd), so one header.
	if n := heads(VmstatOpts{}); n != 1 {
		t.Errorf("4.0.4: %d headers, want 1", n)
	}
	rep.Disks[21].part = false
	if n := heads(VmstatOpts{}); n != 2 {
		t.Errorf("4.0.4 with device 21 a disk: %d headers, want 2", n)
	}
	// 3.3: 16 disks printed, a header before the first only.
	if n := heads(VmstatOpts{Version: "3.3.17"}); n != 1 {
		t.Errorf("3.3: %d headers, want 1", n)
	}
}

// TestIostatOptions: -m's and -s's headers and values, -z, -N.
func TestIostatOptions(t *testing.T) {
	rep := IOStatReport{Devices: []IOStatDev{
		{Device: "dm-0", DMName: "vg-root", TPS: 10, RS: 4, WS: 6, RKBS: 2048, WKBS: 1024, KBRead: 4096, KBWrtn: 2048, RAwait: 1, WAwait: 2},
		{Device: "sda"}}}
	out := func(o IOStatOpts) string {
		var b strings.Builder
		printIOStat12(&b, rep, o)
		return b.String()
	}
	if got := out(IOStatOpts{MB: true}); !strings.Contains(got, "MB_read/s    MB_wrtn/s") ||
		!strings.Contains(got, "dm-0             10.00         2.00         1.00         0.00          4          2          0") {
		t.Errorf("-m:\n%s", got)
	}
	if got := out(IOStatOpts{Short: true}); !strings.Contains(got, "kB_read/s    kB_w+d/s    kB_read    kB_w+d") {
		t.Errorf("-s:\n%s", got)
	}
	// -x -s: await over all I/Os: (4*1 + 6*2) / 10.
	if got := out(IOStatOpts{Extended: true, Short: true}); !strings.Contains(got, "dm-0             10.00   3072.00     0.00    1.60   307.20") {
		t.Errorf("-xs:\n%s", got)
	}
	if got := out(IOStatOpts{Zero: true, DevMap: true}); strings.Contains(got, "sda") || !strings.Contains(got, "vg-root") {
		t.Errorf("-zN:\n%s", got)
	}
}
