package query

import (
	"strings"
	"testing"
	"time"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// TestBalloonChanges: a virtio balloon (no deflate-on-oom: the total goes
// down too) inflated over two samples, then deflated; a reboot starts the
// counters again (no change); then memory hotplug (the total alone).
func TestBalloonChanges(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.UTC
	const gib = 1 << 20 // KiB
	base := int64(1_790_000_000_000)
	type s struct {
		up, total, pages, in, out int64
	}
	var batches []*store.Batch
	for i, v := range []s{
		{1000, 8 * gib, -1, 0, 0},
		{11000, 7 * gib, -1, 262144, 0},      // +1 GiB into the balloon
		{21000, 6 * gib, -1, 524288, 0},      // +1 GiB more: the same change
		{31000, 6 * gib, -1, 524288, 0},      // nothing
		{41000, 7 * gib, -1, 524288, 262144}, // 1 GiB out
		{500, 8 * gib, -1, 0, 0},             // a reboot: counters since boot
		{10500, 9 * gib, 0, 0, 0},            // hotplug (a kernel with nr_balloon_pages)
		{20500, 9 * gib, 131072, 131072, 0},  // VMware-like: the total stays
	} {
		ts := base + int64(i)*10_000
		batches = append(batches, &store.Batch{Sample: store.Sample{TS: ts}, Sys: []store.SysSample{{TS: ts, UptimeMS: v.up,
			MemTotal: v.total, BalloonPages: v.pages, BalloonInflate: v.in, BalloonDeflate: v.out}}})
	}
	db := testrec.Open(t, []string{"page_kb", "4"}, batches...)
	ch, err := BalloonChanges(db, base, base+70_000)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range ch {
		got = append(got, FormatMS(c.TS)+" "+FormatMS(c.EndTS)+" "+BalloonText(c))
	}
	want := []string{
		"2026-09-21 14:13:30 2026-09-21 14:13:40 memory balloon inflated by 2.0 GiB (the hypervisor took it; 2.0 GiB in the balloon; MemTotal 6.0 GiB)",
		"2026-09-21 14:14:00 2026-09-21 14:14:00 memory balloon deflated by 1.0 GiB (the hypervisor gave it back; 1.0 GiB in the balloon; MemTotal 7.0 GiB)",
		"2026-09-21 14:14:20 2026-09-21 14:14:20 MemTotal changed by +1.0 GiB to 9.0 GiB (memory hotplug, or a balloon this kernel does not count)",
		"2026-09-21 14:14:30 2026-09-21 14:14:30 memory balloon inflated by 512 MiB (the hypervisor took it; 512 MiB in the balloon)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("changes:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// A window starting inside the inflation still compares its first
	// sample with the one before.
	if ch, _ := BalloonChanges(db, base+20_000, base+20_000); len(ch) != 1 || ch[0].DeltaKB != gib {
		t.Errorf("from the second sample: %+v", ch)
	}
	if n := BalloonNote(db, base+30_000, base+30_000); !strings.HasPrefix(n, "memory balloon: 2.0 GiB held by the hypervisor") {
		t.Errorf("note at a moment = %q", n)
	}
	if n := BalloonNote(db, base+50_000, base+50_000); n != "" {
		t.Errorf("note after the reboot = %q, want none", n)
	}
	if n := BalloonNote(db, base, base+30_000); !strings.Contains(n, "inflated by 2.0 GiB") {
		t.Errorf("note over a range = %q", n)
	}
}

// Recordings before schema 16: MemTotal only, no error.
func TestBalloonOldRecording(t *testing.T) {
	base := int64(1_790_000_000_000)
	db := testrec.Open(t, nil,
		&store.Batch{Sample: store.Sample{TS: base}, Sys: []store.SysSample{{TS: base, UptimeMS: 1000, MemTotal: 1000}}},
		&store.Batch{Sample: store.Sample{TS: base + 10_000}, Sys: []store.SysSample{{TS: base + 10_000, UptimeMS: 11000, MemTotal: 1000}}})
	if ch, err := BalloonChanges(db, base, base+10_000); err != nil || len(ch) != 0 {
		t.Errorf("changes = %+v %v", ch, err)
	}
}
