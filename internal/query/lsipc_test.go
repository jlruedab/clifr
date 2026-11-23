package query

import (
	"strings"
	"testing"
)

func TestLsipcFormats(t *testing.T) {
	if got := strmode(0640); got != "rw-r-----" {
		t.Errorf("strmode 0640 = %q", got)
	}
	// dest, then locked after a comma; hugetlb without dest gets none (lsipc.c).
	for perms, want := range map[int64]string{0600: "", 01600: "dest", 03600: "dest,locked", 06600: "lockedhugetlb"} {
		if got := shmStatus(perms); got != want {
			t.Errorf("shmStatus(%o) = %q, want %q", perms, got, want)
		}
	}
	now := int64(1_795_400_000_000) // 2026-11-24 (UTC)
	if got := lsipcTime("short", now/1000-60, now); !strings.Contains(got, ":") {
		t.Errorf("today: %q, want HH:MM", got)
	}
	if got := lsipcTime("short", now/1000-40*86400, now); len(got) != 5 {
		t.Errorf("this year: %q, want MonDD", got)
	}
	if got := lsipcTime("short", now/1000-400*86400, now); !strings.HasPrefix(got, "2025-") {
		t.Errorf("an earlier year: %q, want YYYY-MonDD", got)
	}
	if !LsipcApplies("SIZE", "shm") || LsipcApplies("SIZE", "sem") || !LsipcApplies("KEY", "sem") || LsipcApplies("KEY", "") {
		t.Error("LsipcApplies")
	}
}

// TestLsipcPrint: libsmartcols' layout; --noheadings keeps the header's
// widths before 2.41; an empty table prints nothing.
func TestLsipcPrint(t *testing.T) {
	s := func(v string) *string { return &v }
	tb := &LsipcTable{Cols: []string{"KEY", "ID", "NSEMS"}, Rows: [][]*string{{s("0x00000001"), s("3"), s("2")}}}
	out := func(o LsipcOpts) string {
		var b strings.Builder
		PrintLsipc(&b, tb, o)
		return b.String()
	}
	if got := out(LsipcOpts{}); got != "KEY        ID NSEMS\n0x00000001 3      2\n" {
		t.Errorf("table:\n%q", got)
	}
	if got := out(LsipcOpts{NoHead: true, Version: "2.37"}); got != "0x00000001 3      2\n" {
		t.Errorf("2.37 --noheadings: %q", got)
	}
	if got := out(LsipcOpts{NoHead: true}); got != "0x00000001 3 2\n" {
		t.Errorf("2.41 --noheadings: %q", got)
	}
	tb.Rows = nil
	if got := out(LsipcOpts{}); got != "" {
		t.Errorf("empty: %q", got)
	}
}
