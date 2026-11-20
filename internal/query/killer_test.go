package query

import (
	"strings"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

func TestLifeKiller(t *testing.T) {
	sig := func(n int) *int { return &n }
	end := func(ms int64) *int64 { return &ms }
	b := &store.Batch{Sample: store.Sample{TS: 1000},
		ProcInserts: []store.ProcRow{
			{ID: 1, PID: 40, StartTime: 500, Comm: "bash", Cmdline: "bash -l", FirstSeen: 500, Source: "sample"},
			{ID: 2, PID: 50, StartTime: 600, Comm: "worker", Cmdline: "worker --x", FirstSeen: 600, Source: "ebpf",
				LastSeen: end(900), Ended: end(900), ExitTS: end(900), Signal: sig(15), Killer: &store.Killer{PID: 40, UID: 0, Comm: "bash"}},
			{ID: 3, PID: 51, StartTime: 600, Comm: "crash", Cmdline: "crash", FirstSeen: 600, Source: "ebpf",
				LastSeen: end(950), Ended: end(950), ExitTS: end(950), Signal: sig(11), Killer: &store.Killer{}},
			{ID: 4, PID: 52, StartTime: 600, Comm: "abort", Cmdline: "abort", FirstSeen: 600, Source: "ebpf",
				LastSeen: end(960), Ended: end(960), ExitTS: end(960), Signal: sig(6), Killer: &store.Killer{PID: 52, Comm: "abort"}},
			{ID: 5, PID: 53, StartTime: 600, Comm: "old", Cmdline: "old", FirstSeen: 600, Source: "ebpf",
				LastSeen: end(970), Ended: end(970), ExitTS: end(970), Signal: sig(9)},
		},
		ProcSamples: []store.ProcSample{{ProcID: 1, TS: 1000, State: "S"}},
	}
	db := testrec.Open(t, nil, b)
	rows, err := Life(db, 0, 1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]string{40: "", 50: "40 (bash, root)", 51: "the kernel", 52: "itself", 53: ""}
	for _, r := range rows {
		if got := r.SentBy(); got != want[r.PID] {
			t.Errorf("pid %d: sent by %q, want %q", r.PID, got, want[r.PID])
		}
		if r.PID == 50 && r.KillerCommand != "bash -l" {
			t.Errorf("sender's command %q", r.KillerCommand)
		}
	}
	var out strings.Builder
	PrintLife(&out, rows)
	if !strings.Contains(out.String(), "SENT BY") || !strings.Contains(out.String(), "SIGTERM 40 (bash, root) ") {
		t.Errorf("life:\n%s", out.String())
	}
	evs, err := Events(db, 0, 1000, nil, map[string]bool{"exit": true})
	if err != nil {
		t.Fatal(err)
	}
	var d []string
	for _, e := range evs {
		d = append(d, e.Detail)
	}
	all := strings.Join(d, "\n")
	for _, s := range []string{"SIGTERM from 40 (bash, root) [bash -l] after 300ms: worker --x",
		"SIGSEGV from the kernel after", "SIGABRT from itself after", "SIGKILL after 370ms: old"} {
		if !strings.Contains(all, s) {
			t.Errorf("events: no %q in\n%s", s, all)
		}
	}
}
