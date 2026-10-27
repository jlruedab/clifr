package query

import (
	"strings"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

func TestLossNote(t *testing.T) {
	db := testrec.Open(t, nil,
		&store.Batch{Sample: store.Sample{TS: 1000}, Stats: []store.StatRow{{TS: 1000, Source: "ebpf_exec", Events: 5, Dropped: 7}}},
		&store.Batch{Sample: store.Sample{TS: 31000}, Stats: []store.StatRow{{TS: 31000, Source: "ebpf_exec", Events: 5}}},
		&store.Batch{Sample: store.Sample{TS: 61000}, Stats: []store.StatRow{
			{TS: 61000, Source: "ebpf_exec", Events: 5, Dropped: 3}, {TS: 61000, Source: "tcp_missed_runs", Dropped: 2}}},
		&store.Batch{Sample: store.Sample{TS: 91000}, Stats: []store.StatRow{{TS: 91000, Source: "ebpf_fork", Dropped: 9}}})
	if n := LossNote(db, 1000, 31000); n != "" {
		t.Errorf("no loss after 1000: %q", n)
	}
	// Lost before 61000, counted at that sample: in a window ending at 45000.
	want := "events lost in this window (ebpf_exec 3, tcp_missed_runs 2): short-lived processes or connections may be missing"
	if n := LossNote(db, 31000, 45000); n != want {
		t.Errorf("31000..45000: %q", n)
	}
	if n := LossNote(db, 61000, 90000); !strings.Contains(n, "ebpf_fork 9") || strings.Contains(n, "ebpf_exec") {
		t.Errorf("61000..90000: %q", n)
	}
}
