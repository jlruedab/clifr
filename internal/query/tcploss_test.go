package query

import (
	"strings"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// TestTCPLoss: lost TCP events make the TCP view from the sample before
// them to the keyframe after them uncertain; a keyframe at the same sample
// repairs them, missed program runs and budget shedding do not count.
func TestTCPLoss(t *testing.T) {
	b := func(ts int64) *store.Batch { return &store.Batch{Sample: store.Sample{TS: ts}} }
	b2, b3, b4, b5, b6 := b(2000), b(3000), b(4000), b(5000), b(6000)
	b2.Reconcile = []store.ReconcileRow{{TS: 2000, Kind: "tcp"}}
	b3.Stats = []store.StatRow{{TS: 3000, Source: "tcp_state", Events: 100, Dropped: 40}, {TS: 3000, Source: "tcp_app_close", Dropped: 10},
		{TS: 3000, Source: "tcp_conns_shed", Events: 99}}
	b4.Reconcile = []store.ReconcileRow{{TS: 4000, Kind: "tcp"}} // the early keyframe
	b5.Stats = []store.StatRow{{TS: 5000, Source: "tcp_missed_runs", Dropped: 3}}
	b6.Guard = []store.GuardEvent{{TS: 6000, Kind: "events_lost", Detail: "TCP event queue full (500000 events): 7 TCP events dropped"}}
	db := testrec.Open(t, nil, b(1000), b2, b3, b4, b5, b6)
	for _, c := range []struct {
		from, to            int64
		n, lost0, lost1, kf int64
	}{
		{1500, 1500, 0, 0, 0, 0},
		{2500, 2500, 50, 2000, 3000, 4000}, // lost between the samples at 2000 and 3000
		{3500, 3500, 50, 2000, 3000, 4000},
		{4000, 4000, 0, 0, 0, 0}, // the keyframe repaired them
		{4500, 4500, 0, 0, 0, 0}, // missed runs: not lost
		{5500, 5500, 7, 5000, 6000, 0},
		{1500, 3500, 50, 2000, 3000, 4000},
	} {
		n, a, z, kf := TCPLoss(db, c.from, c.to)
		if n != c.n || a != c.lost0 || z != c.lost1 || kf != c.kf {
			t.Errorf("%d..%d: %d lost %d..%d, keyframe %d; want %d lost %d..%d, keyframe %d", c.from, c.to, n, a, z, kf, c.n, c.lost0, c.lost1, c.kf)
		}
	}
	if n := TCPLossNote(db, 5500, 5500); !strings.Contains(n, "7 TCP events lost") || !strings.Contains(n, "end of the recording") {
		t.Errorf("note: %q", n)
	}
	if n := TCPLossNote(db, 1500, 1500); n != "" {
		t.Errorf("note without losses: %q", n)
	}
}
