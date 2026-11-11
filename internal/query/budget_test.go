package query

import (
	"strings"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// TestBudgetNote: lists covering an events_shed guard event of their kind
// say they are incomplete; others do not.
func TestBudgetNote(t *testing.T) {
	base := int64(1_790_000_000_000)
	db := testrec.Open(t, nil, &store.Batch{Sample: store.Sample{TS: base},
		Guard: []store.GuardEvent{{TS: base + 30_000, Kind: "events_shed",
			Detail: "processes: 500 only counted of 900 process events (fork, exec) since 10:00:00 (budget: 4000/s in full)"}}})
	if n := BudgetNote(db, base, base+10_000, "processes"); !strings.HasPrefix(n, "incomplete: process events") {
		t.Errorf("covering range: %q", n)
	}
	if n := BudgetNote(db, base, base+10_000, "tcp"); n != "" {
		t.Errorf("tcp: %q, want none", n)
	}
	if n := BudgetNote(db, base+100_000, base+200_000, "processes"); n != "" {
		t.Errorf("later range: %q, want none", n)
	}
	if n := BudgetNote(db, 0, 0, "processes"); n == "" {
		t.Error("whole recording: no note")
	}
}
