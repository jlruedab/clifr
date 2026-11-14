package pqstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clifr/internal/store"
)

// TestIntegrity: every file the store writes is logged; a changed byte in a
// logged file and a damaged unlogged file are found; a file rewritten after
// its line (an open file at the next flush) is not reported.
func TestIntegrity(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	s.SetMeta("boot_id", "A")
	for i := range 3 {
		b := &store.Batch{Sample: store.Sample{TS: int64(1000 + i)},
			ProcInserts: []store.ProcRow{{ID: int64(10 + i), PID: 10 + i, StartTime: 1, Comm: "x", FirstSeen: 1000}}}
		for j := range 2000 {
			b.Guard = append(b.Guard, store.GuardEvent{TS: int64(j), Kind: "skip", Detail: strings.Repeat("d", j%50)})
		}
		s.Write(b)
		if err := s.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	r := CheckIntegrity(dir)
	if r.Files == 0 || r.Logged != r.Files || r.Unlogged != 0 || len(r.Damaged) != 0 {
		t.Fatalf("clean store: %+v", r)
	}
	// A changed byte in a logged file.
	guards, _ := filepath.Glob(filepath.Join(dir, Dir("guard_events"), "*", "*.parquet"))
	b, _ := os.ReadFile(guards[0])
	b[len(b)/3] ^= 1
	os.WriteFile(guards[0], b, 0o640)
	// An unlogged file (an older clifrd), damaged inside a page.
	unlogged := filepath.Join(filepath.Dir(guards[0]), "23-59.parquet")
	b2, _ := os.ReadFile(guards[1])
	b2[len(b2)/3] ^= 1
	os.WriteFile(unlogged, b2, 0o640)
	// The open file rewritten by the next flush: logged again, not damaged.
	s.Write(&store.Batch{Sample: store.Sample{TS: 2000}, ProcInserts: []store.ProcRow{{ID: 99, PID: 99, StartTime: 1, Comm: "y", FirstSeen: 2000}}})
	s.Flush()
	r = CheckIntegrity(dir)
	var bad []string
	for _, d := range r.Damaged {
		bad = append(bad, filepath.Base(d.Path)+": "+d.Error)
	}
	if len(r.Damaged) != 2 || r.Unlogged != 1 ||
		!strings.Contains(bad[0]+bad[1], filepath.Base(guards[0])+": SHA-256") || !strings.Contains(bad[0]+bad[1], "23-59.parquet: ") {
		t.Errorf("damaged %q, report %+v", bad, r)
	}
	s.Close()
}
