// Package testrec makes small recordings for tests: batches written to a
// Parquet data directory (internal/pqstore) and read back through DuckDB
// (internal/duck), as clifr reads a real recording.
package testrec

import (
	"testing"
	"time"

	"clifr/internal/duck"
	"clifr/internal/pqstore"
	"clifr/internal/store"
)

// Open writes the meta pairs (key, value, key, value, ...) and the batches to
// a new data directory and opens it. The database is closed when the test ends.
func Open(t testing.TB, meta []string, batches ...*store.Batch) *store.DB {
	t.Helper()
	dir := t.TempDir()
	s, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(meta); i += 2 {
		s.SetMeta(meta[i], meta[i+1])
	}
	for _, b := range batches {
		if err := s.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := duck.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
