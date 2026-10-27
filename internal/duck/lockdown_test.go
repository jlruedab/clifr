package duck_test

import (
	"os"
	"path/filepath"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// The database reads the recording and nothing else: no other file, no
// writes outside it, no extensions, and the settings cannot be undone.
// (DuckDB's allowed_directories allows writing there too: a bug could add
// files to the recording, not touch anything else.)
func TestLockDown(t *testing.T) {
	db := testrec.Open(t, nil, &store.Batch{Sample: store.Sample{TS: 1000}})
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM samples`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("reading the recording: %d, %v", n, err)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SELECT * FROM read_text('` + outside + `')`,
		`SELECT * FROM read_csv('/etc/passwd')`,
		`COPY (SELECT 1) TO '` + filepath.Join(filepath.Dir(outside), "out.csv") + `'`,
		`INSTALL httpfs`,
		`LOAD httpfs`,
		`SET enable_external_access = true`,
		`SET allowed_directories = ['/']`,
		`RESET lock_configuration`,
	} {
		if _, err := db.DB.Exec(q); err == nil {
			t.Errorf("%s: allowed", q)
		}
	}
}
