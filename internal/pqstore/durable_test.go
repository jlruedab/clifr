package pqstore

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// TestCompactSyncsBeforeDeleting: compaction makes the merged hour file's
// rename durable (a sync of its directory) while every part still exists,
// so a power loss can never keep the deletes and lose the rename.
func TestCompactSyncsBeforeDeleting(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	day := filepath.Join(dir, Dir("guard_events"), "2026-10-09")
	parts := []string{filepath.Join(day, "10-00.parquet"), filepath.Join(day, "10-05.parquet")}
	for _, p := range parts {
		if err := writeFile(p, guardRows(3, 0)); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(day, "10.parquet")
	synced := false
	onDirSync = func(d string) {
		if d != day {
			return
		}
		if _, err := os.Stat(out); err != nil {
			return // a sync before the merged file exists
		}
		synced = true
		for _, p := range parts {
			if _, err := os.Stat(p); err != nil {
				t.Errorf("%s deleted before the merged file's rename was synced", filepath.Base(p))
			}
		}
	}
	defer func() { onDirSync = nil }()
	if err := s.compact(time.Date(2026, 10, 9, 11, 0, 0, 0, time.UTC), func() {}); err != nil {
		t.Fatal(err)
	}
	if !synced {
		t.Error("the merged file's directory was never synced")
	}
	if n := rowsIn(t, out); n != 6 {
		t.Errorf("hour 10 has %d rows, want 6", n)
	}
}

// TestMkdirDurable: every directory created gets its parent synced, and an
// existing directory costs no sync.
func TestMkdirDurable(t *testing.T) {
	root := t.TempDir()
	var synced []string
	onDirSync = func(d string) { synced = append(synced, d) }
	defer func() { onDirSync = nil }()
	deep := filepath.Join(root, "a", "b", "c")
	if err := mkdirDurable(deep, 0o750); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(deep); err != nil || !fi.IsDir() {
		t.Fatalf("not created: %v", err)
	}
	want := []string{filepath.Join(root, "a", "b"), filepath.Join(root, "a"), root}
	if !slices.Equal(synced, want) {
		t.Errorf("synced %v, want %v", synced, want)
	}
	synced = nil
	if err := mkdirDurable(deep, 0o750); err != nil || len(synced) != 0 {
		t.Errorf("existing directory: err %v, synced %v", err, synced)
	}
}

// TestRenameDurable syncs the target's directory, and the source's when it
// differs.
func TestRenameDurable(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	os.Mkdir(a, 0o750)
	os.Mkdir(b, 0o750)
	os.WriteFile(filepath.Join(a, "x.tmp"), []byte("x"), 0o640)
	var synced []string
	onDirSync = func(d string) { synced = append(synced, d) }
	defer func() { onDirSync = nil }()
	if err := RenameDurable(filepath.Join(a, "x.tmp"), filepath.Join(b, "x")); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(synced, []string{b, a}) {
		t.Errorf("synced %v, want [%s %s]", synced, b, a)
	}
	if _, err := os.Stat(filepath.Join(b, "x")); err != nil {
		t.Error(err)
	}
}
