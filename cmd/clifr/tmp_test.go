package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// TestSweepStale removes run directories of processes that are gone and
// keeps a live process's and anything not named like one.
func TestSweepStale(t *testing.T) {
	base := t.TempDir()
	dead := exec.Command("true")
	if err := dead.Run(); err != nil {
		t.Skip(err)
	}
	gone := filepath.Join(base, runPrefix+strconv.Itoa(dead.Process.Pid)+"-123")
	live := filepath.Join(base, runPrefix+strconv.Itoa(os.Getpid())+"-456")
	other := filepath.Join(base, "clifr-schema-789")
	odd := filepath.Join(base, runPrefix+"x-1")
	for _, d := range []string{gone, live, other, odd} {
		if err := os.MkdirAll(filepath.Join(d, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sweepStale(base)
	if _, err := os.Stat(gone); !os.IsNotExist(err) {
		t.Errorf("a dead process's run directory was kept: %v", err)
	}
	for _, d := range []string{live, other, odd} {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("%s removed: %v", filepath.Base(d), err)
		}
	}
}
