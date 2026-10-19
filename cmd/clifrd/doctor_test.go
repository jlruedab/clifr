package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDataDirState(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "priv")
	os.Mkdir(priv, 0o750)
	if d, ok := dataDirState(priv); !ok {
		t.Errorf("0750: %s", d)
	}
	open := filepath.Join(dir, "open")
	os.Mkdir(open, 0o755)
	if d, ok := dataDirState(open); ok || !strings.Contains(d, "readable by everyone") {
		t.Errorf("0755: %s %v", d, ok)
	}
	if d, ok := dataDirState(filepath.Join(dir, "new")); !ok || !strings.Contains(d, "will be created") {
		t.Errorf("missing: %s %v", d, ok)
	}
}
