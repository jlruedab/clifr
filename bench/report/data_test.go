package main

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScriptMS(t *testing.T) {
	cases := map[string]int64{
		"1791428465675":       1791428465675, // GNU date +%s%3N
		"1791525783823413795": 1791525783823, // uutils: unpadded nanoseconds
		"179144513830370295":  1791445138030, // ns part 030370295 lost its leading zero
		"":                    0,
	}
	for in, want := range cases {
		if got := scriptMS(in); got != want {
			t.Errorf("scriptMS(%q) = %d, want %d", in, got, want)
		}
	}
}

// A run whose times miss the sampler rows must fail, not render as "—".
func TestAnalyseWindowMismatch(t *testing.T) {
	dir := t.TempDir()
	writeGz(t, filepath.Join(dir, "cgroup.csv.gz"), "ts_ms,group,cpu_usage_us\n1000,rec,0\n6000,rec,100\n")
	writeGz(t, filepath.Join(dir, "system.csv.gz"), "ts_ms,group\n1000,\n6000,\n")
	run := &Run{Dir: dir, From: 1000, To: 6000, M: map[string]float64{}}
	if err := run.analyse(4); err != nil {
		t.Fatalf("matching window: %v", err)
	}
	run = &Run{Dir: dir, From: 1000e6, To: 6000e6, M: map[string]float64{}}
	if err := run.analyse(4); err == nil || !strings.Contains(err.Error(), "no sampler rows") {
		t.Fatalf("mismatched window: err = %v", err)
	}
}

func writeGz(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := gzip.NewWriter(f)
	w.Write([]byte(content))
	w.Close()
	f.Close()
}
