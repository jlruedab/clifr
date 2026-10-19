package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	for _, n := range []string{"data-dir", "D", "retention", "max-size", "log-level", "interval", "sys-interval", "fd-interval",
		"keyframe-interval", "flush-interval", "events", "tcp", "fd-mode", "proc-io", "cpu-budget", "gc-heap-target", "config", "C"} {
		fs.String(n, "default", "")
	}
	return fs
}

func TestApplyConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "clifrd.yml")
		os.WriteFile(p, []byte(s), 0o644)
		return p
	}
	fs := testFlags()
	fs.Parse([]string{"--interval", "10s"})
	p := write("data_dir: /srv/clifr\nmax_size: 5G\nintervals:\n  process: 30s\n  files: 120s\ncollectors:\n  tcp: sample\ncpu_budget: 3%\n")
	if err := applyConfig(fs, p, true); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"data-dir": "/srv/clifr", "max-size": "5G", "interval": "10s",
		"fd-interval": "120s", "tcp": "sample", "cpu-budget": "3%", "retention": "default"} {
		if got := fs.Lookup(name).Value.String(); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if err := applyConfig(testFlags(), filepath.Join(dir, "none.yml"), false); err != nil {
		t.Errorf("missing default file: %v", err)
	}
	if err := applyConfig(testFlags(), write(""), true); err != nil {
		t.Errorf("empty file: %v", err)
	}
	for _, c := range []struct{ yml, want string }{
		{"", "no such file"},
		{"intervals:\n  proces: 30s\n", "field proces not found"},
		{"memory_limit: 256M\n", "use gc_heap_target"},
		{"redact:\n  - x\n", "not available yet"},
		{"intervals:\n  process: [1, 2]\n", "want a single value"},
	} {
		path := filepath.Join(dir, "none.yml")
		if c.yml != "" {
			path = write(c.yml)
		}
		err := applyConfig(testFlags(), path, true)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.yml, err, c.want)
		}
	}
}
