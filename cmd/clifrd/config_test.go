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
		"keyframe-interval", "flush-interval", "events", "tcp", "fd-mode", "proc-io", "redact", "cpu-budget", "gc-heap-target", "config", "C"} {
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
		{"redact: x\n", "cannot unmarshal"},
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

// TestEventBudgetConfig: the event_budget section sets the four flags.
func TestEventBudgetConfig(t *testing.T) {
	fs := testFlags()
	for _, n := range []string{"event-budget-processes", "event-budget-processes-max", "event-budget-cmdline", "event-budget-connections"} {
		fs.String(n, "default", "")
	}
	p := filepath.Join(t.TempDir(), "clifrd.yml")
	os.WriteFile(p, []byte("event_budget:\n  processes: 8000\n  processes_max: 0\n  cmdline_bytes: 4M\n  connections: 20000\n"), 0o644)
	if err := applyConfig(fs, p, true); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"event-budget-processes": "8000", "event-budget-processes-max": "0",
		"event-budget-cmdline": "4M", "event-budget-connections": "20000"} {
		if got := fs.Lookup(name).Value.String(); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if got := yamlName("event-budget-cmdline"); got != "event_budget.cmdline_bytes" {
		t.Errorf("yamlName = %q", got)
	}
}

// TestVerifyEveryConfig: verify_every sets --verify-every (a packaged clifrd
// gets no flags: the unit's ExecStart has none), and a flag still wins.
func TestVerifyEveryConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "clifrd.yml")
	os.WriteFile(p, []byte("verify_every: 15m\n"), 0o644)
	for _, c := range []struct {
		args []string
		want string
	}{{nil, "15m"}, {[]string{"--verify-every", "5m"}, "5m"}} {
		fs := testFlags()
		fs.String("verify-every", "0s", "")
		fs.Parse(c.args)
		if err := applyConfig(fs, p, true); err != nil {
			t.Fatal(err)
		}
		if got := fs.Lookup("verify-every").Value.String(); got != c.want {
			t.Errorf("%v: verify-every = %q, want %q", c.args, got, c.want)
		}
	}
	if got := yamlName("verify-every"); got != "verify_every" {
		t.Errorf("yamlName = %q", got)
	}
}
