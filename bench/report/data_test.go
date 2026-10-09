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

// The 26.04 batch as first reported: blank recorder metrics and an atop log
// growing 10 B/h. Validation must name each problem.
func TestValidate(t *testing.T) {
	good := map[string]float64{"tps": 30000, "lat_avg_ms": 0.2, "lat_p99_ms": 1, "sys_busy": 57, "sys_cpu_some": 35, "sys_io_some": 0.1,
		"rec_cpu": 11, "rec_mem_avg": 4e8, "rec_anon_avg": 1.5e8, "write_per_h": 1.3e10, "store_per_h": 8e8}
	run := func(id, config string, m map[string]float64) *Run {
		c := map[string]float64{}
		for k, v := range m {
			c[k] = v
		}
		return &Run{ID: id, Config: config, From: 0, To: 900_000, M: c}
	}
	ok := &Report{Matrix: []*Matrix{{Dir: "m", Env: map[string]string{"cpus": "4"},
		Runs: []*Run{run("01-A", "A", good), run("02-B", "B", good)}}}}
	if p := ok.validate(); len(p) != 0 {
		t.Fatalf("complete data reported invalid: %v", p)
	}
	blank := run("02-B", "B", good)
	for _, k := range []string{"rec_cpu", "rec_mem_avg", "rec_anon_avg", "write_per_h", "sys_busy"} {
		blank.M[k] = nan
	}
	atop := run("03-R1", "R1", good)
	atop.M["store_per_h"] = 10
	bad := &Report{Matrix: []*Matrix{{Dir: "m", Env: map[string]string{"cpus": "4"}, Runs: []*Run{blank, atop}}}}
	p := strings.Join(bad.validate(), "\n")
	for _, want := range []string{"02-B: recorder CPU (% of one core) is missing", "02-B: machine CPU busy (%) is missing",
		"02-B: disk written per hour is missing", "03-R1: DB or log file growth per hour = 10, outside"} {
		if !strings.Contains(p, want) {
			t.Errorf("missing problem %q in:\n%s", want, p)
		}
	}
}
