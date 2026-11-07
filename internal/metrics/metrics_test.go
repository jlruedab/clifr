package metrics

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"clifr/internal/store"
)

func testSnapshot() *Snapshot {
	return &Snapshot{
		Version: "0.1.0-test",
		BootMS:  1_790_000_000_500,
		SysTS:   1_790_000_100_000,
		Sys: store.SysSample{Load1: 123, Load5: 45, Load15: 6, MemTotal: 1000, MemAvailable: 600,
			Ctxt: 77, Forks: 5, Intr: 9, ProcsRunning: 2, ProcsBlocked: 1, PgMajFault: 3},
		CPUs: []store.CPUSample{
			{CPU: -1, T: [10]int64{999}}, // the total: left out
			{CPU: 1, T: [10]int64{250, 0, 50, 1000, 0, 0, 0, 0, 20, 0}},
			{CPU: 0, T: [10]int64{150, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
		},
		Sample:  store.Sample{TS: 1_790_000_099_000, CPUUS: 2_500_000, RSSKB: 2048, DBBytes: 4096, NProc: 300, FDIntervalS: 120},
		Samples: 7,
		Stats: map[string][2]int64{"ebpf_exec": {10, 0}, "tcp_state": {500, 3},
			"bpf_runs:handle_exec": {40, 0}, "bpf_ns:handle_exec": {2_000_000_000, 0}},
		Guard: map[string]int64{"budget_exceeded": 2},
	}
}

// parse checks the text format the way a scraper reads it (every sample
// after its family's HELP and TYPE, each family once, numeric values) and
// returns the samples by their full name with labels.
func parse(t *testing.T, text string) map[string]float64 {
	t.Helper()
	got := map[string]float64{}
	typed := map[string]bool{}
	var family string
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "# HELP "):
			name := strings.Fields(line)[2]
			if typed[name] {
				t.Errorf("family %s twice", name)
			}
			family = name
		case strings.HasPrefix(line, "# TYPE "):
			f := strings.Fields(line)
			if f[2] != family || len(f) != 4 {
				t.Errorf("TYPE line %q not after its HELP", line)
			}
			switch f[3] {
			case "counter", "gauge", "untyped":
			default:
				t.Errorf("type %q", f[3])
			}
			typed[f[2]] = true
		default:
			i := strings.LastIndexByte(line, ' ')
			key, val := line[:i], line[i+1:]
			name := key
			if j := strings.IndexByte(key, '{'); j >= 0 {
				name = key[:j]
			}
			if name != family || !typed[name] {
				t.Errorf("sample %q outside its family %q", line, family)
			}
			v, err := strconv.ParseFloat(val, 64)
			if err != nil {
				t.Errorf("value in %q: %v", line, err)
			}
			got[key] = v
		}
	}
	return got
}

func TestWrite(t *testing.T) {
	var b strings.Builder
	if err := Write(&b, testSnapshot()); err != nil {
		t.Fatal(err)
	}
	got := parse(t, b.String())
	for key, want := range map[string]float64{
		`node_cpu_seconds_total{cpu="0",mode="user"}`:       1.5, // ticks / 100
		`node_cpu_seconds_total{cpu="1",mode="idle"}`:       10,
		`node_cpu_seconds_total{cpu="0",mode="steal"}`:      0.07,
		`node_cpu_guest_seconds_total{cpu="1",mode="user"}`: 0.2,
		`node_cpu_guest_seconds_total{cpu="0",mode="nice"}`: 0.09,
		"node_load1":                                              1.23, // hundredths
		"node_load15":                                             0.06,
		"node_memory_MemTotal_bytes":                              1000 * 1024, // kB
		"node_memory_MemAvailable_bytes":                          600 * 1024,
		"node_boot_time_seconds":                                  1_790_000_000,
		"node_context_switches_total":                             77,
		"node_procs_blocked":                                      1,
		"node_vmstat_pgmajfault":                                  3,
		`clifr_build_info{version="0.1.0-test"}`:                  1,
		"clifr_recorder_cpu_seconds_total":                        2.5,
		"clifr_recorder_resident_memory_bytes":                    2048 * 1024,
		"clifr_samples_total":                                     7,
		`clifr_events_total{source="tcp_state"}`:                  500,
		`clifr_events_dropped_total{source="tcp_state"}`:          3,
		`clifr_ebpf_program_runs_total{program="handle_exec"}`:    40,
		`clifr_ebpf_program_seconds_total{program="handle_exec"}`: 2,
		`clifr_guard_events_total{kind="budget_exceeded"}`:        2,
	} {
		if v, ok := got[key]; !ok || v != want {
			t.Errorf("%s = %v (present %v), want %v", key, v, ok, want)
		}
	}
	for key := range got {
		if strings.Contains(key, `cpu="-1"`) || strings.Contains(key, "bpf_runs:") || strings.Contains(key, "bpf_ns:") {
			t.Errorf("should not be served: %s", key)
		}
	}
	if !strings.Contains(b.String(), `node_cpu_seconds_total{cpu="0",mode="user"} 1.5`+"\n"+
		`node_cpu_seconds_total{cpu="0",mode="nice"} 0.01`) {
		t.Error("CPUs not in order, or modes not in Node Exporter's order")
	}

	// Before the first system sample: only clifr_*.
	s := testSnapshot()
	s.SysTS = 0
	b.Reset()
	Write(&b, s)
	if got := parse(t, b.String()); len(got) == 0 || strings.Contains(b.String(), "node_") {
		t.Errorf("without a system sample: %q", b.String())
	}
}

func TestEscape(t *testing.T) {
	if got := escape("a\"b\\c\nd"); got != `a\"b\\c\nd` {
		t.Errorf("escape: %q", got)
	}
}

func TestListenLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":9100", "10.1.2.3:9100", "example.com:9100", "[::]:0", "9100"} {
		if ln, err := Listen(addr); err == nil {
			ln.Close()
			t.Errorf("%s: accepted", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:0", "localhost:0"} {
		ln, err := Listen(addr)
		if err != nil {
			t.Errorf("%s: %v", addr, err)
			continue
		}
		if !strings.HasPrefix(ln.Addr().String(), "127.0.0.1:") {
			t.Errorf("%s: listening on %s", addr, ln.Addr())
		}
		ln.Close()
	}
}

func TestHandler(t *testing.T) {
	var snap *Snapshot
	srv := httptest.NewServer(Handler(func() *Snapshot { return snap }))
	defer srv.Close()
	get := func(method, path string) (*http.Response, string) {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b strings.Builder
		bufio.NewReader(resp.Body).WriteTo(&b)
		return resp, b.String()
	}
	if resp, _ := get("GET", "/metrics"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("before a sample: %d", resp.StatusCode)
	}
	snap = testSnapshot()
	resp, body := get("GET", "/metrics")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" ||
		!strings.Contains(body, "node_load1 1.23\n") {
		t.Errorf("GET /metrics: %d %q %.200q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	if resp, body := get("HEAD", "/metrics"); resp.StatusCode != 200 || body != "" {
		t.Errorf("HEAD: %d %q", resp.StatusCode, body)
	}
	if resp, _ := get("POST", "/metrics"); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", resp.StatusCode)
	}
	if resp, _ := get("GET", "/other"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("other path: %d", resp.StatusCode)
	}
}
