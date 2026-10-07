package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	tpsRe    = regexp.MustCompile(`tps = ([0-9.]+) \(without initial connection time\)`)
	txRe     = regexp.MustCompile(`number of transactions actually processed: (\d+)`)
	failedRe = regexp.MustCompile(`number of failed transactions: (\d+)`)
	avgRe    = regexp.MustCompile(`latency average = ([0-9.]+) ms`)
)

// pglat prints one CSV line (with header) summarising a pgbench run: TPS and
// average latency from pgbench's own summary (exact, over all transactions),
// latency percentiles from the sampled per-transaction logs (column 3 is the
// latency in microseconds).
func pglat(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: pglat PGBENCH_OUT LOG...")
	}
	out, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	find := func(re *regexp.Regexp) string {
		if m := re.FindSubmatch(out); m != nil {
			return string(m[1])
		}
		return ""
	}
	tps := find(tpsRe)
	if tps == "" {
		return fmt.Errorf("no tps line in %s (did pgbench fail?)", args[0])
	}
	var lat []float64
	for _, path := range args[1:] {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 3 {
				continue
			}
			if us, err := strconv.ParseFloat(fs[2], 64); err == nil {
				lat = append(lat, us/1000)
			}
		}
		f.Close()
	}
	sort.Float64s(lat)
	q := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return lat[int(p*float64(len(lat)-1)+0.5)]
	}
	fmt.Println("tps,lat_avg_ms,lat_p50_ms,lat_p95_ms,lat_p99_ms,transactions,failed,latency_samples")
	fmt.Printf("%s,%s,%.3f,%.3f,%.3f,%s,%s,%d\n", tps, find(avgRe), q(0.5), q(0.95), q(0.99), find(txRe), find(failedRe), len(lat))
	return nil
}
