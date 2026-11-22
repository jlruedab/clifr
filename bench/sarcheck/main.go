// sarcheck compares a real sar's output (sar -f FILE ... or live) with
// clifr's sar for the same reports and period.
//
//	sarcheck REAL.txt CLIFR.txt
//
// Both are split into reports (verify.ParseSar: by column titles, rows by
// kind and item, in order). The first line's kernel and CPU count, the
// LINUX RESTART lines, the reports, their row counts and items must be the
// same; values are exact, near (verify.SarNear: within 5%, or 0.5 for
// decimals) or differ. The times are not compared: sa1's records and
// clifr's samples are seconds apart.
package main

import (
	"fmt"
	"os"
	"strings"

	"clifr/internal/verify"
)

func read(path string) verify.SarOutput {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	return verify.ParseSar(string(b))
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: sarcheck REAL.txt CLIFR.txt")
		os.Exit(2)
	}
	real, rec := read(os.Args[1]), read(os.Args[2])
	var bad, examples []string
	rf, cf := strings.Fields(real.First), strings.Fields(rec.First)
	if len(rf) < 4 || len(cf) < 4 || rf[0] != cf[0] || rf[1] != cf[1] || rf[len(rf)-2] != cf[len(cf)-2] {
		bad = append(bad, fmt.Sprintf("first line:\n  real  %q\n  clifr %q", real.First, rec.First))
	}
	if real.Restarts != rec.Restarts {
		bad = append(bad, fmt.Sprintf("LINUX RESTART: real %d, clifr %d", real.Restarts, rec.Restarts))
	}
	recBy := map[string]*verify.SarReport{}
	for _, r := range rec.Reports {
		recBy[r.Titles] = r
	}
	seen := map[string]bool{}
	var tot [4]int
	for _, rr := range real.Reports {
		key := rr.Titles
		if len(key) > 50 {
			key = key[:50]
		}
		cr := recBy[rr.Titles]
		if cr == nil {
			bad = append(bad, "report missing in clifr: "+rr.Titles)
			continue
		}
		seen[rr.Titles] = true
		rm, keys := verify.SarRows(rr)
		cm, ckeys := verify.SarRows(cr)
		var t [4]int // rows, exact, near, differ
		for _, k := range keys {
			if len(rm[k]) != len(cm[k]) {
				bad = append(bad, fmt.Sprintf("%s: %s rows %d, clifr %d", key, k, len(rm[k]), len(cm[k])))
			}
			for n := 0; n < min(len(rm[k]), len(cm[k])); n++ {
				t[0]++
				a, x := rm[k][n].Vals, cm[k][n].Vals
				if len(a) != len(x) {
					bad = append(bad, fmt.Sprintf("%s: %s: %d values, clifr %d", key, k, len(a), len(x)))
					continue
				}
				for v := range a {
					switch {
					case a[v] == x[v]:
						t[1]++
					case verify.SarNear(a[v], x[v]):
						t[2]++
					default:
						t[3]++
						if len(examples) < 30 {
							f := strings.Fields(rr.Titles)
							title := ""
							if j := len(f) - len(a) + v; j >= 0 && j < len(f) {
								title = f[j]
							}
							examples = append(examples, fmt.Sprintf("%s %s #%d %s: real %s clifr %s", key, k, n+1, title, a[v], x[v]))
						}
					}
				}
			}
		}
		for _, k := range ckeys {
			if _, ok := rm[k]; !ok {
				bad = append(bad, fmt.Sprintf("%s: clifr only: %s (%d rows)", key, k, len(cm[k])))
			}
		}
		fmt.Printf("  %-52s rows %4d  values: exact %5d near %5d differ %4d\n", key, t[0], t[1], t[2], t[3])
		for i := range tot {
			tot[i] += t[i]
		}
	}
	fmt.Printf("  %-52s rows %4d  values: exact %5d near %5d differ %4d\n", "TOTAL", tot[0], tot[1], tot[2], tot[3])
	for _, r := range rec.Reports {
		if !seen[r.Titles] {
			bad = append(bad, "report only in clifr: "+r.Titles)
		}
	}
	for _, b := range bad {
		fmt.Println("STRUCTURE " + b)
	}
	for _, e := range examples {
		fmt.Println("e.g. " + e)
	}
	if len(bad) > 0 {
		os.Exit(1)
	}
}
