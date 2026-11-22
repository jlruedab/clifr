package query

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The --json forms of sar, htop, iotop and atop come from the code that
// prints the text: each check below compares them with the printed lines.

var jsonStamp = regexp.MustCompile(`^(\d\d:\d\d:\d\d|Average:|Summary:)\s`)

// checkSarRows: one row per printed value line, in order, with the line's
// numbers as its values.
func checkSarRows(t *testing.T, name, text string, rows []SarRow) {
	t.Helper()
	var lines [][]float64
	for _, l := range strings.Split(text, "\n") {
		if !jsonStamp.MatchString(l) || strings.Contains(l, "LINUX RESTART") {
			continue
		}
		var nums []float64
		for _, f := range strings.Fields(l[11:]) {
			if v, err := strconv.ParseFloat(f, 64); err == nil {
				nums = append(nums, v)
			}
		}
		if len(nums) > 0 && strings.ContainsAny(l[11:], ".0123456789") && !strings.Contains(l, "%user") {
			lines = append(lines, nums)
		}
	}
	var data []SarRow
	for _, r := range rows {
		if r.Kind != "restart" {
			data = append(data, r)
		}
	}
	if len(data) != len(lines) {
		t.Fatalf("%s: %d rows, %d value lines", name, len(data), len(lines))
	}
	for i, r := range data {
		if r.Kind == "record" && r.TS == 0 {
			t.Errorf("%s: row %d has no time", name, i)
		}
		var got []float64
		for _, v := range r.Values {
			got = append(got, v)
		}
		want := lines[i]
		if r.Item != "" { // a numeric item (a CPU, an interrupt) is not a value
			if _, err := strconv.ParseFloat(r.Item, 64); err == nil && len(want) == len(got)+1 {
				want = want[1:]
			}
		}
		sort.Float64s(got)
		w := append([]float64(nil), want...)
		sort.Float64s(w)
		if len(got) != len(w) {
			t.Errorf("%s: row %d (%s %s): %v, line %v", name, i, r.Report, r.Item, got, want)
			continue
		}
		for j := range got {
			if got[j] != w[j] {
				t.Errorf("%s: row %d (%s %s): %v, line %v", name, i, r.Report, r.Item, got, want)
				break
			}
		}
	}
}

// checkPIDs: the pids of the JSON's processes, in order, as the screen's
// process lines have them.
func checkPIDs(t *testing.T, name, text string, line *regexp.Regexp, pids []int) {
	t.Helper()
	var want []int
	for _, l := range strings.Split(text, "\n") {
		if m := line.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[1])
			want = append(want, n)
		}
	}
	if len(want) == 0 || len(pids) != len(want) {
		t.Fatalf("%s: JSON pids %v, screen %v", name, pids, want)
	}
	for i := range want {
		if pids[i] != want[i] {
			t.Fatalf("%s: JSON pids %v, screen %v", name, pids, want)
		}
	}
}

var (
	htopPIDLine  = regexp.MustCompile(`^\s*(\d+) \S+\s+(?:-?\d+|RT)\s+-?\d+ `)
	iotopPIDLine = regexp.MustCompile(`^(?:b['"])?\s*(\d+)\s+(?:be/|rt/|idle|\?)`)
)
