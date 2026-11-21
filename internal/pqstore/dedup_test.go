package pqstore

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func readConns(t *testing.T, p string) []tcpConnRow {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := newReader[tcpConnRow](f)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	out := make([]tcpConnRow, r.NumRows())
	n, _ := r.Read(out)
	return out[:n]
}

// TestMergeConns: compaction keeps, per connection, only the rows with the
// hour's newest last_seen, whatever the order of the parts.
func TestMergeConns(t *testing.T) {
	dir := t.TempDir()
	c := func(id, ls, lingerUntil int64) tcpConnRow {
		return tcpConnRow{ID: id, PID: 7, OpenTS: 1000, CloseTS: 2000, LingerState: 6, LingerUntil: lingerUntil,
			LAddr: "10.0.0.1", LPort: 22, RAddr: "10.0.0.2", RPort: 40000, Direction: "in", LastSeen: ls}
	}
	parts := [][]tcpConnRow{
		// A later flush's part sorted first (an earlier hour file).
		{c(1, 9000, 61000), c(5, 9000, 61000)},
		{c(1, 3000, 62000), c(2, 3000, 62000), c(3, 3000, 62000), c(4, 0, 0), c(6, 3000, 62000)},
		{c(2, 6000, 55000), c(3, 6000, 62000), c(4, 5000, 62000), c(6, 3000, 61500)},
		{c(2, 8000, 54000)},
	}
	var paths []string
	for i, rows := range parts {
		p := filepath.Join(dir, string(rune('a'+i))+".parquet")
		if err := writeFile(p, rows); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	out := filepath.Join(dir, "out.parquet")
	if err := mergeConns(paths, out); err != nil {
		t.Fatal(err)
	}
	got := map[int64][][2]int64{}
	for _, r := range readConns(t, out) {
		got[r.ID] = append(got[r.ID], [2]int64{r.LastSeen, r.LingerUntil})
	}
	want := map[int64][][2]int64{
		1: {{9000, 61000}},                // the newest even in the first part
		2: {{8000, 54000}},                // three versions
		3: {{6000, 62000}},                //
		4: {{5000, 62000}},                // a NULL last_seen is the oldest
		5: {{9000, 61000}},                // one version: kept
		6: {{3000, 62000}, {3000, 61500}}, // tied: both kept
	}
	for id, w := range want {
		if !slices.Equal(got[id], w) {
			t.Errorf("id %d: got %v, want %v", id, got[id], w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("ids %v", got)
	}

	// Without versions the file is the plain merge's.
	if err := mergeConns(paths[:1], out); err != nil {
		t.Fatal(err)
	}
	if n := len(readConns(t, out)); n != 2 {
		t.Errorf("one part: %d rows, want 2", n)
	}
}

// TestMergeConnsRandom: the bitmaps against a plain map, with ids dense,
// across blocks and far apart, ties and NULLs.
func TestMergeConnsRandom(t *testing.T) {
	dir := t.TempDir()
	rng := rand.New(rand.NewPCG(1, 2))
	base := int64(1795036714) * 1e9
	newest := map[int64]int64{}
	var paths []string
	var all []tcpConnRow
	for p := range 6 {
		seen := map[int64]bool{} // one row per id and part, as a flush writes
		var rows []tcpConnRow
		for range 3000 {
			id := base + rng.Int64N(5000)
			if rng.IntN(20) == 0 {
				id = base + rng.Int64N(1e9) // a long-lived connection's id
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			ls := 1000 + rng.Int64N(50)
			if rng.IntN(30) == 0 {
				ls = 0
			}
			r := tcpConnRow{ID: id, OpenTS: 10, CloseTS: 20, LastSeen: ls, LingerUntil: int64(p)}
			rows = append(rows, r)
			all = append(all, r)
			if o, ok := newest[id]; !ok || ls > o {
				newest[id] = ls
			}
		}
		path := filepath.Join(dir, fmt.Sprintf("%02d.parquet", p))
		if err := writeFile(path, rows); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	out := filepath.Join(dir, "out.parquet")
	if err := mergeConns(paths, out); err != nil {
		t.Fatal(err)
	}
	key := func(r tcpConnRow) string { return fmt.Sprint(r.ID, r.LastSeen, r.LingerUntil) }
	var want, got []string
	for _, r := range all {
		if r.LastSeen >= newest[r.ID] {
			want = append(want, key(r))
		}
	}
	for _, r := range readConns(t, out) {
		got = append(got, key(r))
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("kept %d rows, want %d", len(got), len(want))
	}
	if len(want) == len(all) {
		t.Error("no row dropped: the test has no versions")
	}
}
