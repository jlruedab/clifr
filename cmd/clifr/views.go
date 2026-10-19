package main

import (
	"fmt"
	"os"

	"clifr/internal/query"
)

// Range views of the commands that show a moment (ps, ss, netstat, lsof,
// df, mount): --samples prints the output at every sample in the range,
// --changes what appeared, disappeared or changed between consecutive
// samples, and diff (later) the same between two moments. A view takes the
// snapshot at a time, a key per row, what counts as changed, and the printer.
type view[R any] struct {
	name  string
	at    func(t int64) ([]R, func(*R) rowMeta, error)
	key   func(*R) string
	same  func(a, b *R) bool // false: the row changed
	print func([]R)
}

// rangeView runs v over c's range if --samples or --changes asks for it; ok
// is false when the summary applies instead.
func rangeView[R any](c *runCtx, v view[R]) (ok bool, err error) {
	if c.diffAt != nil {
		c.quiet = true
		return true, diffView(c, v, c.diffAt[0], c.diffAt[1])
	}
	if !c.w.IsRange() || !c.g.samples && !c.g.changes {
		return false, nil
	}
	times, err := query.SampleTimes(c.db, c.w.From, c.w.To, c.g.everyMS)
	if err != nil {
		return true, err
	}
	if len(times) == 0 {
		return true, fmt.Errorf("%s: no samples in %s .. %s", v.name, query.FormatMS(c.w.From), query.FormatMS(c.w.To))
	}
	if c.g.changes {
		return true, runChanges(c, v, times)
	}
	if c.g.number > 0 && len(times) > c.g.number {
		times = times[:c.g.number]
	}
	c.header("%s: %d samples, %s .. %s", v.name, len(times), query.FormatMS(times[0]), query.FormatMS(times[len(times)-1]))
	c.quiet = true
	for i, t := range times {
		rows, meta, err := v.at(t)
		if err != nil {
			return true, err
		}
		if c.g.json {
			if err := writeLines(rows, func(i int) rowMeta { m := meta(&rows[i]); m.TS = t; return m }); err != nil {
				return true, err
			}
			continue
		}
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("# %s at %s\n", v.name, query.FormatMS(t))
		v.print(rows)
	}
	return true, nil
}

// change is one row of a comparison: "+" appeared, "-" gone, "~" changed
// (the row as it is at the later time).
type change[R any] struct {
	kind string
	row  R
}

// compare lists what differs from a to b, in b's order (gone rows in a's).
func compare[R any](v view[R], a, b []R) []change[R] {
	old := make(map[string]*R, len(a))
	for i := range a {
		old[v.key(&a[i])] = &a[i]
	}
	seen := make(map[string]bool, len(b))
	var out []change[R]
	for i := range b {
		k := v.key(&b[i])
		seen[k] = true
		switch o, ok := old[k]; {
		case !ok:
			out = append(out, change[R]{"+", b[i]})
		case !v.same(o, &b[i]):
			out = append(out, change[R]{"~", b[i]})
		}
	}
	for i := range a {
		if !seen[v.key(&a[i])] {
			out = append(out, change[R]{"-", a[i]})
		}
	}
	return out
}

// printChanges prints one comparison: appeared, gone and changed rows as
// three tables in the command's own format.
func printChanges[R any](c *runCtx, v view[R], from, to int64, ch []change[R], meta func(*R) rowMeta) error {
	if c.g.json {
		return writeLines(func() []R {
			rows := make([]R, len(ch))
			for i := range ch {
				rows[i] = ch[i].row
			}
			return rows
		}(), func(i int) rowMeta {
			m := meta(&ch[i].row)
			m.TS, m.From, m.Change = to, from, ch[i].kind
			return m
		})
	}
	counts := map[string]int{}
	for _, x := range ch {
		counts[x.kind]++
	}
	fmt.Printf("# %s, %s -> %s: %d appeared, %d gone, %d changed\n", v.name, query.FormatMS(from), query.FormatMS(to),
		counts["+"], counts["-"], counts["~"])
	for _, kind := range []struct{ k, title string }{{"+", "appeared"}, {"-", "gone"}, {"~", "changed (as at " + query.FormatMS(to) + ")"}} {
		var rows []R
		for _, x := range ch {
			if x.kind == kind.k {
				rows = append(rows, x.row)
			}
		}
		if len(rows) > 0 {
			fmt.Printf("## %s\n", kind.title)
			v.print(rows)
		}
	}
	return nil
}

func runChanges[R any](c *runCtx, v view[R], times []int64) error {
	c.header("%s: changes between %d samples, %s .. %s (anything shorter than a sample interval is in \"events\")",
		v.name, len(times), query.FormatMS(times[0]), query.FormatMS(times[len(times)-1]))
	c.quiet = true
	prev, _, err := v.at(times[0])
	if err != nil {
		return err
	}
	n, printed := 0, false
	for i := 1; i < len(times); i++ {
		cur, meta, err := v.at(times[i])
		if err != nil {
			return err
		}
		if ch := compare(v, prev, cur); len(ch) > 0 {
			if c.g.number > 0 && n == c.g.number {
				break
			}
			if printed && !c.g.json {
				fmt.Println()
			}
			if err := printChanges(c, v, times[i-1], times[i], ch, meta); err != nil {
				return err
			}
			n, printed = n+1, true
		}
		prev = cur
	}
	if !printed && !c.g.json {
		fmt.Fprintln(os.Stderr, "# no changes")
	}
	return nil
}

// diffView compares two moments (clifr diff).
func diffView[R any](c *runCtx, v view[R], a, b int64) error {
	ra, _, err := v.at(a)
	if err != nil {
		return err
	}
	rb, meta, err := v.at(b)
	if err != nil {
		return err
	}
	ch := compare(v, ra, rb)
	if len(ch) == 0 && !c.g.json {
		fmt.Fprintf(os.Stderr, "# %s: no differences between %s and %s\n", v.name, query.FormatMS(a), query.FormatMS(b))
		return nil
	}
	return printChanges(c, v, a, b, ch, meta)
}
