package main

import (
	"fmt"
	"io"
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
	print func(io.Writer, []R)
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
	if c.g.json {
		for _, t := range times {
			rows, meta, err := v.at(t)
			if err != nil {
				return true, err
			}
			if err := writeLines(rows, func(i int) rowMeta { m := meta(&rows[i]); m.TS = t; return m }); err != nil {
				return true, err
			}
		}
		return true, nil
	}
	pages := make([]page, len(times))
	for i, t := range times {
		pages[i] = page{title: fmt.Sprintf("%s at %s", v.name, query.FormatMS(t)), ts: t, body: func(w io.Writer) error {
			rows, _, err := v.at(t)
			if err == nil {
				v.print(w, rows)
			}
			return err
		}}
	}
	return true, c.show(pages)
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

// writeChanges writes one comparison as JSON Lines.
func writeChanges[R any](from, to int64, ch []change[R], meta func(*R) rowMeta) error {
	rows := make([]R, len(ch))
	for i := range ch {
		rows[i] = ch[i].row
	}
	return writeLines(rows, func(i int) rowMeta {
		m := meta(&ch[i].row)
		m.TS, m.From, m.Change = to, from, ch[i].kind
		return m
	})
}

// changesPage is one comparison: appeared, gone and changed rows as three
// tables in the command's own format.
func changesPage[R any](v view[R], from, to int64, ch []change[R]) page {
	counts := map[string]int{}
	for _, x := range ch {
		counts[x.kind]++
	}
	title := fmt.Sprintf("%s, %s -> %s: %d appeared, %d gone, %d changed", v.name, query.FormatMS(from), query.FormatMS(to),
		counts["+"], counts["-"], counts["~"])
	return page{title: title, ts: to, body: func(w io.Writer) error {
		for _, kind := range []struct{ k, title string }{{"+", "appeared"}, {"-", "gone"}, {"~", "changed (as at " + query.FormatMS(to) + ")"}} {
			var rows []R
			for _, x := range ch {
				if x.kind == kind.k {
					rows = append(rows, x.row)
				}
			}
			if len(rows) > 0 {
				fmt.Fprintf(w, "## %s\n", kind.title)
				v.print(w, rows)
			}
		}
		return nil
	}}
}

func runChanges[R any](c *runCtx, v view[R], times []int64) error {
	c.header("%s: changes between %d samples, %s .. %s (anything shorter than a sample interval is in \"events\")",
		v.name, len(times), query.FormatMS(times[0]), query.FormatMS(times[len(times)-1]))
	c.quiet = true
	prev, _, err := v.at(times[0])
	if err != nil {
		return err
	}
	var pages []page
	for i := 1; i < len(times); i++ {
		cur, meta, err := v.at(times[i])
		if err != nil {
			return err
		}
		if ch := compare(v, prev, cur); len(ch) > 0 {
			if c.g.number > 0 && len(pages) == c.g.number {
				break
			}
			if c.g.json {
				if err := writeChanges(times[i-1], times[i], ch, meta); err != nil {
					return err
				}
			}
			pages = append(pages, changesPage(v, times[i-1], times[i], ch))
		}
		prev = cur
	}
	switch {
	case c.g.json:
		return nil
	case len(pages) == 0:
		fmt.Fprintln(os.Stderr, "# no changes")
		return nil
	}
	return c.show(pages)
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
	switch {
	case c.g.json:
		return writeChanges(a, b, ch, meta)
	case len(ch) == 0:
		fmt.Fprintf(os.Stderr, "# %s: no differences between %s and %s\n", v.name, query.FormatMS(a), query.FormatMS(b))
		return nil
	}
	return c.show([]page{changesPage(v, a, b, ch)})
}
