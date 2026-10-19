package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
)

// --json writes JSON Lines: one object per row. Each row starts with the
// times it describes and ends with "sampled", the names of its fields whose
// values come from a periodic sample (the others are exact, from events or
// stable for the object's life):
//
//	ts_ms         the moment the row describes (--at, or the row's own time)
//	sample_ts_ms  the sample the sampled values come from
//	from_ms/to_ms the range (or, for counters, the interval) it covers
//	change        with --changes and diff: + appeared, - gone, ~ changed
//	              (from_ms is the earlier moment, ts_ms the later)
//
// Keys a row already has are not repeated. Times are Unix milliseconds.

type rowMeta struct {
	TS, SampleTS, From, To int64
	Change                 string // --changes and diff: + appeared, - gone, ~ changed
	Sampled                []string
}

// emit prints rows (a slice, or one value) as JSON Lines, or their text
// (through the pager when it applies).
func (c *runCtx) emit(rows any, meta func(i int) rowMeta, text func(io.Writer)) error {
	if !c.g.json {
		return c.show([]page{{body: func(w io.Writer) error { text(w); return nil }}})
	}
	return writeLines(rows, meta)
}

func writeLines(rows any, meta func(i int) rowMeta) error {
	w := bufio.NewWriter(os.Stdout)
	v := reflect.ValueOf(rows)
	if v.Kind() != reflect.Slice {
		v = reflect.Append(reflect.MakeSlice(reflect.SliceOf(v.Type()), 0, 1), v)
	}
	for i := 0; i < v.Len(); i++ {
		var m rowMeta
		if meta != nil {
			m = meta(i)
		}
		b, err := jsonLine(v.Index(i).Interface(), m, meta != nil)
		if err != nil {
			return err
		}
		w.Write(b)
		w.WriteByte('\n')
	}
	return w.Flush()
}

// jsonLine is one row with the times in front and, if withSampled, the
// sampled list at the end.
func jsonLine(row any, m rowMeta, withSampled bool) ([]byte, error) {
	b, err := json.Marshal(row)
	if err != nil {
		return nil, err
	}
	if len(b) < 2 || b[0] != '{' {
		return b, nil
	}
	var has map[string]json.RawMessage
	if err := json.Unmarshal(b, &has); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteByte('{')
	n := 0
	if m.Change != "" {
		out.WriteString(`"change":"` + m.Change + `",`)
		n++
	}
	for _, f := range []struct {
		key string
		v   int64
	}{{"ts_ms", m.TS}, {"sample_ts_ms", m.SampleTS}, {"from_ms", m.From}, {"to_ms", m.To}} {
		if _, dup := has[f.key]; f.v != 0 && !dup {
			out.WriteString(`"` + f.key + `":` + strconv.FormatInt(f.v, 10) + ",")
			n++
		}
	}
	body := b[1 : len(b)-1]
	out.Write(body)
	if withSampled {
		if len(body) > 0 {
			out.WriteByte(',')
		}
		present := []string{} // only keys the row has (omitempty fields may be absent)
		for _, k := range m.Sampled {
			if _, ok := has[k]; ok {
				present = append(present, k)
			}
		}
		s, _ := json.Marshal(present)
		out.WriteString(`"sampled":`)
		out.Write(s)
	} else if len(body) == 0 && n > 0 {
		out.Truncate(out.Len() - 1) // the comma after the last time
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// jsonKeys lists the JSON keys of a struct value's fields, except those in
// skip (for rows whose values are all sampled).
func jsonKeys(v any, skip ...string) []string {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		skipped := false
		for _, s := range skip {
			skipped = skipped || s == name
		}
		if !skipped {
			out = append(out, name)
		}
	}
	return out
}
