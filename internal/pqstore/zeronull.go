package pqstore

import (
	"reflect"
	"slices"
	"strings"
)

// ZeroNull lists the columns of table where a stored 0 means NULL: numbers
// kept in a plain (not pointer) field tagged optional, which the writer
// stores as NULL when 0. parquet-go (v0.32.0, still on its main branch
// 2026-11-21) sometimes stores such a 0 as a value: in
// writeRowsFuncOfOptional, after a run of nulls, the test whether the rest
// of the 64-row word is non-null compares with (1<<y)-1 instead of
// ^uint64(0)>>y, so [0, 5, 0] is written as NULL, 5, 0. On a desktop
// recording with a benchmark: 62 tcp_conns.owner_until (ss lost the owner:
// "the application closed the socket"), 96 processes.exec_ts, 900
// tcp_conns.linger_until. Readers therefore read 0 as NULL in these
// columns (internal/duck); 0 is no valid value in any of them (times).
func ZeroNull(table string) []string {
	r, ok := tableRows[table]
	if !ok {
		return nil
	}
	var cols []string
	for i := range r.typ.NumField() {
		f := r.typ.Field(i)
		tag := f.Tag.Get("parquet")
		name, opts, _ := strings.Cut(tag, ",")
		if !slices.Contains(strings.Split(opts, ","), "optional") {
			continue
		}
		switch f.Type.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
			cols = append(cols, name)
		}
	}
	return cols
}
