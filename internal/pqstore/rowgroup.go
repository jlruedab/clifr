package pqstore

import (
	"reflect"
	"sync"

	"github.com/parquet-go/parquet-go"
)

// rowGroupBytes bounds the rows a writer buffers before it ends a row group.
// parquet-go keeps a whole row group in memory (with its dictionaries) until
// it is written; compacting an hour of a process flood as one row group (94
// MB on disk of nearly random command lines) took the recorder past its
// MemoryMax at every start (2026-11-11).
const rowGroupBytes = 32 << 20

// groupWriter writes rows and ends a row group whenever the rows written
// since the last one reach rowGroupBytes (estimated: the row's size plus its
// strings).
type groupWriter[T any] struct {
	w     *parquet.GenericWriter[T]
	bytes int64
}

func (g *groupWriter[T]) write(rows []T) error {
	if _, err := g.w.Write(rows); err != nil {
		return err
	}
	for i := range rows {
		g.bytes += rowBytes(&rows[i])
	}
	if g.bytes >= rowGroupBytes {
		g.bytes = 0
		return g.w.Flush()
	}
	return nil
}

var stringFields sync.Map // reflect.Type -> []int

// rowBytes estimates a row's size in memory: its struct and its strings.
func rowBytes[T any](row *T) int64 {
	v := reflect.ValueOf(row).Elem()
	t := v.Type()
	idx, ok := stringFields.Load(t)
	if !ok {
		var l []int
		for i := range t.NumField() {
			if t.Field(i).Type.Kind() == reflect.String {
				l = append(l, i)
			}
		}
		idx, _ = stringFields.LoadOrStore(t, l)
	}
	n := int64(t.Size())
	for _, i := range idx.([]int) {
		n += int64(v.Field(i).Len())
	}
	return n
}
