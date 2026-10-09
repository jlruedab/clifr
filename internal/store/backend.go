package store

import "errors"

// Backend is where the recorder writes. The SQLite database (DB) keeps the v1
// schema; internal/pqstore writes the same tables as Parquet files. Tee
// writes to two backends at once, for side-by-side comparisons.
type Backend interface {
	// Write stores one sample's batch.
	Write(b *Batch) error
	SetMeta(key, value string) error
	// MaxID is the largest id already used in an entity table, so the
	// recorder's id counters continue after it.
	MaxID(table string) (int64, error)
	// Bytes is the data the backend holds (for the samples table's db_bytes).
	Bytes() int64
	Close() error
}

// Bytes is the logical size of the SQLite database.
func (d *DB) Bytes() int64 { return d.LogicalBytes() }

type tee struct{ a, b Backend }

// Tee writes every batch to both backends. Ids come from the larger MaxID, so
// both hold the same ids; Bytes reports the first backend.
func Tee(a, b Backend) Backend { return tee{a, b} }

func (t tee) Write(b *Batch) error { return errors.Join(t.a.Write(b), t.b.Write(b)) }
func (t tee) SetMeta(k, v string) error {
	return errors.Join(t.a.SetMeta(k, v), t.b.SetMeta(k, v))
}
func (t tee) MaxID(table string) (int64, error) {
	x, err1 := t.a.MaxID(table)
	y, err2 := t.b.MaxID(table)
	return max(x, y), errors.Join(err1, err2)
}
func (t tee) Bytes() int64 { return t.a.Bytes() }
func (t tee) Close() error { return errors.Join(t.a.Close(), t.b.Close()) }
