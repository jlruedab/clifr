package store

// Backend is where the recorder writes: internal/pqstore, the Parquet files.
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
