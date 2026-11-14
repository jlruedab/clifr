package pqstore

import (
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/parquet-go/parquet-go"
)

// Meta keys of a clean stop: a run that writes MetaWritesStop at its start
// writes MetaStopMS (Unix ms) when it stops cleanly. A run with the first and
// without the second ended without a clean stop (a crash, a power loss,
// clifrd killed); runs from before these keys say nothing.
const (
	MetaWritesStop = "writes_stop"
	MetaStopMS     = "stop_ms"
)

// PrevRun is what the data directory says about the run before this one.
type PrevRun struct {
	Run          int64 // its start (Unix s)
	BootID       string
	Known        bool  // it wrote MetaWritesStop: Clean is meaningful
	Clean        bool  // it wrote MetaStopMS
	StopMS       int64 // MetaStopMS
	LastSampleMS int64 // the newest sample on disk (0: none found)
}

// PrevRun is the run before this one, read when the store was opened (ok =
// false: no earlier run).
func (s *Store) PrevRun() (PrevRun, bool) { return s.prev, s.prev.Run != 0 }

// readPrevRun reads the meta of the newest run before run, and the newest
// sample on disk (which this run has not written yet).
func readPrevRun(dir string, run int64) PrevRun {
	var p PrevRun
	dated, open := DataFiles(dir, "meta")
	byRun := map[int64]map[string]string{}
	buf := make([]metaRow, 256)
	for _, f := range append(dated, open...) {
		eachRow(f, buf, func(m metaRow) {
			if m.Run >= run {
				return
			}
			if byRun[m.Run] == nil {
				byRun[m.Run] = map[string]string{}
			}
			byRun[m.Run][m.Key] = m.Value
		})
	}
	for r := range byRun {
		p.Run = max(p.Run, r)
	}
	if p.Run == 0 {
		return p
	}
	m := byRun[p.Run]
	p.BootID = m["boot_id"]
	p.Known = m[MetaWritesStop] == "1"
	p.StopMS, _ = strconv.ParseInt(m[MetaStopMS], 10, 64)
	p.Clean = p.StopMS > 0
	// The newest sample: the last files by name (day, then HH-MM or HH).
	samples, _ := DataFiles(dir, "samples")
	slices.Sort(samples)
	now := time.Now().UnixMilli()
	sbuf := make([]sampleRow, 256)
	for _, f := range samples[max(0, len(samples)-3):] {
		eachRow(f, sbuf, func(r sampleRow) {
			if r.TS <= now {
				p.LastSampleMS = max(p.LastSampleMS, r.TS)
			}
		})
	}
	return p
}

// eachRow calls fn for every row of a Parquet file; a file that is gone or
// damaged is skipped.
func eachRow[T any](path string, buf []T, fn func(T)) {
	if CheckFile(path) != nil {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	r := parquet.NewGenericReader[T](f)
	defer r.Close()
	for {
		n, err := r.Read(buf)
		for _, row := range buf[:n] {
			fn(row)
		}
		if errors.Is(err, io.EOF) || err != nil {
			return
		}
	}
}
