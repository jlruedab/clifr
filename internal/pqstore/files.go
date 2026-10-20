package pqstore

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/parquet-go/parquet-go"
)

// FileSpan is the range of times the rows of a data file can have, in Unix
// milliseconds. A file is named after when it was written (UTC):
// DAY/HH-MM[-n].parquet for a flush, DAY/HH.parquet for a compacted hour.
// Its rows are no later than that (plus a minute of slack), and no earlier
// than one flush interval before; with flush 0 (not known) lo is 0. ok is
// false for open files and names it does not know.
func FileSpan(path string, flush time.Duration) (lo, hi int64, ok bool) {
	day, name := filepath.Base(filepath.Dir(path)), filepath.Base(path)
	var start, end time.Time
	switch {
	case partRe.MatchString(name):
		t, err := time.Parse("2006-01-02 15-04", day+" "+name[:5])
		if err != nil {
			return 0, 0, false
		}
		start, end = t, t.Add(time.Minute)
	case hourRe.MatchString(name):
		t, err := time.Parse("2006-01-02 15", day+" "+name[:2])
		if err != nil {
			return 0, 0, false
		}
		start, end = t, t.Add(time.Hour)
	default:
		return 0, 0, false
	}
	const slack = time.Minute
	hi = end.Add(slack).UnixMilli()
	if flush > 0 {
		lo = start.Add(-flush - slack).UnixMilli()
	}
	return lo, hi, true
}

// DataFiles lists a table's dated files and its open files.
func DataFiles(dir, table string) (dated, open []string) {
	dated, _ = filepath.Glob(filepath.Join(dir, table, "*-*-*", "*.parquet"))
	open, _ = filepath.Glob(filepath.Join(dir, table, "open", "*.parquet"))
	return dated, open
}

// ReadMeta reads the meta table of a data directory: the latest value of
// each key over every run.
func ReadMeta(dir string) (map[string]string, error) {
	dated, open := DataFiles(dir, "meta")
	type kv struct {
		ts    int64
		value string
	}
	latest := map[string]kv{}
	buf := make([]metaRow, 256)
	for _, p := range append(dated, open...) {
		f, err := os.Open(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // compacted meanwhile
			}
			return nil, err
		}
		r := parquet.NewGenericReader[metaRow](f)
		for {
			n, err := r.Read(buf)
			for _, m := range buf[:n] {
				if m.TS >= latest[m.Key].ts {
					latest[m.Key] = kv{m.TS, m.Value}
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				r.Close()
				f.Close()
				return nil, err
			}
		}
		r.Close()
		f.Close()
	}
	out := make(map[string]string, len(latest))
	for k, v := range latest {
		out[k] = v.value
	}
	return out, nil
}

// StartedBy writes to out the rows of an entity table's files that began at
// or before to (first_seen, open_ts): the entities of a window that closed
// after it, without the ones that began after it. It reports the rows kept.
func StartedBy(table string, parts []string, out string, to int64) (int, error) {
	f, ok := starters[table]
	if !ok {
		return 0, fmt.Errorf("%s: not an entity table", table)
	}
	return f(parts, out, to)
}

var starters = map[string]func(parts []string, out string, to int64) (int, error){
	"processes":   filterRows(func(r *processRow) int64 { return r.FirstSeen }),
	"sockets":     filterRows(func(r *socketRow) int64 { return r.FirstSeen }),
	"sock_owners": filterRows(func(r *ownerRow) int64 { return r.FirstSeen }),
	"open_files":  filterRows(func(r *fileRow) int64 { return r.FirstSeen }),
	"fds_held":    filterRows(func(r *heldRow) int64 { return r.FirstSeen }),
	"tcp_conns":   filterRows(func(r *tcpConnRow) int64 { return r.OpenTS }),
}

func filterRows[T any](start func(*T) int64) func(parts []string, out string, to int64) (int, error) {
	return func(parts []string, out string, to int64) (int, error) {
		f, err := os.Create(out)
		if err != nil {
			return 0, err
		}
		w := parquet.NewGenericWriter[T](f, writerOptions...)
		buf, keep := make([]T, 4096), make([]T, 0, 4096)
		kept := 0
		for _, p := range parts {
			in, err := os.Open(p)
			if err != nil {
				w.Close()
				f.Close()
				return 0, err
			}
			r := parquet.NewGenericReader[T](in)
			for {
				n, rerr := r.Read(buf)
				keep = keep[:0]
				for i := range buf[:n] {
					if start(&buf[i]) <= to {
						keep = append(keep, buf[i])
					}
				}
				if len(keep) > 0 {
					if _, err = w.Write(keep); err != nil {
						break
					}
					kept += len(keep)
				}
				if rerr == io.EOF {
					break
				}
				if rerr != nil {
					err = rerr
					break
				}
			}
			r.Close()
			in.Close()
			if err != nil {
				w.Close()
				f.Close()
				return 0, err
			}
		}
		return kept, errors.Join(w.Close(), f.Close())
	}
}
