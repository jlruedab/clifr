package pqstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

// Dir is the name of a table's directory: 8 hex digits of the SHA-256 of
// "clifr/" and the table name, so that the names do not show what is
// recorded (the user, 2026-11-01). It is the same on every host: any clifr
// reads any recording or bundle without a key.
func Dir(table string) string {
	if d, ok := dirs[table]; ok {
		return d
	}
	return hashDir(table)
}

var dirs = func() map[string]string {
	m := make(map[string]string, len(Tables))
	for _, t := range Tables {
		m[t] = hashDir(t)
	}
	return m
}()

func hashDir(table string) string {
	h := sha256.Sum256([]byte("clifr/" + table))
	return hex.EncodeToString(h[:4])
}

// TableDir is the directory of a table in a data directory: Dir(table), or
// the table's own name in recordings and bundles made before 2026-11-01
// (clifrd renames those when it opens the store).
func TableDir(dataDir, table string) string {
	p := filepath.Join(dataDir, Dir(table))
	if _, err := os.Stat(p); err != nil {
		if old := filepath.Join(dataDir, table); dirExists(old) {
			return old
		}
	}
	return p
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// IsDataDir reports whether dir holds a recording (its samples table).
func IsDataDir(dir string) error {
	_, err := os.Stat(TableDir(dir, "samples"))
	return err
}

// renameDirs gives the table directories of an older recording their
// Dir names. When both exist (an older clifrd ran meanwhile) the files are
// moved one by one; one whose name is already taken stays where it was.
func renameDirs(dataDir string, logf func(string, ...any)) error {
	var errs []error
	for _, t := range Tables {
		old, cur := filepath.Join(dataDir, t), filepath.Join(dataDir, Dir(t))
		if !dirExists(old) {
			continue
		}
		if !dirExists(cur) {
			errs = append(errs, os.Rename(old, cur))
			continue
		}
		left := 0
		filepath.WalkDir(old, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(old, p)
			to := filepath.Join(cur, rel)
			if _, err := os.Stat(to); err == nil {
				left++
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
				return err
			}
			return os.Rename(p, to)
		})
		if left > 0 {
			logf("pqstore: %s: %d files left in %s (their names exist in %s)", t, left, old, cur)
			continue
		}
		errs = append(errs, os.RemoveAll(old))
	}
	return errors.Join(errs...)
}

// DataFiles lists a table's dated files and its open files.
func DataFiles(dir, table string) (dated, open []string) {
	d := TableDir(dir, table)
	dated, _ = filepath.Glob(filepath.Join(d, "*-*-*", "*.parquet"))
	open, _ = filepath.Glob(filepath.Join(d, "open", "*.parquet"))
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
