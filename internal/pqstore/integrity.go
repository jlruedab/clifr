package pqstore

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/parquet-go/parquet-go"
)

// The integrity log: every data file the store writes (flush parts, open
// files, compacted hour files) gets a line "SHA256 SIZE PATH" (PATH relative
// to the data directory) in IntegrityDir/DAY.log, DAY the UTC day of the
// write. Later lines win (open files are rewritten every flush). Removed by
// retention like the data. CheckIntegrity compares the files with it.
const IntegrityDir = "integrity"

type integrityLog struct {
	mu    sync.Mutex
	dir   string // data directory
	f     *os.File
	day   string
	dirty bool
}

// record appends path's checksum (path: a file just written).
func (l *integrityLog) record(path string) error {
	sum, size, err := hashFile(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(l.dir, path)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	day := time.Now().UTC().Format("2006-01-02")
	if l.f == nil || l.day != day {
		if l.f != nil {
			l.f.Sync()
			l.f.Close()
			l.f = nil
		}
		if err := mkdirDurable(filepath.Join(l.dir, IntegrityDir), 0o750); err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(l.dir, IntegrityDir, day+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return err
		}
		l.f, l.day = f, day
	}
	_, err = fmt.Fprintf(l.f, "%s %d %s\n", sum, size, filepath.ToSlash(rel))
	l.dirty = true
	return err
}

// sync makes the lines written so far durable (once per flush).
func (l *integrityLog) sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil || !l.dirty {
		return nil
	}
	l.dirty = false
	return l.f.Sync()
}

func (l *integrityLog) close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := errors.Join(l.f.Sync(), l.f.Close())
	l.f = nil
	return err
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

type logEntry struct {
	sum  string
	size int64
}

// readIntegrityLogs reads every log of dir: the last line of each path.
// A torn last line (a crash while appending) is ignored.
func readIntegrityLogs(dir string) map[string]logEntry {
	out := map[string]logEntry{}
	logs, _ := filepath.Glob(filepath.Join(dir, IntegrityDir, "*.log"))
	sort.Strings(logs)
	for _, p := range logs {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.SplitN(sc.Text(), " ", 3)
			if len(fs) != 3 || len(fs[0]) != 64 {
				continue
			}
			size, err := strconv.ParseInt(fs[1], 10, 64)
			if err != nil {
				continue
			}
			out[fs[2]] = logEntry{fs[0], size}
		}
		f.Close()
	}
	return out
}

// IntegrityFile is one damaged file found by CheckIntegrity.
type IntegrityFile struct {
	Path  string // relative to the data directory
	Table string
	Error string
}

// IntegrityReport is what CheckIntegrity found.
type IntegrityReport struct {
	Files      int             // data files checked
	Bytes      int64           // their size
	Logged     int             // compared with their logged checksum
	Unlogged   int             // read whole instead (written before the log, or not logged)
	Damaged    []IntegrityFile // checksum mismatch, or not readable
	Duration   time.Duration
	LogEntries int
}

// CheckIntegrity checks every data file of dir: against its last line in
// the integrity log (SHA-256 of the whole file), else by reading every page
// (Parquet's page CRCs, zstd frame checksums, structure). A file rewritten
// while it runs (an open file at a flush) is compared with the log again.
func CheckIntegrity(dir string) IntegrityReport {
	t0 := time.Now()
	var r IntegrityReport
	logs := readIntegrityLogs(dir)
	r.LogEntries = len(logs)
	for _, t := range Tables {
		dated, open := DataFiles(dir, t)
		for _, p := range append(dated, open...) {
			rel, _ := filepath.Rel(dir, p)
			rel = filepath.ToSlash(rel)
			st, err := os.Stat(p)
			if err != nil {
				continue // compacted or expired meanwhile
			}
			r.Files++
			r.Bytes += st.Size()
			if e, ok := logs[rel]; ok {
				r.Logged++
				sum, _, err := hashFile(p)
				if err != nil {
					continue // gone meanwhile
				}
				if sum != e.sum {
					// Rewritten after the log was read? Read it again.
					if e2, ok := readIntegrityLogs(dir)[rel]; ok && e2.sum != e.sum {
						if sum2, _, err := hashFile(p); err == nil && sum2 == e2.sum {
							continue
						}
					}
					r.Damaged = append(r.Damaged, IntegrityFile{rel, t, fmt.Sprintf("SHA-256 %.12s..., logged %.12s... (%d bytes, logged %d)", sum, e.sum, st.Size(), e.size)})
				}
				continue
			}
			r.Unlogged++
			if err := readWhole(p); err != nil {
				if _, serr := os.Stat(p); serr != nil {
					continue
				}
				r.Damaged = append(r.Damaged, IntegrityFile{rel, t, err.Error()})
			}
		}
	}
	r.Duration = time.Since(t0)
	return r
}

// readWhole reads every page of every column of a Parquet file.
func readWhole(path string) error {
	if err := CheckFile(path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	pf, err := parquet.OpenFile(f, st.Size(), parquet.SkipPageIndex(true), parquet.SkipBloomFilters(true))
	if err != nil {
		return err
	}
	for _, rg := range pf.RowGroups() {
		for _, cc := range rg.ColumnChunks() {
			pages := cc.Pages()
			for {
				p, err := pages.ReadPage()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					pages.Close()
					return err
				}
				parquet.Release(p)
			}
			pages.Close()
		}
	}
	return nil
}
