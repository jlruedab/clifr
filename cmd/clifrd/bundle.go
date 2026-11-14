package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"clifr/internal/bundle"
	"clifr/internal/pqstore"
	"clifr/internal/query"
)

// bundleCmd is "clifrd bundle": the data files a window needs, as one tar
// (for sos report, or to read elsewhere with clifr --data-dir FILE).
func bundleCmd(args []string) error {
	fs := flag.NewFlagSet("clifrd bundle", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "clifrd bundle writes the recording, or the part a window needs, as one tar file.\n"+
			"Whole data files are copied unchanged; clifr reads the file with --data-dir FILE.\n"+
			"With -o FILE, FILE.sha256 is written too (sha256sum -c FILE.sha256 checks a copy).\n\n"+
			"Usage:\n  clifrd bundle [OPTIONS] -o FILE   (FILE - for standard output)\n\nOptions:\n")
		fs.PrintDefaults()
	}
	dataDir := defaultDataDir
	if d := os.Getenv("CLIFR_DATA_DIR"); d != "" {
		dataDir = d
	}
	fs.StringVar(&dataDir, "data-dir", dataDir, "Parquet data directory")
	fs.StringVar(&dataDir, "D", dataDir, "short for --data-dir")
	last := fs.String("last", "", `the window: this long until now, e.g. 6h or 2d`)
	since := fs.String("since", "", `the window's start, e.g. "2026-10-20 14:00" or "-3h"`)
	until := fs.String("until", "", `the window's end (default: now)`)
	out := fs.String("o", "", "output file (- for standard output)")
	fs.StringVar(out, "output", "", "same as -o")
	split := fs.String("split", "", `cut the bundle into parts of at most this size (e.g. 250M): FILE.part1.tar, ...,
each a bundle of its own with its .sha256; clifr reads them together (-D part1 -D part2 ...)`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *out == "" {
		return errors.New("bundle: -o FILE is required (- for standard output)")
	}
	var splitBytes int64
	if *split != "" {
		var err error
		if splitBytes, err = parseSize(*split); err != nil || splitBytes < 1<<20 {
			return fmt.Errorf("bundle: --split %q: want a size of at least 1M", *split)
		}
		if *out == "-" {
			return errors.New("bundle: --split needs -o FILE")
		}
	}
	now := time.Now()
	o := bundle.Options{DataDir: dataDir, Writer: "clifrd " + version(), Now: now}
	switch {
	case *last != "" && (*since != "" || *until != ""):
		return errors.New("bundle: give --last or --since/--until, not both")
	case *last != "":
		d, err := query.ParseDuration(*last)
		if err != nil || d <= 0 {
			return fmt.Errorf("bundle: bad --last %q", *last)
		}
		o.From, o.To = now.Add(-d).UnixMilli(), now.UnixMilli()
	case *since != "" || *until != "":
		o.From, o.To = 1, now.UnixMilli() // 1: from the start, but a window
		if *since != "" {
			t, err := query.ParseWhen(*since, now)
			if err != nil {
				return err
			}
			o.From = t.UnixMilli()
		}
		if *until != "" {
			t, err := query.ParseWhen(*until, now)
			if err != nil {
				return err
			}
			o.To = t.UnixMilli()
		}
		if o.To < o.From {
			return errors.New("bundle: --until is before --since")
		}
	}
	if *out == "-" {
		_, err := bundle.Write(o, os.Stdout)
		return err
	}
	// Written beside the target and renamed: no half bundle under its name.
	tmp, err := os.CreateTemp(filepath.Dir(*out), ".clifr-bundle-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	m, err := bundle.Write(o, io.MultiWriter(tmp, h))
	if err == nil {
		err = tmp.Sync()
	}
	if err = errors.Join(err, tmp.Close()); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		return err
	}
	if splitBytes > 0 {
		return writeParts(tmp.Name(), *out, splitBytes)
	}
	if err := pqstore.RenameDurable(tmp.Name(), *out); err != nil {
		return err
	}
	sumFile, err := writeSum(*out, h.Sum(nil))
	if err != nil {
		return err
	}
	var n int64
	for _, f := range m.Files {
		n += f.Bytes
	}
	fmt.Fprintf(os.Stderr, "clifrd bundle: %s: %d files, %.1f MB of data (checksum in %s)\n", *out, len(m.Files), float64(n)/1e6, sumFile)
	return nil
}

// writeSum writes FILE.sha256 in sha256sum's format: a copy is checked
// anywhere (sha256sum -c), before clifr reads it.
func writeSum(file string, sum []byte) (string, error) {
	sumFile := file + ".sha256"
	line := hex.EncodeToString(sum) + "  " + filepath.Base(file) + "\n"
	if err := os.WriteFile(sumFile+".tmp", []byte(line), 0o640); err != nil {
		return "", err
	}
	return sumFile, pqstore.RenameDurable(sumFile+".tmp", sumFile)
}

// partName is FILE.partN.tar (FILE without its .tar).
func partName(out string, n int) string {
	return fmt.Sprintf("%s.part%d.tar", strings.TrimSuffix(out, ".tar"), n)
}

// partFile is a part being written, hashed as it is written.
type partFile struct {
	f    *os.File
	h    hash.Hash
	name string
}

func (p *partFile) Write(b []byte) (int, error) { p.h.Write(b); return p.f.Write(b) }
func (p *partFile) Close() error {
	if p.f == nil {
		return nil
	}
	err := errors.Join(p.f.Sync(), p.f.Close())
	p.f = nil
	return err
}

// writeParts cuts the whole bundle at src into parts beside out, each
// written to a temporary name and renamed, each with its .sha256.
func writeParts(src, out string, max int64) error {
	var files []*partFile
	defer func() {
		for _, p := range files {
			p.Close()
			os.Remove(p.name)
		}
	}()
	ms, err := bundle.Split(src, max, func(n int) (io.WriteCloser, error) {
		f, err := os.CreateTemp(filepath.Dir(out), ".clifr-bundle-part-*")
		if err != nil {
			return nil, err
		}
		os.Chmod(f.Name(), 0o640)
		p := &partFile{f: f, h: sha256.New(), name: f.Name()}
		files = append(files, p)
		return p, nil
	})
	if err != nil {
		return err
	}
	for i, p := range files {
		final := partName(out, i+1)
		if err := pqstore.RenameDurable(p.name, final); err != nil {
			return err
		}
		p.name = final + ".moved" // nothing left to remove
		if _, err := writeSum(final, p.h.Sum(nil)); err != nil {
			return err
		}
		var n int64
		for _, f := range ms[i].Files {
			n += f.Bytes
		}
		fmt.Fprintf(os.Stderr, "clifrd bundle: %s: part %d of %d, %d files, %.1f MB of data (checksum in %s.sha256)\n",
			final, i+1, len(files), len(ms[i].Files), float64(n)/1e6, final)
	}
	return nil
}
