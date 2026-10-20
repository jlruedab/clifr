package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"clifr/internal/bundle"
	"clifr/internal/query"
)

// bundleCmd is "clifrd bundle": the data files a window needs, as one tar
// (for sos report, or to read elsewhere with clifr --data-dir FILE).
func bundleCmd(args []string) error {
	fs := flag.NewFlagSet("clifrd bundle", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "clifrd bundle writes the recording, or the part a window needs, as one tar file.\n"+
			"Whole data files are copied unchanged; clifr reads the file with --data-dir FILE.\n\n"+
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *out == "" {
		return errors.New("bundle: -o FILE is required (- for standard output)")
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
	m, err := bundle.Write(o, tmp)
	if err == nil {
		err = tmp.Sync()
	}
	if err = errors.Join(err, tmp.Close()); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), *out); err != nil {
		return err
	}
	var n int64
	for _, f := range m.Files {
		n += f.Bytes
	}
	fmt.Fprintf(os.Stderr, "clifrd bundle: %s: %d files, %.1f MB of data\n", *out, len(m.Files), float64(n)/1e6)
	return nil
}
