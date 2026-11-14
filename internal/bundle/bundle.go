// Package bundle writes a clifrd recording, or the part of it a time window
// needs, as one tar file: the Parquet files unchanged and a manifest. It is
// what travels to sos-vault (inside a sosreport, or pushed later); clifr
// reads the tar directly. Pure Go: it runs in clifrd, on the recorded host.
package bundle

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"clifr/internal/pqstore"
	"clifr/internal/store"
)

// Version is the bundle layout version (bundle.json "bundle_version").
const Version = 1

// Root is the directory every path in the tar starts with.
const Root = "clifr-bundle"

// Manifest is bundle.json.
type Manifest struct {
	BundleVersion int    `json:"bundle_version"`
	Writer        string `json:"writer"` // clifrd that made the bundle
	CreatedMS     int64  `json:"created_ms"`
	FromMS        int64  `json:"from_ms"` // the window asked for (0: the whole recording)
	ToMS          int64  `json:"to_ms"`
	// From the recording's meta.
	SchemaVersion string `json:"schema_version"`
	Recorder      string `json:"clifrd_version"`
	Hostname      string `json:"hostname"`
	MachineID     string `json:"machine_id"`
	BootID        string `json:"boot_id"`
	TimeZone      string `json:"timezone"`
	Files         []File `json:"files"`
}

// File is one file in the bundle.
type File struct {
	Path   string `json:"path"` // under clifr-bundle/
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Options says what to bundle.
type Options struct {
	DataDir  string
	From, To int64 // Unix ms; both 0: everything
	Writer   string
	Now      time.Time
}

// Tables whose values are written only when they change: a value in the
// window may have been written long before it. kmsg too: dmesg at a moment
// prints every record of the boot up to it (internal/duck loads it so).
var changeOnly = []string{"proc_samples", "sock_samples", "mounts", "fs_samples", "kmsg"}

// Tables whose state at a moment is the last snapshot before it (written
// every store.NetSnapshotMS) plus the changes after, as internal/duck loads
// them: a window needs the hour before it.
var hourly = []string{"addrs", "routing", "units", "cgroups"}

// Selection is what a window needs: files copied whole, and per entity
// table the files written after the window, of which only the rows of
// entities begun by its end are kept (see pqstore.StartedBy).
type Selection struct {
	Copy  []string            // relative to the data directory
	After map[string][]string // table: absolute paths
}

// defaultFlush is the recorder's default flush interval: assumed for
// recordings made before meta had flush_interval_s.
const defaultFlush = 5 * time.Minute

// Select lists the data files the window needs, per table:
//   - meta: all;
//   - values written on change: everything up to the window's end;
//   - entity tables (a row is written when the entity closes, maybe long
//     after the window): from shortly before the window on, and the open
//     files;
//   - the rest: the window.
//
// "Shortly before" is two keyframe intervals and ten minutes: the state at
// the window's start comes from the keyframe and the sample before it.
func Select(o Options, meta map[string]string) (Selection, error) {
	sec := func(k string, def time.Duration) time.Duration {
		v, err := strconv.ParseFloat(meta[k], 64)
		if err != nil || v <= 0 {
			return def
		}
		return time.Duration(v * float64(time.Second))
	}
	flush := sec("flush_interval_s", defaultFlush)
	keyframe := sec("keyframe_interval_s", 5*time.Minute)
	all := o.From == 0 && o.To == 0
	sel := Selection{After: map[string][]string{}}
	var out []string
	for _, t := range pqstore.Tables {
		dated, open := pqstore.DataFiles(o.DataDir, t)
		entity := slices.Contains(pqstore.EntityTables, t)
		lo, hi := o.From-(2*keyframe+10*time.Minute).Milliseconds(), o.To
		switch {
		case all || t == "meta":
			lo, hi = 0, 1<<62
		case entity:
			hi = 1 << 62
		case slices.Contains(changeOnly, t):
			lo = 0
		case slices.Contains(hourly, t):
			lo = o.From - store.NetSnapshotMS - (2 * time.Minute).Milliseconds()
		}
		for _, f := range dated {
			fLo, fHi, ok := pqstore.FileSpan(f, flush)
			switch {
			case ok && entity && !all && fLo > o.To:
				sel.After[t] = append(sel.After[t], f)
			case !ok || fHi >= lo && fLo <= hi:
				out = append(out, f)
			}
		}
		if entity || all || t == "meta" {
			out = append(out, open...)
		}
	}
	for _, f := range out {
		rel, err := filepath.Rel(o.DataDir, f)
		if err != nil {
			return sel, err
		}
		sel.Copy = append(sel.Copy, rel)
	}
	return sel, nil
}

// Write writes the bundle as a tar to w. The recorder may be running: its
// files are replaced by renaming, so an open file stays whole; one removed
// meanwhile (an hour compacted into one file) makes the selection be done
// again, once.
func Write(o Options, w io.Writer) (*Manifest, error) {
	if err := pqstore.IsDataDir(o.DataDir); err != nil {
		return nil, fmt.Errorf("%s: not a clifr data directory (no samples table)", o.DataDir)
	}
	meta, err := pqstore.ReadMeta(o.DataDir)
	if err != nil {
		return nil, fmt.Errorf("meta: %w", err)
	}
	m := &Manifest{BundleVersion: Version, Writer: o.Writer, CreatedMS: o.Now.UnixMilli(), FromMS: o.From, ToMS: o.To,
		SchemaVersion: meta["schema_version"], Recorder: meta["clifrd_version"], Hostname: meta["hostname"],
		MachineID: meta["machine_id"], BootID: meta["boot_id"], TimeZone: meta["timezone"]}
	tw := tar.NewWriter(w)
	written := map[string]bool{}
	var sel Selection
	for attempt := 0; attempt < 2; attempt++ {
		if sel, err = Select(o, meta); err != nil {
			return nil, err
		}
		vanished := false
		for _, rel := range sel.Copy {
			if written[rel] {
				continue
			}
			f, err := addFile(tw, o.DataDir, rel, rel)
			if errors.Is(err, fs.ErrNotExist) {
				vanished = true
				continue
			}
			if err != nil {
				return nil, err
			}
			written[rel] = true
			m.Files = append(m.Files, f)
		}
		if !vanished {
			break
		}
	}
	if err := addAfter(tw, m, sel, o, meta); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := tw.WriteHeader(&tar.Header{Name: Root + "/bundle.json", Mode: 0o640, Size: int64(len(b)),
		ModTime: o.Now, Typeflag: tar.TypeReg}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(b); err != nil {
		return nil, err
	}
	return m, tw.Close()
}

// addAfter adds, per entity table, one file of the rows written after the
// window that began by its end. Its name (TABLE/DAY/after-window.parquet,
// DAY of the window's end) is not a flush time: readers keep it for any
// window.
func addAfter(tw *tar.Writer, m *Manifest, sel Selection, o Options, meta map[string]string) error {
	if len(sel.After) == 0 {
		return nil
	}
	tmp, err := os.MkdirTemp("", "clifr-bundle-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	day := time.UnixMilli(o.To).UTC().Format("2006-01-02")
	for _, t := range pqstore.EntityTables {
		parts := sel.After[t]
		if len(parts) == 0 {
			continue
		}
		var n int
		for attempt := 0; ; attempt++ {
			n, err = pqstore.StartedBy(t, parts, filepath.Join(tmp, t+".parquet"), o.To)
			if !errors.Is(err, fs.ErrNotExist) || attempt == 1 {
				break
			}
			// Compacted meanwhile: the hour's file instead of its parts.
			s, serr := Select(o, meta)
			if serr != nil {
				return serr
			}
			parts = s.After[t]
		}
		if err != nil {
			return fmt.Errorf("%s: %w", t, err)
		}
		if n == 0 {
			continue
		}
		// Under the table's Dir, where readers look (from 2026-11-01 to
		// 2026-11-07 this used the plain name, beside it: lost).
		f, err := addFile(tw, tmp, t+".parquet", filepath.Join(pqstore.Dir(t), day, "after-window.parquet"))
		if err != nil {
			return err
		}
		m.Files = append(m.Files, f)
	}
	return nil
}

// addFile adds dir/rel to the bundle as data/name.
func addFile(tw *tar.Writer, dir, rel, name string) (File, error) {
	f, err := os.Open(filepath.Join(dir, rel))
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return File{}, err
	}
	if err := tw.WriteHeader(&tar.Header{Name: Root + "/data/" + filepath.ToSlash(name), Mode: 0o640, Size: st.Size(), ModTime: st.ModTime(),
		Typeflag: tar.TypeReg}); err != nil {
		return File{}, err
	}
	h := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(tw, h), f, st.Size()); err != nil {
		return File{}, err
	}
	return File{Path: "data/" + filepath.ToSlash(name), Bytes: st.Size(), SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// Extract unpacks a bundle into dir and returns its data directory and
// manifest. Only regular files under clifr-bundle/ are written; checksums
// are verified. At most limit bytes are written (0: no limit): a bundle is
// an uncompressed tar, so its own size is enough, but a tar entry can be
// sparse, a large file of zeros in a few bytes.
func Extract(r io.Reader, dir string, limit int64) (string, *Manifest, error) {
	data, m, _, err := extract(r, dir, limit, false)
	return data, m, err
}

// Salvage is Extract for a damaged bundle (a transfer cut short, a changed
// file): it keeps the files whose checksums match and returns the paths of
// the ones it left out (damaged, or missing from a tar cut short). Without
// bundle.json (the last entry: lost when the tar was cut short) the Manifest
// is nil and it keeps the files that are whole Parquet files
// (pqstore.CheckFile), unverified.
func Salvage(r io.Reader, dir string, limit int64) (string, *Manifest, []string, error) {
	return extract(r, dir, limit, true)
}

// cutShort explains a tar that ends in the middle (a transfer that stopped).
func cutShort(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("bundle cut short (%w); clifr --salvage reads what arrived", err)
	}
	return err
}

func extract(r io.Reader, dir string, limit int64, salvage bool) (string, *Manifest, []string, error) {
	tr := tar.NewReader(r)
	sums := map[string]string{}
	var m *Manifest
	var written int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if salvage { // cut short: keep what came before
				break
			}
			return "", nil, nil, cutShort(err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		rel, err := filepath.Rel(Root, filepath.FromSlash(h.Name))
		if err != nil || rel == ".." || filepath.IsAbs(rel) || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
			return "", nil, nil, fmt.Errorf("bundle: unexpected path %q", h.Name)
		}
		if rel == "bundle.json" {
			m = &Manifest{}
			if err := json.NewDecoder(tr).Decode(m); err != nil {
				return "", nil, nil, fmt.Errorf("bundle.json: %w", err)
			}
			continue
		}
		if written += h.Size; limit > 0 && written > limit {
			return "", nil, nil, fmt.Errorf("bundle: %s: more data than the bundle's %d bytes hold", h.Name, limit)
		}
		dst := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return "", nil, nil, err
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
		if err != nil {
			return "", nil, nil, err
		}
		hs := sha256.New()
		_, err = io.Copy(io.MultiWriter(f, hs), tr)
		err = errors.Join(err, f.Close())
		if err != nil {
			if salvage { // the file was cut short: its checksum will not match
				sums[filepath.ToSlash(rel)] = ""
				break
			}
			return "", nil, nil, cutShort(err)
		}
		sums[filepath.ToSlash(rel)] = hex.EncodeToString(hs.Sum(nil))
	}
	if m == nil && salvage && len(sums) > 0 {
		// bundle.json is the tar's last entry: a transfer cut short loses
		// it. Without checksums, keep the files that are whole Parquet files.
		var bad []string
		for p := range sums {
			if err := pqstore.CheckFile(filepath.Join(dir, filepath.FromSlash(p))); err != nil {
				bad = append(bad, p)
				os.Remove(filepath.Join(dir, filepath.FromSlash(p)))
			}
		}
		slices.Sort(bad)
		return filepath.Join(dir, "data"), nil, bad, nil
	}
	if m == nil {
		return "", nil, nil, errors.New("not a clifr bundle (no bundle.json; if it was cut short, clifr --salvage reads what arrived)")
	}
	if m.BundleVersion > Version {
		return "", nil, nil, fmt.Errorf("bundle version %d is newer than this clifr reads (%d): update clifr", m.BundleVersion, Version)
	}
	listed := map[string]bool{}
	var bad []string
	for _, f := range m.Files {
		listed[f.Path] = true
		if sums[f.Path] == f.SHA256 {
			continue
		}
		if !salvage {
			return "", nil, nil, fmt.Errorf("bundle: %s is damaged or missing (clifr --salvage reads the rest)", f.Path)
		}
		bad = append(bad, f.Path)
		os.Remove(filepath.Join(dir, filepath.FromSlash(f.Path)))
	}
	if salvage { // a file bundle.json does not list cannot be checked
		for p := range sums {
			if !listed[p] {
				bad = append(bad, p)
				os.Remove(filepath.Join(dir, filepath.FromSlash(p)))
			}
		}
	}
	slices.Sort(bad)
	return filepath.Join(dir, "data"), m, bad, nil
}
