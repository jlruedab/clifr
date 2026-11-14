package bundle

import (
	"archive/tar"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"clifr/internal/pqstore"
)

// Split cuts a finished bundle (the tar at src) into parts of at most
// maxBytes each (a file larger than that is a part of its own): every part
// is a whole bundle, with the files it holds listed in its own bundle.json
// (the window and summary are the whole bundle's, BundleID shared, Part i of
// Parts), so a part is checked and read alone, and the parts together read
// as the whole. A data file is never cut. open creates part i (1-based).
func Split(src string, maxBytes int64, open func(part int) (io.WriteCloser, error)) ([]*Manifest, error) {
	m, err := readManifest(src)
	if err != nil {
		return nil, err
	}
	// Each file's place: tar header and padding, and its entry in the
	// part's bundle.json (path, size, checksum, rows: under 300 bytes).
	entry := func(f File) int64 { return 512 + (f.Bytes+511)/512*512 + 300 }
	// bundle.json without files (summary), its header, the end of the tar.
	base, _ := json.MarshalIndent(Manifest{Tables: m.Tables, Samples: m.Samples, Events: m.Events, Hostname: m.Hostname}, "", "  ")
	overhead := int64(len(base)) + 4096
	// meta first: part 1 alone still names the host and its versions.
	files := slices.Clone(m.Files)
	slices.SortStableFunc(files, func(a, b File) int {
		am, bm := isMeta(a.Path), isMeta(b.Path)
		switch {
		case am && !bm:
			return -1
		case bm && !am:
			return 1
		}
		return 0
	})
	var parts [][]File
	var size int64
	for _, f := range files {
		if len(parts) == 0 || size > 0 && size+entry(f)+overhead > maxBytes {
			parts = append(parts, nil)
			size = 0
		}
		parts[len(parts)-1] = append(parts[len(parts)-1], f)
		size += entry(f)
	}
	if len(parts) == 0 {
		parts = [][]File{nil}
	}
	id := make([]byte, 8)
	rand.Read(id)
	partOf := map[string]int{}
	var out []*Manifest
	for i, files := range parts {
		pm := *m
		pm.Files, pm.BundleID, pm.Part, pm.Parts = files, hex.EncodeToString(id), i+1, len(parts)
		out = append(out, &pm)
		for _, f := range files {
			partOf[f.Path] = i
		}
	}
	ws := make([]io.WriteCloser, len(parts))
	tws := make([]*tar.Writer, len(parts))
	closeAll := func() {
		for _, w := range ws {
			if w != nil {
				w.Close()
			}
		}
	}
	for i := range parts {
		if ws[i], err = open(i + 1); err != nil {
			closeAll()
			return nil, err
		}
		tws[i] = tar.NewWriter(ws[i])
	}
	f, err := os.Open(src)
	if err != nil {
		closeAll()
		return nil, err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			closeAll()
			return nil, err
		}
		rel := strings.TrimPrefix(h.Name, Root+"/")
		i, ok := partOf[rel]
		if !ok {
			continue // bundle.json: each part gets its own
		}
		if err := tws[i].WriteHeader(h); err != nil {
			closeAll()
			return nil, err
		}
		if _, err := io.Copy(tws[i], tr); err != nil {
			closeAll()
			return nil, err
		}
	}
	var errs []error
	for i, pm := range out {
		b, err := json.MarshalIndent(pm, "", "  ")
		if err == nil {
			err = tws[i].WriteHeader(&tar.Header{Name: Root + "/bundle.json", Mode: 0o640, Size: int64(len(b)), Typeflag: tar.TypeReg})
		}
		if err == nil {
			_, err = tws[i].Write(b)
		}
		errs = append(errs, err, tws[i].Close(), ws[i].Close())
	}
	return out, errors.Join(errs...)
}

// isMeta: a file of the meta table (data/DIR/...).
func isMeta(path string) bool {
	parts := strings.SplitN(path, "/", 3)
	return len(parts) == 3 && pqstore.TableOf(parts[1]) == "meta"
}

// readManifest reads bundle.json of a bundle file.
func readManifest(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("not a clifr bundle (no bundle.json)")
		}
		if err != nil {
			return nil, err
		}
		if h.Name == Root+"/bundle.json" {
			var m Manifest
			if err := json.NewDecoder(tr).Decode(&m); err != nil {
				return nil, fmt.Errorf("bundle.json: %w", err)
			}
			return &m, nil
		}
	}
}
