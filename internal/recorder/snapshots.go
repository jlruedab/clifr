package recorder

import (
	"slices"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// snapState is what was last written of a snapshot source: its lines by
// key, the keys in file order, and when it was last written whole.
type snapState struct {
	lines map[string]string
	keys  []string
	full  int64
}

// sampleSnapshots adds the snapshot sources' rows (store.SnapshotRow): a
// source is written whole at its first read, every NetCountersFullMS and
// when its keys or their order changed; otherwise only its changed lines.
func (r *Recorder) sampleSnapshots(ts int64, b *store.Batch, fail func(string, error) bool) {
	s := r.sys
	if s.snaps == nil {
		s.snaps = map[string]*snapState{}
	}
	for _, src := range procfs.SnapSources {
		lines, err := r.fs.ReadSnap(src)
		if fail(src.Name, err) {
			continue
		}
		keys := make([]string, len(lines))
		for i, l := range lines {
			keys[i] = l.Key
		}
		st := s.snaps[src.Name]
		if st == nil || ts-st.full >= store.NetCountersFullMS || !slices.Equal(keys, st.keys) {
			st = &snapState{lines: make(map[string]string, len(lines)), keys: keys, full: ts}
			s.snaps[src.Name] = st
			for i, l := range lines {
				b.Snapshots = append(b.Snapshots, store.SnapshotRow{TS: ts, Source: src.Name, Key: l.Key, Pos: i, Full: true, Line: l.Line})
				st.lines[l.Key] = l.Line
			}
			if len(lines) == 0 {
				b.Snapshots = append(b.Snapshots, store.SnapshotRow{TS: ts, Source: src.Name, Pos: -1, Full: true})
			}
			continue
		}
		for i, l := range lines {
			if st.lines[l.Key] != l.Line {
				b.Snapshots = append(b.Snapshots, store.SnapshotRow{TS: ts, Source: src.Name, Key: l.Key, Pos: i, Line: l.Line})
				st.lines[l.Key] = l.Line
			}
		}
	}
}
