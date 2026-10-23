package recorder

import (
	"os"
	"slices"
	"strconv"

	"clifr/internal/procfs"
	"clifr/internal/rtnl"
	"clifr/internal/store"
)

// snapReader is a snapshot source and how it is read: at every system
// sample, or every everyMS.
type snapReader struct {
	name    string
	read    func() ([]procfs.SnapLine, error)
	everyMS int64
}

// machineSnaps are read only on the real /proc (they describe this
// machine, not a fixture).
var machineSnaps = []snapReader{{"netns", readNetns, 0}, {"locks", readLocks, 0}, {"sysctl", readSysctl, sysctlReadMS}}

// sysctlReadMS: how often /proc/sys is read (some 1,600 files: 6-12 ms).
const sysctlReadMS = 60_000

// readNetns lists /run/netns as ip netns does: in directory order, each
// name with the id this namespace gives it ("name id", -1 for none).
func readNetns() ([]procfs.SnapLine, error) {
	d, err := os.Open("/run/netns")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names, err := d.Readdirnames(-1) // unsorted: the directory's order
	d.Close()
	if err != nil {
		return nil, err
	}
	out := make([]procfs.SnapLine, 0, len(names))
	for _, n := range names {
		id, _ := rtnl.NSID("/run/netns/" + n)
		out = append(out, procfs.SnapLine{Key: n, Line: n + " " + strconv.Itoa(id)})
	}
	return out, nil
}

// snapState is what was last written of a snapshot source: its lines by
// key, the keys in file order, and when it was last written whole.
type snapState struct {
	lines map[string]string
	keys  []string
	full  int64
	read  int64 // when it was last read
}

// sampleSnapshots adds the snapshot sources' rows (store.SnapshotRow): a
// source is written whole at its first read, every NetCountersFullMS and
// when its keys or their order changed; otherwise only its changed lines.
func (r *Recorder) sampleSnapshots(ts int64, b *store.Batch, fail func(string, error) bool) {
	s := r.sys
	if s.snaps == nil {
		s.snaps = map[string]*snapState{}
	}
	sources := make([]snapReader, 0, len(procfs.SnapSources)+len(machineSnaps))
	for _, src := range procfs.SnapSources {
		sources = append(sources, snapReader{src.Name, func() ([]procfs.SnapLine, error) { return r.fs.ReadSnap(src) }, 0})
	}
	if s.sysfs {
		sources = append(sources, machineSnaps...)
	}
	for _, src := range sources {
		if st := s.snaps[src.name]; st != nil && src.everyMS > 0 && ts-st.read < src.everyMS {
			continue
		}
		lines, err := src.read()
		if fail(src.name, err) {
			continue
		}
		keys := make([]string, len(lines))
		for i, l := range lines {
			keys[i] = l.Key
		}
		st := s.snaps[src.name]
		if st == nil || ts-st.full >= store.NetCountersFullMS || !slices.Equal(keys, st.keys) {
			st = &snapState{lines: make(map[string]string, len(lines)), keys: keys, full: ts, read: ts}
			s.snaps[src.name] = st
			for i, l := range lines {
				b.Snapshots = append(b.Snapshots, store.SnapshotRow{TS: ts, Source: src.name, Key: l.Key, Pos: i, Full: true, Line: l.Line})
				st.lines[l.Key] = l.Line
			}
			if len(lines) == 0 {
				b.Snapshots = append(b.Snapshots, store.SnapshotRow{TS: ts, Source: src.name, Pos: -1, Full: true})
			}
			continue
		}
		st.read = ts
		for i, l := range lines {
			if st.lines[l.Key] != l.Line {
				b.Snapshots = append(b.Snapshots, store.SnapshotRow{TS: ts, Source: src.name, Key: l.Key, Pos: i, Line: l.Line})
				st.lines[l.Key] = l.Line
			}
		}
	}
}
