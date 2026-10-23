package recorder

import (
	"bytes"
	"slices"
	"strconv"

	"clifr/internal/rtnl"
	"clifr/internal/store"
)

// neighState is what was last written of the neighbour table: the entries
// by key, the keys in dump order, and when all were last written.
type neighState struct {
	rows map[string]store.NeighRow
	keys []string
	full int64
}

func neighKey(n *rtnl.Neigh) string {
	return strconv.Itoa(n.Family) + "/" + strconv.Itoa(n.Index) + "/" + string(n.Dst)
}

// neighTimeSlackMS: two dumps give the same cacheinfo time up to a USER_HZ
// tick apart (the age is in ticks, the sample time in ms); such a
// difference is not a change.
const neighTimeSlackMS = 20

// addNeighs writes the neighbour table: whole at the first dump, every
// NetCountersFullMS and when the entries or their order changed, else the
// entries that changed.
func (s *sysSampler) addNeighs(ts int64, ns []rtnl.Neigh, b *store.Batch) {
	keys := make([]string, len(ns))
	rows := make([]store.NeighRow, len(ns))
	for i := range ns {
		n := &ns[i]
		keys[i] = neighKey(n)
		r := store.NeighRow{TS: ts, Pos: int64(i), Family: n.Family, Index: n.Index, State: int(n.State), Flags: int(n.Flags),
			Type: int(n.Type), ExtFlags: int64(n.ExtFlags), Dst: n.Dst, LLAddr: n.LLAddr, HasLLAddr: n.HasLLAddr,
			Probes: n.Probes, Protocol: n.Protocol}
		if n.HasCache {
			r.ConfirmedMS, r.UsedMS, r.UpdatedMS = ts-int64(n.Confirmed)*10, ts-int64(n.Used)*10, ts-int64(n.Update)*10
			r.RefCnt = int64(n.RefCnt)
		}
		rows[i] = r
	}
	st := s.neighs
	whole := st == nil || ts-st.full >= store.NetCountersFullMS || !slices.Equal(keys, st.keys)
	if whole {
		st = &neighState{rows: make(map[string]store.NeighRow, len(rows)), keys: keys, full: ts}
		s.neighs = st
	}
	for i, r := range rows {
		old, ok := st.rows[keys[i]]
		if !whole && ok && sameNeigh(&old, &r) {
			continue
		}
		r.Whole = whole
		b.Neighs = append(b.Neighs, r)
		st.rows[keys[i]] = r
	}
	if whole && len(rows) == 0 {
		b.Neighs = append(b.Neighs, store.NeighRow{TS: ts, Pos: -1, Whole: true})
	}
}

// sameNeigh compares two dumps of an entry, the times within
// neighTimeSlackMS.
func sameNeigh(a, b *store.NeighRow) bool {
	near := func(x, y int64) bool { return x-y <= neighTimeSlackMS && y-x <= neighTimeSlackMS }
	return a.State == b.State && a.Flags == b.Flags && a.Type == b.Type && a.ExtFlags == b.ExtFlags &&
		bytes.Equal(a.LLAddr, b.LLAddr) && a.HasLLAddr == b.HasLLAddr && a.Probes == b.Probes && a.Protocol == b.Protocol &&
		a.RefCnt == b.RefCnt && near(a.ConfirmedMS, b.ConfirmedMS) && near(a.UsedMS, b.UsedMS) && near(a.UpdatedMS, b.UpdatedMS)
}
