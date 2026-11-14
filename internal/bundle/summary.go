package bundle

import (
	"slices"
	"strconv"
	"strings"

	"clifr/internal/pqstore"
)

// What bundle.json says about the data besides the files (2026-11-14,
// additive: bundle_version stays 1): rows per file and table, the samples'
// span, interval and gaps, and the events that explain a gap (an unclean
// stop, a kernel crash record, a full disk). A receiver can then tell data
// missing from the recording from data lost in transfer.

// TableSummary is one table's files in the bundle.
type TableSummary struct {
	Files int   `json:"files"`
	Rows  int64 `json:"rows"`
	Bytes int64 `json:"bytes"`
}

// Samples is the span of the samples in the bundle and its gaps (sample
// intervals longer than 2.5 times interval_s, the gap rule of clifr events).
type Samples struct {
	Count     int     `json:"count"`
	FirstMS   int64   `json:"first_ms"`
	LastMS    int64   `json:"last_ms"`
	IntervalS float64 `json:"interval_s,omitempty"`
	Gaps      []Gap   `json:"gaps,omitempty"`
}

type Gap struct {
	FromMS int64 `json:"from_ms"` // the last sample before it
	ToMS   int64 `json:"to_ms"`   // the first after it
}

// Event is a guard event that explains missing data.
type Event struct {
	TS     int64  `json:"ts_ms"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// noteKinds are the guard events copied into the manifest.
var noteKinds = map[string]bool{"unclean_stop": true, "pstore": true, "disk_full": true, "disk_ok": true, "events_lost": true}

const maxGaps, maxEvents = 100, 100

// summary collects what the bundle's files hold while they are added.
type summary struct {
	from, to int64 // the window (0, 0: all)
	interval float64
	times    []int64
	events   []Event
}

// add looks at a file just added (src: its path on disk, table: its table).
func (s *summary) add(table, src string) {
	switch table {
	case "samples":
		s.times = append(s.times, pqstore.SampleTimes(src)...)
	case "guard_events":
		for _, g := range pqstore.GuardEvents(src) {
			if noteKinds[g.Kind] && (s.to == 0 || g.TS >= s.from && g.TS <= s.to) {
				s.events = append(s.events, Event{g.TS, g.Kind, g.Detail})
			}
		}
	}
}

// fill writes the summary into m.
func (s *summary) fill(m *Manifest, meta map[string]string) {
	m.Tables = map[string]TableSummary{}
	for _, f := range m.Files {
		parts := strings.Split(f.Path, "/")
		if len(parts) < 2 {
			continue
		}
		t := pqstore.TableOf(parts[1])
		if t == "" {
			continue
		}
		ts := m.Tables[t]
		ts.Files++
		ts.Rows += f.Rows
		ts.Bytes += f.Bytes
		m.Tables[t] = ts
	}
	if s.to != 0 {
		s.times = slices.DeleteFunc(s.times, func(t int64) bool { return t < s.from || t > s.to })
	}
	slices.Sort(s.times)
	s.times = slices.Compact(s.times)
	if len(s.times) > 0 {
		sm := &Samples{Count: len(s.times), FirstMS: s.times[0], LastMS: s.times[len(s.times)-1]}
		sm.IntervalS, _ = strconv.ParseFloat(meta["interval_s"], 64)
		if sm.IntervalS > 0 {
			limit := int64(sm.IntervalS * 2500)
			for i := 1; i < len(s.times) && len(sm.Gaps) < maxGaps; i++ {
				if s.times[i]-s.times[i-1] > limit {
					sm.Gaps = append(sm.Gaps, Gap{s.times[i-1], s.times[i]})
				}
			}
		}
		m.Samples = sm
	}
	slices.SortFunc(s.events, func(a, b Event) int { return int(a.TS - b.TS) })
	if len(s.events) > maxEvents {
		s.events = s.events[:maxEvents]
	}
	m.Events = s.events
}
