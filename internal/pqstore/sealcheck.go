package pqstore

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SealCheck is clifr verify --integrity --seal-key: the chain (SealReport)
// and every data file against its last sealed log line.
type SealCheck struct {
	SealReport
	Verified  int      // present files that match their sealed line
	Removed   int      // files clifrd removed (a sealed "del" line), gone
	Modified  []string // "PATH: why": changed after it was sealed
	Deleted   []string // sealed, missing, no sealed removal
	Premature []string // removed by retention before the retention had passed
	// Unprotected: present files written after the last seal (their line
	// is not sealed yet), and files with no line at all (written before the
	// integrity log, or not by clifrd).
	AfterLastSeal int
	NoLine        []string
	Anchors       []string // one result per --seal-anchor
	AnchorsBad    int
	// NotInBundle: sealed files a bundle left out (its window).
	NotInBundle int
}

// Bad is the number of findings that mean the recording was altered.
func (c *SealCheck) Bad() int {
	return len(c.SealReport.Bad) + len(c.Modified) + len(c.Deleted) + len(c.Premature) + c.AnchorsBad
}

var partName = regexp.MustCompile(`^(\d\d)-\d\d(-\d+)?\.parquet$`)

// CheckSeals verifies dir's seal chain with keys, checks the data files
// against their sealed lines (ir: CheckIntegrity's report of the same
// directory, for the files present and their SHA-256) and the anchors
// ("KEYID/EPOCH:TAG", from clifrd's journal). In a bundle (bundle), sealed
// files that are missing are counted as not in the bundle.
func CheckSeals(dir string, keys [][]byte, anchors []string, ir IntegrityReport, bundle bool) SealCheck {
	c := SealCheck{SealReport: VerifySeals(dir, keys)}
	present := map[string]bool{}
	for _, p := range ir.Present {
		present[p] = true
	}
	for p, sf := range c.Sealed {
		at := time.UnixMilli(sf.MS).UTC().Format("2006-01-02 15:04 UTC")
		if reason, ok := strings.CutPrefix(sf.What, "del "); ok {
			if present[p] {
				if w, ok := c.Pending[p]; ok && !strings.HasPrefix(w, "del ") && ir.Sums[p] == strings.Fields(w)[0] {
					c.AfterLastSeal++ // written again since (an open file)
					continue
				}
				c.Modified = append(c.Modified, fmt.Sprintf("%s: removed by clifrd (%s, sealed %s), present again", p, reason, at))
				continue
			}
			c.Removed++
			c.checkRemoval(p, reason, sf.MS, present)
			continue
		}
		sum := strings.Fields(sf.What)[0]
		switch {
		case !present[p]:
			if w, ok := c.Pending[p]; ok && strings.HasPrefix(w, "del ") {
				c.AfterLastSeal++ // removed by clifrd since the last seal
			} else if bundle {
				c.NotInBundle++
			} else if !strings.HasPrefix(p, IntegrityDir+"/") {
				c.Deleted = append(c.Deleted, fmt.Sprintf("%s: sealed %s, missing, and clifrd recorded no removal", p, at))
			}
		case ir.Sums[p] == sum:
			c.Verified++
		case ir.Sums[p] != "" && c.Pending[p] != "" && ir.Sums[p] == strings.Fields(c.Pending[p])[0]:
			c.AfterLastSeal++ // rewritten since (an open file at the next flush)
		default:
			c.Modified = append(c.Modified, fmt.Sprintf("%s: SHA-256 %.12s..., sealed %.12s... (%s)", p, ir.Sums[p], sum, at))
		}
	}
	for _, p := range ir.Present {
		if _, ok := c.Sealed[p]; ok {
			continue
		}
		if w, ok := c.Pending[p]; ok && !strings.HasPrefix(w, "del ") && ir.Sums[p] == strings.Fields(w)[0] {
			c.AfterLastSeal++
		} else {
			c.NoLine = append(c.NoLine, p)
		}
	}
	sort.Strings(c.Modified)
	sort.Strings(c.Deleted)
	sort.Strings(c.Premature)
	sort.Strings(c.NoLine)
	for _, a := range anchors {
		ok, msg := c.anchor(a)
		if !ok {
			c.AnchorsBad++
		}
		c.Anchors = append(c.Anchors, msg)
	}
	return c
}

// checkRemoval judges a sealed removal: parts merged into an hour file that
// is there (or was removed in turn), retention not before its time.
func (c *SealCheck) checkRemoval(p, reason string, ms int64, present map[string]bool) {
	dir, name := path.Split(p)
	switch {
	case reason == "compacted":
		m := partName.FindStringSubmatch(name)
		if m == nil {
			return
		}
		hour := dir + m[1] + ".parquet"
		if _, sealed := c.Sealed[hour]; !sealed && !present[hour] {
			if _, pend := c.Pending[hour]; !pend {
				c.Deleted = append(c.Deleted, fmt.Sprintf("%s: removed as merged into %s, which is missing", p, hour))
			}
		}
	case strings.HasPrefix(reason, "retention:"):
		secs, err := strconv.ParseInt(strings.TrimPrefix(reason, "retention:"), 10, 64)
		if err != nil {
			return
		}
		end, ok := fileEnd(p)
		if !ok {
			return // an open file: its age is not in its name
		}
		if keep := time.Duration(secs) * time.Second; time.UnixMilli(ms).Before(end.Add(keep - 5*time.Minute)) {
			c.Premature = append(c.Premature, fmt.Sprintf("%s: removed by retention (%s) by %s, before its time",
				p, keep, time.UnixMilli(ms).UTC().Format("2006-01-02 15:04 UTC")))
		}
	}
}

// fileEnd is the end of what a dated file holds, from its name: an hour
// file or part (DAY/HH...), the day of an integrity log (DAY.log).
func fileEnd(p string) (time.Time, bool) {
	dir, name := path.Split(p)
	day := path.Base(strings.TrimSuffix(dir, "/"))
	if strings.HasSuffix(name, ".log") {
		d, err := time.Parse("2006-01-02", strings.TrimSuffix(name, ".log"))
		return d.Add(24 * time.Hour), err == nil
	}
	if len(name) < 2 {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02 15", day+" "+name[:2])
	return t.Add(time.Hour), err == nil
}

// anchor checks one --seal-anchor KEYID/EPOCH:TAG against the verified seals.
func (c *SealCheck) anchor(a string) (bool, string) {
	id, rest, ok1 := strings.Cut(a, "/")
	es, tag, ok2 := strings.Cut(rest, ":")
	epoch, err := strconv.ParseUint(es, 10, 64)
	if !ok1 || !ok2 || err != nil || len(tag) < 8 {
		return false, a + ": not an anchor (KEYID/EPOCH:TAG, from clifrd's \"seal anchor\" log line)"
	}
	tags := c.tags[id]
	if got, ok := tags[epoch]; ok {
		if strings.HasPrefix(got, strings.ToLower(tag)) {
			return true, a + ": reached"
		}
		return false, fmt.Sprintf("%s: the recording has another seal %d (%.16s): the chain was rewritten or restored from an older copy", a, epoch, got)
	}
	if tags == nil {
		return false, a + ": no verified seal of chain " + id + " (another key, or its logs are gone)"
	}
	var last uint64
	for e := range tags {
		last = max(last, e)
	}
	if epoch > last {
		return false, fmt.Sprintf("%s: the recording's last verified seal of this chain is %d: the seals after it were removed", a, last)
	}
	if first := c.StartEpoch[id]; epoch < first {
		return true, fmt.Sprintf("%s: older than the logs kept (they start at seal %d: retention)", a, first)
	}
	return false, fmt.Sprintf("%s: seal %d is missing from the recording", a, epoch)
}

// SealStatus is the sealing state of a data directory, for clifr info.
type SealStatus struct {
	State  string `json:"state"` // "off", "set up" (no seal yet), "on", "unsealed"
	KeyID  string `json:"key_id,omitempty"`
	Epoch  uint64 `json:"epoch,omitempty"`   // of the last seal
	LastMS int64  `json:"last_ms,omitempty"` // time of the last seal
	Why    string `json:"why,omitempty"`     // unsealed: state-missing or state-damaged
}

// ReadSealStatus reads the last seal of the logs and seal.state (no key
// needed, nothing verified).
func ReadSealStatus(dir string) SealStatus {
	var st SealStatus
	var last *sealRec
	unsealed := ""
	for _, p := range integrityLogFiles(dir) {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			if r, ok := parseSeal(l); ok {
				last, unsealed = &r, ""
			} else if w, ok := strings.CutPrefix(l, "unsealed "); ok {
				unsealed = w
			}
		}
	}
	_, _, err := readSealState(dir)
	switch {
	case unsealed != "":
		st.State, st.Why = "unsealed", unsealed
	case last != nil && err != nil:
		st.State, st.Why = "unsealed", "state-missing"
		if _, serr := os.Stat(filepath.Join(dir, IntegrityDir, SealStateFile)); serr == nil {
			st.Why = "state-damaged"
		}
	case last != nil:
		st.State = "on"
	case err == nil:
		st.State = "set up"
	default:
		st.State = "off"
	}
	if last != nil {
		st.KeyID, st.Epoch, st.LastMS = last.keyID, last.epoch, last.ms
	}
	return st
}
