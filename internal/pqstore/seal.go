package pqstore

// Forward-secure sealing of the integrity log (docs/sealing.md).
//
// `clifrd seal-setup` (SealSetup) draws a random k0, the verification key,
// prints it once and stores only k1 = evolve(k0) in integrity/seal.state.
// At every flush the store appends a seal line to the log,
//
//	seal KEYID EPOCH TIME_MS RUN FLAG LINES PREVTAG TAG
//
// TAG = HMAC-SHA256(mac(k(EPOCH)), the fields, PREVTAG and the SHA-256 of
// the log lines written since the previous seal), then replaces k(EPOCH) in
// seal.state with k(EPOCH+1) = evolve(k(EPOCH)). Nobody can compute an
// earlier key from a later one, so root on the host at time C cannot forge
// the seals made before C; the verifier derives every k(i) from k0.
//
// FLAG: "-" a flush; "start" a run's first seal; "end" a clean stop; "late"
// lines written before this run started and not sealed (a crash), sealed at
// its start; "day" the lines of a UTC day, sealed before the next day's log
// file begins (so every day's log verifies on its own).
//
// Without seal.state, while the logs hold seals (it was lost or damaged), the
// store writes "unsealed REASON" once, logs a warning hourly and never starts
// a chain by itself (D3).

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// SealStateFile holds the current key (integrity/seal.state).
	SealStateFile = "seal.state"
	sealSlot      = 256 // bytes per slot; the file has two
	sealVersion   = "clifr-seal-1"
	// VerifyKeyPrefix starts a printed verification key.
	VerifyKeyPrefix = "cs1-"
)

var zeroTag = strings.Repeat("0", 64)

func evolveKey(k []byte) []byte {
	m := hmac.New(sha256.New, k)
	m.Write([]byte("clifr seal evolve"))
	return m.Sum(nil)
}

func macKey(k []byte) []byte {
	m := hmac.New(sha256.New, k)
	m.Write([]byte("clifr seal mac"))
	return m.Sum(nil)
}

// SealKeyID names a chain: the first 8 hex digits of SHA-256(k0).
func SealKeyID(k0 []byte) string {
	s := sha256.Sum256(k0)
	return hex.EncodeToString(s[:4])
}

// sealRec is one seal line.
type sealRec struct {
	keyID     string
	epoch     uint64
	ms, run   int64
	flag      string
	lines     int
	prev, tag string
}

func (r sealRec) line() string {
	return fmt.Sprintf("seal %s %d %d %d %s %d %s %s", r.keyID, r.epoch, r.ms, r.run, r.flag, r.lines, r.prev, r.tag)
}

// mac computes the tag of r over sum (the SHA-256 of its lines) with
// k(r.epoch).
func (r sealRec) mac(key, sum []byte) string {
	m := hmac.New(sha256.New, macKey(key))
	fmt.Fprintf(m, "%s|%s|%d|%d|%d|%s|%d|%s|%x", sealVersion, r.keyID, r.epoch, r.ms, r.run, r.flag, r.lines, r.prev, sum)
	return hex.EncodeToString(m.Sum(nil))
}

func parseSeal(line string) (sealRec, bool) {
	f := strings.Fields(line)
	if len(f) != 9 || f[0] != "seal" || len(f[7]) != 64 || len(f[8]) != 64 {
		return sealRec{}, false
	}
	var r sealRec
	var err1, err2, err3, err4 error
	r.keyID, r.flag, r.prev, r.tag = f[1], f[5], f[7], f[8]
	r.epoch, err1 = strconv.ParseUint(f[2], 10, 64)
	r.ms, err2 = strconv.ParseInt(f[3], 10, 64)
	r.run, err3 = strconv.ParseInt(f[4], 10, 64)
	r.lines, err4 = strconv.Atoi(f[6])
	return r, errors.Join(err1, err2, err3, err4) == nil
}

// sealState is a slot of seal.state: the key of the next seal.
type sealState struct {
	seq   uint64 // the newer valid slot wins
	keyID string
	epoch uint64 // of the next seal
	key   []byte // k(epoch)
	prev  string // tag of the previous seal (zeroTag at a chain's start)
}

func (s sealState) encode() []byte {
	body := fmt.Sprintf("%s %d %s %d %x %s", sealVersion, s.seq, s.keyID, s.epoch, s.key, s.prev)
	sum := sha256.Sum256([]byte(body))
	b := []byte(body + " " + hex.EncodeToString(sum[:8]))
	out := []byte(strings.Repeat(" ", sealSlot-1) + "\n")
	copy(out, b)
	return out
}

func decodeSealState(b []byte) (sealState, bool) {
	f := strings.Fields(string(b))
	if len(f) != 7 || f[0] != sealVersion {
		return sealState{}, false
	}
	body := strings.Join(f[:6], " ")
	sum := sha256.Sum256([]byte(body))
	if hex.EncodeToString(sum[:8]) != f[6] {
		return sealState{}, false
	}
	var s sealState
	var err1, err2, err3 error
	s.seq, err1 = strconv.ParseUint(f[1], 10, 64)
	s.keyID = f[2]
	s.epoch, err2 = strconv.ParseUint(f[3], 10, 64)
	s.key, err3 = hex.DecodeString(f[4])
	s.prev = f[5]
	if errors.Join(err1, err2, err3) != nil || len(s.key) != 32 || len(s.prev) != 64 {
		return sealState{}, false
	}
	return s, true
}

func sealStatePath(dir string) string { return filepath.Join(dir, IntegrityDir, SealStateFile) }

// errSealDamaged: seal.state exists, but neither slot is valid.
var errSealDamaged = errors.New("seal.state is damaged")

// readSealState returns the newest valid slot and its index. A missing file
// is fs.ErrNotExist.
func readSealState(dir string) (sealState, int, error) {
	b, err := os.ReadFile(sealStatePath(dir))
	if err != nil {
		return sealState{}, 0, err
	}
	best, slot := sealState{}, -1
	for i := 0; i < 2 && (i+1)*sealSlot <= len(b); i++ {
		if s, ok := decodeSealState(b[i*sealSlot : (i+1)*sealSlot]); ok && (slot < 0 || s.seq > best.seq) {
			best, slot = s, i
		}
	}
	if slot < 0 {
		return sealState{}, 0, errSealDamaged
	}
	return best, slot, nil
}

// writeSealState writes s into the slot that is not cur, makes it durable,
// then overwrites slot cur (the previous key) with blanks: the old key is
// overwritten in place, not left in a renamed-away file. A crash in between
// leaves both valid; the newer wins and the next write wipes the other.
func writeSealState(dir string, s sealState, cur int) error {
	p := sealStatePath(dir)
	_, statErr := os.Stat(p)
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	next := 1 - cur
	if _, err := f.WriteAt(s.encode(), int64(next*sealSlot)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	blank := []byte(strings.Repeat(" ", sealSlot-1) + "\n")
	if _, err := f.WriteAt(blank, int64(cur*sealSlot)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if errors.Is(statErr, fs.ErrNotExist) {
		return SyncDir(filepath.Dir(p))
	}
	return nil
}

// SealSetup starts a chain for the data directory: it draws k0, stores
// k1 = evolve(k0) and returns the verification key (VerifyKeyPrefix + hex
// k0) and its id. k0 itself is never written. An existing seal.state, valid
// or not, is replaced only with replace (seal-setup --new); the old chain
// stays verifiable with its own key.
func SealSetup(dir string, replace bool) (verifyKey, keyID string, err error) {
	_, cur, rerr := readSealState(dir)
	switch {
	case rerr == nil && !replace:
		return "", "", errors.New("sealing is already set up for " + dir + " (--new starts a new chain with a new key)")
	case errors.Is(rerr, errSealDamaged) && !replace:
		return "", "", errors.New("seal.state is damaged (--new starts a new chain with a new key)")
	case rerr != nil && !errors.Is(rerr, fs.ErrNotExist) && !errors.Is(rerr, errSealDamaged):
		return "", "", rerr
	}
	if errors.Is(rerr, errSealDamaged) {
		cur = 1 // overwrite slot 0 first, then blank slot 1
		if b, _ := os.ReadFile(sealStatePath(dir)); len(b) < 2*sealSlot {
			cur = 0
		}
	}
	k0 := make([]byte, 32)
	if _, err := rand.Read(k0); err != nil {
		return "", "", err
	}
	if err := mkdirDurable(filepath.Join(dir, IntegrityDir), 0o750); err != nil {
		return "", "", err
	}
	id := SealKeyID(k0)
	st := sealState{seq: uint64(time.Now().UnixNano()), keyID: id, epoch: 1, key: evolveKey(k0), prev: zeroTag}
	if err := writeSealState(dir, st, cur); err != nil {
		return "", "", err
	}
	return VerifyKeyPrefix + hex.EncodeToString(k0), id, nil
}

// ParseVerifyKey reads a key printed by SealSetup.
func ParseVerifyKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	k, err := hex.DecodeString(strings.TrimPrefix(s, VerifyKeyPrefix))
	if err != nil || !strings.HasPrefix(s, VerifyKeyPrefix) || len(k) != 32 {
		return nil, fmt.Errorf("not a clifr verification key (%s followed by 64 hex digits)", VerifyKeyPrefix)
	}
	return k, nil
}

// sealOpen reads the logs at Open, before anything is appended: it ends a
// torn last line (so the next line is not glued to it), notes whether the
// logs hold seals, takes the lines after the last seal as the pending lines
// (the next seal covers them) and finishes a seal whose state update a crash
// stopped.
func (l *integrityLog) sealOpen(run int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.run = run
	l.sum.Reset()
	l.lines = 0
	logs := integrityLogFiles(l.dir)
	if n := len(logs); n > 0 {
		if b, err := os.ReadFile(logs[n-1]); err == nil && len(b) > 0 && b[len(b)-1] != '\n' {
			if f, err := os.OpenFile(logs[n-1], os.O_WRONLY|os.O_APPEND, 0); err == nil {
				f.Write([]byte("\n"))
				f.Sync()
				f.Close()
			}
		}
		l.day = strings.TrimSuffix(filepath.Base(logs[n-1]), ".log")
	}
	var last *sealRec
	for _, p := range logs {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			if r, ok := parseSeal(sc.Text()); ok {
				last = &r
				l.chained = true
				l.sum.Reset()
				l.lines = 0
				continue
			}
			l.sum.Write(append(sc.Bytes(), '\n'))
			l.lines++
		}
		f.Close()
	}
	st, cur, err := readSealState(l.dir)
	if err == nil && last != nil && last.keyID == st.keyID && last.epoch == st.epoch {
		// The seal line is durable, the key was not evolved yet.
		st.seq++
		st.epoch++
		st.key = evolveKey(st.key)
		st.prev = last.tag
		if err := writeSealState(l.dir, st, cur); err != nil {
			l.logf("pqstore: seal: %v", err)
		}
	}
}

// sealLate seals, at Open before recover, the lines the previous run left
// unsealed (a crash), or notes that sealing was lost.
func (l *integrityLog) sealLate() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lines > 0 {
		l.sealLocked("late")
	} else {
		l.checkLostLocked()
	}
}

// seal seals the lines since the last seal ("-" at a flush, "end" at Close;
// a run's first seal is "start").
func (l *integrityLog) seal(flag string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if flag == "-" && !l.runSealed {
		flag = "start"
	}
	if l.sealLocked(flag) {
		l.runSealed = true
	}
}

// checkLostLocked: no usable seal.state. Sealing is off, or (when the logs
// hold seals) lost: noted once in the log, warned hourly.
func (l *integrityLog) checkLostLocked() (sealState, int, bool) {
	st, cur, err := readSealState(l.dir)
	if err == nil {
		l.lost = ""
		return st, cur, true
	}
	if !l.chained {
		return st, cur, false // sealing not set up
	}
	why := "state-missing"
	if !errors.Is(err, fs.ErrNotExist) {
		why = "state-damaged"
	}
	if l.lost != why {
		l.lost = why
		l.appendLocked("unsealed "+why, true)
		l.lostWarn = time.Time{}
	}
	if time.Since(l.lostWarn) >= time.Hour {
		l.lostWarn = time.Now()
		l.logf("pqstore: the integrity log is no longer sealed (%s: %v); `clifrd seal-setup --new` starts a new chain", why, err)
	}
	return st, cur, false
}

// sealLocked writes a seal and evolves the key; false when sealing is off
// or failed.
func (l *integrityLog) sealLocked(flag string) bool {
	st, cur, ok := l.checkLostLocked()
	if !ok {
		return false
	}
	r := sealRec{keyID: st.keyID, epoch: st.epoch, ms: time.Now().UnixMilli(), run: l.run, flag: flag, lines: l.lines, prev: st.prev}
	r.tag = r.mac(st.key, l.sum.Sum(nil))
	if l.f == nil { // the seal goes into the log of its lines
		day := l.day
		if day == "" {
			day = time.Now().UTC().Format("2006-01-02")
		}
		if err := l.openLocked(day); err != nil {
			l.logf("pqstore: seal: %v", err)
			return false
		}
	}
	if err := l.writeLocked(r.line(), false); err != nil {
		l.logf("pqstore: seal: %v", err)
		return false
	}
	// The seal line durable first: a crash before the key is evolved is
	// finished at the next Open (sealOpen).
	if err := l.f.Sync(); err != nil {
		l.logf("pqstore: seal: %v", err)
		return false
	}
	l.dirty = false
	l.chained = true
	l.sum.Reset()
	l.lines = 0
	st.seq++
	st.epoch++
	st.key = evolveKey(st.key)
	st.prev = r.tag
	if err := writeSealState(l.dir, st, cur); err != nil {
		l.logf("pqstore: seal: %v", err)
	}
	if time.Since(l.anchorAt) >= anchorEvery {
		l.anchorAt = time.Now()
		l.infof("seal anchor %s (where the journal is copied to another machine, clifr verify --seal-anchor checks that the recording still reaches it)", r.anchor())
	}
	return true
}

// anchorEvery: how often a seal is logged as an anchor (D4): a copy of the
// journal kept elsewhere then shows when the newest seals were cut off.
const anchorEvery = time.Hour

// anchor names a seal for --seal-anchor: KEYID/EPOCH:the first 16 hex digits
// of its tag.
func (r sealRec) anchor() string { return fmt.Sprintf("%s/%d:%s", r.keyID, r.epoch, r.tag[:16]) }

// integrityLogFiles lists the day logs, oldest first.
func integrityLogFiles(dir string) []string {
	logs, _ := filepath.Glob(filepath.Join(dir, IntegrityDir, "*.log"))
	sort.Strings(logs)
	return logs
}

// SealReport is what VerifySeals found.
type SealReport struct {
	Seals       int      // verified seal lines
	Chains      []string // key ids seen, in order
	First, Last int64    // times of the first and last verified seal (ms)
	Starts      []int64  // run starts (ms)
	Ends        []int64  // clean stops (ms)
	Late        []int64  // seals of lines a crash left unsealed (ms)
	Unsealed    []string // "unsealed" notes: sealing lost (state missing or damaged)
	After       int      // lines after the last seal (not protected yet)
	Bad         []string // tags that do not verify, gaps in the epochs, unknown keys
	// StartEpoch per chain: the first epoch the logs hold (1 = the chain's start).
	StartEpoch map[string]uint64
	// Sealed: per data file (path relative to the data directory), its last
	// sealed line ("SHA SIZE" or "del REASON"), for the file checks.
	Sealed map[string]string
}

// VerifySeals walks the seal chain of dir's integrity logs with the given
// verification keys (k0s).
func VerifySeals(dir string, keys [][]byte) SealReport {
	return verifySealLogs(integrityLogFiles(dir), keys)
}

func verifySealLogs(logs []string, keys [][]byte) SealReport {
	r := SealReport{StartEpoch: map[string]uint64{}, Sealed: map[string]string{}}
	k0 := map[string][]byte{}
	for _, k := range keys {
		k0[SealKeyID(k)] = k
	}
	chains := map[string]*sealChain{}
	keyAt := func(c *sealChain, id string, epoch uint64) []byte {
		if c.key == nil || c.epoch > epoch {
			c.key, c.epoch = k0[id], 0
		}
		for c.epoch < epoch {
			c.key = evolveKey(c.key)
			c.epoch++
		}
		return c.key
	}
	sum := sha256.New()
	lines := 0
	pending := map[string]string{} // file lines since the last seal
	seen := false
	for _, p := range logs {
		f, err := os.Open(p)
		if err != nil {
			r.Bad = append(r.Bad, fmt.Sprintf("%s: %v", filepath.Base(p), err))
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			line := sc.Text()
			s, ok := parseSeal(line)
			if !ok {
				sum.Write(append(sc.Bytes(), '\n'))
				lines++
				if path, what, ok := fileLine(line); ok {
					pending[path] = what
				} else if strings.HasPrefix(line, "unsealed ") {
					r.Unsealed = append(r.Unsealed, line)
				}
				continue
			}
			at := time.UnixMilli(s.ms).UTC().Format("2006-01-02 15:04:05 UTC")
			seen = true
			if _, known := k0[s.keyID]; !known {
				r.Bad = append(r.Bad, fmt.Sprintf("seal %s/%d at %s: no verification key for chain %s", s.keyID, s.epoch, at, s.keyID))
			} else {
				c := chains[s.keyID]
				if c == nil {
					c = &sealChain{}
					chains[s.keyID] = c
				}
				prev := c.last
				switch {
				case prev == nil:
					r.StartEpoch[s.keyID] = s.epoch
					r.Chains = append(r.Chains, s.keyID)
				case s.epoch != prev.epoch+1:
					r.Bad = append(r.Bad, fmt.Sprintf("seal %s/%d at %s follows epoch %d: seals were removed or reordered", s.keyID, s.epoch, at, prev.epoch))
				case s.prev != prev.tag:
					r.Bad = append(r.Bad, fmt.Sprintf("seal %s/%d at %s does not follow seal %d: the chain was altered", s.keyID, s.epoch, at, prev.epoch))
				}
				if s.lines != lines || s.mac(keyAt(c, s.keyID, s.epoch), sum.Sum(nil)) != s.tag {
					r.Bad = append(r.Bad, fmt.Sprintf("seal %s/%d at %s does not verify: the %d lines before it were changed, added or removed (it sealed %d)", s.keyID, s.epoch, at, lines, s.lines))
				} else {
					r.Seals++
					if r.First == 0 {
						r.First = s.ms
					}
					r.Last = s.ms
					for k, v := range pending {
						r.Sealed[k] = v
					}
					switch s.flag {
					case "start":
						r.Starts = append(r.Starts, s.ms)
					case "end":
						r.Ends = append(r.Ends, s.ms)
					case "late":
						r.Late = append(r.Late, s.ms)
					}
				}
				c.last = &s
			}
			sum.Reset()
			lines = 0
			clear(pending)
		}
		f.Close()
	}
	if seen {
		r.After = lines
	} else {
		r.Unsealed = append(r.Unsealed, fmt.Sprintf("no seal in the logs (%d lines)", lines))
	}
	return r
}

// sealChain is the verifier's state of one chain: the last key derived
// and the last seal seen.
type sealChain struct {
	epoch uint64
	key   []byte
	last  *sealRec
}

// fileLine parses a file line of the log: "SHA SIZE PATH" (written) or
// "del REASON PATH" (removed by the store). what is "SHA SIZE" or
// "del REASON".
func fileLine(line string) (path, what string, ok bool) {
	f := strings.SplitN(line, " ", 3)
	if len(f) != 3 {
		return "", "", false
	}
	if f[0] == "del" {
		return f[2], "del " + f[1], true
	}
	if len(f[0]) != 64 {
		return "", "", false
	}
	if _, err := strconv.ParseInt(f[1], 10, 64); err != nil {
		return "", "", false
	}
	return f[2], f[0] + " " + f[1], true
}
