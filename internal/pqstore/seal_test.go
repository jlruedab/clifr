package pqstore

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"clifr/internal/store"
)

// sealStore opens a store whose warnings go to the returned buffer.
func sealStore(t *testing.T, dir string) (*Store, *logBuf) {
	t.Helper()
	lb := &logBuf{}
	s, err := Open(dir, Options{FlushInterval: time.Hour, Logf: lb.logf})
	if err != nil {
		t.Fatal(err)
	}
	return s, lb
}

type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuf) logf(f string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.b, f+"\n", a...)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

var sealTS int64 = 1000

func sealWrite(t *testing.T, s *Store) {
	t.Helper()
	sealTS++
	s.Write(&store.Batch{Sample: store.Sample{TS: sealTS},
		ProcInserts: []store.ProcRow{{ID: sealTS, PID: int(sealTS), StartTime: 1, Comm: "x", FirstSeen: sealTS}}})
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
}

func mustKey(t *testing.T, v string) []byte {
	t.Helper()
	k, err := ParseVerifyKey(v)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func logText(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	for _, p := range integrityLogFiles(dir) {
		x, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(x)
	}
	return b.String()
}

// TestSealChain: a sealed recording over two runs, with compaction, verifies
// with its key and with nothing left over; another key does not verify it;
// seal.state holds only the current key, never k0 or an earlier one.
func TestSealChain(t *testing.T) {
	dir := t.TempDir()
	vk, id, err := SealSetup(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := SealSetup(dir, false); err == nil {
		t.Error("a second setup without --new was accepted")
	}
	k0 := mustKey(t, vk)
	if SealKeyID(k0) != id {
		t.Fatalf("key id %s, want %s", SealKeyID(k0), id)
	}
	for run := range 2 {
		s, _ := sealStore(t, dir)
		for range 3 {
			sealWrite(t, s)
		}
		// Merge this hour's parts: their removals are logged and sealed.
		// (Compacting the current hour is a test's shortcut: the parts the
		// next writes make in it are removed as merged at the next Open, by
		// recover, which logs that too.)
		if err := s.compact(time.Now().UTC().Truncate(time.Hour).Add(2*time.Hour), func() {}); err != nil {
			t.Fatal(err)
		}
		sealWrite(t, s)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if run == 0 {
			time.Sleep(1100 * time.Millisecond) // the next run's id (Unix s) differs
		}
	}
	r := VerifySeals(dir, [][]byte{k0})
	if len(r.Bad) != 0 || r.Seals < 10 || r.After != 0 || len(r.Starts) != 2 || len(r.Ends) != 2 ||
		len(r.Late) != 0 || len(r.Unsealed) != 0 || r.StartEpoch[id] != 1 {
		t.Fatalf("clean chain: %+v\n%s", r, logText(t, dir))
	}
	var dels int
	for p, w := range r.Sealed {
		if w.What == "del compacted" {
			dels++
			if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
				t.Errorf("%s: sealed as compacted, still there", p)
			}
		}
	}
	if dels == 0 {
		t.Errorf("no compacted removal sealed: %v", r.Sealed)
	}
	if c := CheckIntegrity(dir); len(c.Damaged) != 0 || c.Unlogged != 0 {
		t.Errorf("integrity: %+v", c)
	}
	other := make([]byte, 32)
	if r := VerifySeals(dir, [][]byte{other}); r.Seals != 0 || len(r.Bad) == 0 || !strings.Contains(r.Bad[0], "no verification key") {
		t.Errorf("another key: %+v", r)
	}
	// Only the current key is on disk.
	state, _ := os.ReadFile(sealStatePath(dir))
	st, _, err := readSealState(dir)
	if err != nil {
		t.Fatal(err)
	}
	k := k0
	for e := uint64(0); e < st.epoch; e++ {
		if strings.Contains(string(state), hex.EncodeToString(k)) {
			t.Errorf("seal.state holds k%d (current epoch %d)", e, st.epoch)
		}
		k = evolveKey(k)
	}
	if !strings.Contains(string(state), hex.EncodeToString(k)) {
		t.Errorf("seal.state lacks the current key k%d", st.epoch)
	}
}

// TestSealTamper: an edited file line, a removed seal, reordered seals and
// an older seal.state are all found.
func TestSealTamper(t *testing.T) {
	setup := func(t *testing.T) (string, []byte) {
		dir := t.TempDir()
		vk, _, err := SealSetup(dir, false)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := sealStore(t, dir)
		for range 4 {
			sealWrite(t, s)
		}
		s.Close()
		return dir, mustKey(t, vk)
	}
	edit := func(t *testing.T, dir string, f func(lines []string) []string) {
		logs := integrityLogFiles(dir)
		p := logs[len(logs)-1]
		b, _ := os.ReadFile(p)
		lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		if err := os.WriteFile(p, []byte(strings.Join(f(lines), "\n")+"\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	seals := func(lines []string) []int {
		var out []int
		for i, l := range lines {
			if strings.HasPrefix(l, "seal ") {
				out = append(out, i)
			}
		}
		return out
	}
	t.Run("file line", func(t *testing.T) {
		dir, k := setup(t)
		edit(t, dir, func(l []string) []string {
			i := seals(l)[1] - 1 // a file line of the second epoch
			l[i] = strings.Repeat("0", 64) + l[i][64:]
			return l
		})
		if r := VerifySeals(dir, [][]byte{k}); len(r.Bad) != 1 || !strings.Contains(r.Bad[0], "does not verify") {
			t.Errorf("%+v", r.Bad)
		}
	})
	t.Run("line removed", func(t *testing.T) {
		dir, k := setup(t)
		edit(t, dir, func(l []string) []string {
			i := seals(l)[1] - 1
			return append(l[:i:i], l[i+1:]...)
		})
		if r := VerifySeals(dir, [][]byte{k}); len(r.Bad) != 1 || !strings.Contains(r.Bad[0], "does not verify") {
			t.Errorf("%+v", r.Bad)
		}
	})
	t.Run("seal removed", func(t *testing.T) {
		dir, k := setup(t)
		edit(t, dir, func(l []string) []string {
			i := seals(l)[1]
			return append(l[:i:i], l[i+1:]...)
		})
		r := VerifySeals(dir, [][]byte{k})
		if len(r.Bad) == 0 || !strings.Contains(strings.Join(r.Bad, "\n"), "removed or reordered") {
			t.Errorf("%+v", r.Bad)
		}
	})
	t.Run("epochs reordered", func(t *testing.T) {
		dir, k := setup(t)
		edit(t, dir, func(l []string) []string {
			s := seals(l)
			a := append([]string{}, l[s[0]+1:s[1]+1]...)
			b := append([]string{}, l[s[1]+1:s[2]+1]...)
			out := append(append(append(append([]string{}, l[:s[0]+1]...), b...), a...), l[s[2]+1:]...)
			return out
		})
		if r := VerifySeals(dir, [][]byte{k}); len(r.Bad) == 0 {
			t.Errorf("reordered epochs verified: %+v", r)
		}
	})
	t.Run("forged with a later key", func(t *testing.T) {
		// Root at C holds seal.state's key: a changed earlier epoch, resealed
		// with it, does not verify.
		dir, k := setup(t)
		st, _, _ := readSealState(dir)
		edit(t, dir, func(l []string) []string {
			s := seals(l)
			i := s[1] - 1
			l[i] = strings.Repeat("0", 64) + l[i][64:]
			r, _ := parseSeal(l[s[1]])
			sum := sha256Lines(l[s[0]+1 : s[1]])
			r.tag = r.mac(st.key, sum)
			l[s[1]] = r.line()
			return l
		})
		if r := VerifySeals(dir, [][]byte{k}); len(r.Bad) == 0 {
			t.Errorf("forged seal verified: %+v", r)
		}
	})
}

// TestSealCrash: lines a crash left unsealed are sealed "late" at the next
// start; a crash between a seal line and the key update is finished.
func TestSealCrash(t *testing.T) {
	dir := t.TempDir()
	vk, _, _ := SealSetup(dir, false)
	k := mustKey(t, vk)
	s, _ := sealStore(t, dir)
	sealWrite(t, s)
	// A crash after a flush's files are logged, before its seal.
	before, _ := os.ReadFile(sealStatePath(dir))
	p := filepath.Join(dir, "extra.parquet")
	os.WriteFile(p, []byte("x"), 0o640)
	s.logFile(p)
	s.ilog.close()
	s.cancel()
	s.wg.Wait()

	s, _ = sealStore(t, dir)
	sealWrite(t, s)
	// A crash between a seal line and the key update: seal.state as before
	// that seal.
	before, _ = os.ReadFile(sealStatePath(dir))
	sealWrite(t, s)
	s.ilog.close()
	s.cancel()
	s.wg.Wait()
	os.WriteFile(sealStatePath(dir), before, 0o600)

	s, _ = sealStore(t, dir)
	sealWrite(t, s)
	s.Close()
	r := VerifySeals(dir, [][]byte{k})
	if len(r.Bad) != 0 || len(r.Late) != 1 || r.After != 0 || len(r.Ends) != 1 || len(r.Starts) != 3 {
		t.Fatalf("%+v", r)
	}
}

// TestSealLost: without seal.state, a sealed recording is marked
// "unsealed" once, warned about, and not sealed again until a new setup;
// a setup while clifrd runs starts sealing at the next flush.
func TestSealLost(t *testing.T) {
	dir := t.TempDir()
	s, _ := sealStore(t, dir)
	sealWrite(t, s)
	vk, _, _ := SealSetup(dir, false) // while it runs
	sealWrite(t, s)
	s.Close()
	k := mustKey(t, vk)
	r := VerifySeals(dir, [][]byte{k})
	if len(r.Bad) != 0 || r.Seals < 2 || len(r.Starts) != 1 {
		t.Fatalf("setup while running: %+v", r)
	}

	os.Remove(sealStatePath(dir))
	s, lb := sealStore(t, dir)
	sealWrite(t, s)
	sealWrite(t, s)
	s.Close()
	if n := strings.Count(logText(t, dir), "unsealed state-missing"); n != 1 {
		t.Errorf("%d unsealed lines, want 1", n)
	}
	if !strings.Contains(lb.String(), "no longer sealed") || strings.Count(lb.String(), "no longer sealed") != 1 {
		t.Errorf("warnings: %q", lb.String())
	}
	r = VerifySeals(dir, [][]byte{k})
	if len(r.Bad) != 0 || len(r.Unsealed) != 1 || r.After == 0 {
		t.Fatalf("lost: %+v", r)
	}

	vk2, id2, err := SealSetup(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	s, _ = sealStore(t, dir)
	sealWrite(t, s)
	s.Close()
	r = VerifySeals(dir, [][]byte{k, mustKey(t, vk2)})
	if len(r.Bad) != 0 || len(r.Chains) != 2 || r.Chains[1] != id2 || r.After != 0 {
		t.Fatalf("new chain: %+v", r)
	}
	os.WriteFile(sealStatePath(dir), []byte("garbage"), 0o600)
	if _, _, err := SealSetup(dir, false); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("setup over a damaged state: %v", err)
	}
	if _, _, err := SealSetup(dir, true); err != nil {
		t.Errorf("--new over a damaged state: %v", err)
	}
}

// TestSealTornLine: a torn last log line (a crash while appending) is ended
// at the next start, so the next line is not glued to it.
func TestSealTornLine(t *testing.T) {
	dir := t.TempDir()
	vk, _, _ := SealSetup(dir, false)
	s, _ := sealStore(t, dir)
	sealWrite(t, s)
	s.Close()
	logs := integrityLogFiles(dir)
	f, _ := os.OpenFile(logs[len(logs)-1], os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString("0123abc")
	f.Close()
	s, _ = sealStore(t, dir)
	sealWrite(t, s)
	s.Close()
	r := VerifySeals(dir, [][]byte{mustKey(t, vk)})
	if len(r.Bad) != 0 || len(r.Late) != 1 {
		t.Fatalf("%+v", r)
	}
	if c := CheckIntegrity(dir); len(c.Damaged) != 0 {
		t.Errorf("%+v", c)
	}
}

func sha256Lines(lines []string) []byte {
	h := newIntegrityLog("", nil).sum
	for _, l := range lines {
		h.Write([]byte(l + "\n"))
	}
	return h.Sum(nil)
}

// TestSealAnchor: the first seal of a run is logged as an anchor at info
// level, then at most hourly; the anchor names a seal of the log.
func TestSealAnchor(t *testing.T) {
	dir := t.TempDir()
	SealSetup(dir, false)
	info := &logBuf{}
	s, err := Open(dir, Options{FlushInterval: time.Hour, Infof: info.logf})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		sealWrite(t, s)
	}
	s.Close()
	got := info.String()
	if strings.Count(got, "seal anchor ") != 1 {
		t.Fatalf("anchors: %q", got)
	}
	a := strings.Fields(strings.SplitN(got, "seal anchor ", 2)[1])[0]
	id, rest, _ := strings.Cut(a, "/")
	epoch, tag, _ := strings.Cut(rest, ":")
	if !strings.Contains(logText(t, dir), "seal "+id+" "+epoch+" ") || !strings.Contains(logText(t, dir), " "+tag) || epoch != "1" {
		t.Errorf("anchor %s names no seal of the log", a)
	}
}
