package pqstore

import (
	"path/filepath"
	"testing"
	"time"

	"clifr/internal/store"
)

func sampleFiles(dir string) int {
	m, _ := filepath.Glob(filepath.Join(dir, Dir("samples"), "*", "*.parquet"))
	return len(m)
}

// TestEarlyFlush: an OOM kill, a serious kernel message or RequestFlush
// flushes at the next sample once the last flush is EarlyFlush old; nothing
// else does before FlushInterval, and a kernel message older than the store
// (the buffer read again at start) does not count.
func TestEarlyFlush(t *testing.T) {
	ts := time.Now().UnixMilli()
	sample := func(b store.Batch) *store.Batch { b.Sample = store.Sample{TS: ts}; ts += 1000; return &b }
	for _, c := range []struct {
		name  string
		b     store.Batch
		req   string
		early bool
	}{
		{"nothing", store.Batch{}, "", false},
		{"oom", store.Batch{OOMEvents: []store.OOMEvent{{TS: ts}}}, "", true},
		{"crit", store.Batch{Kmsg: []store.KmsgRow{{Kind: "msg", Prio: 2, MonoUS: 1 << 62, Msg: "BUG: soft lockup"}}}, "", true},
		{"hung task", store.Batch{Kmsg: []store.KmsgRow{{Kind: "msg", Prio: 3, MonoUS: 1 << 62, Msg: "INFO: task nfsd:123 blocked for more than 122 seconds."}}}, "", true},
		{"ordinary error", store.Batch{Kmsg: []store.KmsgRow{{Kind: "msg", Prio: 3, MonoUS: 1 << 62, Msg: "usb 1-1: device descriptor read/64, error -71"}}}, "", false},
		{"info with a pattern", store.Batch{Kmsg: []store.KmsgRow{{Kind: "msg", Prio: 6, MonoUS: 1 << 62, Msg: "I/O error test passed"}}}, "", false},
		{"replayed at start", store.Batch{Kmsg: []store.KmsgRow{{Kind: "msg", Prio: 0, MonoUS: 1, Msg: "Kernel panic"}}}, "", false},
		{"SIGUSR1", store.Batch{}, "SIGUSR1", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir, Options{EarlyFlush: 30 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if c.req != "" {
				s.RequestFlush(c.req)
			}
			// Too soon after the last flush: held, not lost.
			if err := s.Write(sample(c.b)); err != nil {
				t.Fatal(err)
			}
			if n := sampleFiles(dir); n != 0 {
				t.Fatalf("flushed %d files right after the last flush", n)
			}
			s.lastFlush = time.Now().Add(-31 * time.Second)
			if err := s.Write(sample(store.Batch{})); err != nil {
				t.Fatal(err)
			}
			if got := sampleFiles(dir) > 0; got != c.early {
				t.Errorf("early flush %v, want %v", got, c.early)
			}
			if s.early != "" && c.early {
				t.Errorf("reason %q kept after the flush", s.early)
			}
		})
	}
}

// TestEarlyFlushOff: EarlyFlush 0 never flushes early.
func TestEarlyFlushOff(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.lastFlush = time.Now().Add(-time.Minute)
	s.RequestFlush("test")
	if err := s.Write(&store.Batch{Sample: store.Sample{TS: time.Now().UnixMilli()}, OOMEvents: []store.OOMEvent{{}}}); err != nil {
		t.Fatal(err)
	}
	if n := sampleFiles(dir); n != 0 {
		t.Errorf("flushed %d files with EarlyFlush off", n)
	}
}
