package recorder

import (
	"io"
	"log"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/procfs"
)

// TestStatfsStuck: a mount whose statfs hangs (a dead NFS server) is marked
// stuck after statfsWait, skipped while its call hangs, and the other mounts
// are still measured; when the call returns, its row and statfs_ok come.
func TestStatfsStuck(t *testing.T) {
	release := make(chan struct{})
	var hungCalls atomic.Int32
	oldWait, oldStatfs := statfsWait, statfs
	statfsWait, statfs = 50*time.Millisecond, func(path string, st *unix.Statfs_t) error {
		if strings.HasSuffix(path, "/hung") {
			hungCalls.Add(1)
			<-release
		}
		st.Frsize, st.Blocks, st.Bfree, st.Bavail = 4096, 1000, 500, 400
		if strings.HasSuffix(path, "/data") {
			st.Bfree = int64ToU(time.Now().UnixNano() % 100) // changes every call
		}
		return nil
	}
	defer func() { statfsWait, statfs = oldWait, oldStatfs }()

	mounts := []procfs.MountInfo{
		{ID: 1, Dev: "8:1", Point: "/", FSType: "ext4", Source: "/dev/sda1"},
		{ID: 2, Dev: "0:50", Point: "/hung", FSType: "nfs4", Source: "srv:/x"},
		{ID: 3, Dev: "8:2", Point: "/data", FSType: "xfs", Source: "/dev/sda2"},
	}
	var u fsUsage
	lg := NewLogger(log.New(io.Discard, "", 0), LevelDebug)
	wait := func() {
		t.Helper()
		for i := 0; i < 200; i++ {
			u.mu.Lock()
			busy := u.busy
			u.mu.Unlock()
			if !busy {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("round did not finish: one hung mount stalled it")
	}
	ids := func() map[int]int {
		m := map[int]int{}
		for _, s := range u.take() {
			m[s.MountID]++
		}
		return m
	}

	u.start(1000, mounts, lg)
	wait()
	if got := ids(); got[1] != 1 || got[3] != 1 || got[2] != 0 {
		t.Fatalf("first round rows by mount = %v, want 1 and 3 only", got)
	}
	g := u.takeGuard()
	if len(g) != 1 || g[0].Kind != "statfs_stuck" || !strings.HasPrefix(g[0].Detail, "/hung: statfs not answering") {
		t.Fatalf("guard events = %+v, want one statfs_stuck for /hung", g)
	}

	u.start(2000, mounts, lg)
	wait()
	if got := ids(); got[3] != 1 || got[2] != 0 {
		t.Fatalf("second round rows by mount = %v, want /data again and no /hung", got)
	}
	if n := hungCalls.Load(); n != 1 {
		t.Fatalf("statfs of the stuck mount called %d times, want 1 (skipped while it hangs)", n)
	}

	close(release)
	var ok bool
	for i := 0; i < 200 && !ok; i++ {
		time.Sleep(5 * time.Millisecond)
		u.mu.Lock()
		_, still := u.stuck[fsKey{2, "0:50", "/hung"}]
		u.mu.Unlock()
		ok = !still
	}
	if !ok {
		t.Fatal("stuck mark not cleared after the call returned")
	}
	if got := ids(); got[2] != 1 {
		t.Fatalf("rows after the call returned = %v, want the /hung row", got)
	}
	if g := u.takeGuard(); len(g) != 1 || g[0].Kind != "statfs_ok" || !strings.HasPrefix(g[0].Detail, "/hung: statfs answered after") {
		t.Fatalf("guard events = %+v, want statfs_ok for /hung", g)
	}
	u.start(3000, mounts, lg)
	wait()
	if n := hungCalls.Load(); n != 2 {
		t.Fatalf("statfs of the recovered mount called %d times in all, want 2", n)
	}
}

func int64ToU(n int64) uint64 { return uint64(n) }
