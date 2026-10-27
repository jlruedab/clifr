package recorder

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestStatLockFD(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locked")
	if err := os.WriteFile(path, make([]byte, 1234), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var want syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &want); err != nil {
		t.Fatal(err)
	}
	pid, fd := strconv.Itoa(os.Getpid()), strconv.Itoa(int(f.Fd()))
	st, err := statLockFD(pid, fd)
	if err != nil || st.Inode != want.Ino || st.Size != 1234 {
		t.Fatalf("statLockFD: %+v, %v; want inode %d, size 1234", st, err, want.Ino)
	}
	if sz, ok := lockFileSize(pid, fd, want.Ino); !ok || sz != 1234 {
		t.Errorf("lockFileSize: %d, %v", sz, ok)
	}
	if lf, sz, ok := findLockFile(pid, want.Ino); !ok || lf.path != path || sz != 1234 {
		t.Errorf("findLockFile: %+v, %d, %v", lf, sz, ok)
	}
	if _, err := statLockFD(pid, "x"); err == nil {
		t.Error("statLockFD with a bad fd: no error")
	}
}
