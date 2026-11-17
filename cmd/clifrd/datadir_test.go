package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckDataDir: as root, a data directory another user owns, or one
// writable by others, is refused; the sudo user's own is accepted; a symlink
// to a good directory is judged by its own owner and by where it leads.
func TestCheckDataDir(t *testing.T) {
	me := uint32(os.Getuid())
	if me == 0 {
		t.Skip("needs a non-root user to play the other user")
	}
	base := t.TempDir() // below /tmp: root's, sticky; then ours
	good := filepath.Join(base, "good")
	os.Mkdir(good, 0o750)
	open := filepath.Join(base, "open")
	os.Mkdir(open, 0o750)
	os.Chmod(open, 0o777)
	link := filepath.Join(base, "link")
	os.Symlink(good, link)
	for _, c := range []struct {
		dir     string
		allowed map[uint32]bool
		want    string // "" = accepted
	}{
		{good, map[uint32]bool{0: true}, "belongs to uid"},                           // another user's (ours, seen as root)
		{good, map[uint32]bool{0: true, me: true}, ""},                               // the sudo user's own
		{filepath.Join(good, "new", "data"), map[uint32]bool{0: true, me: true}, ""}, // created later by clifrd
		{open, map[uint32]bool{0: true, me: true}, "writable by group or others"},
		{filepath.Join(open, "data"), map[uint32]bool{0: true, me: true}, "writable by group or others"},
		{link, map[uint32]bool{0: true}, "belongs to uid"},
		{link, map[uint32]bool{0: true, me: true}, ""},
	} {
		err := checkDataDirOwners(c.dir, c.allowed)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s %v: %v", c.dir, c.allowed, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s %v: got %v, want %q", c.dir, c.allowed, err, c.want)
		}
	}
}
