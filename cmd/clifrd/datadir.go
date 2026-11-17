package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// checkDataDir refuses a data directory another user could tamper with
// while clifrd writes, renames and deletes in it as root: one that user
// created (in /tmp, say), or one below a directory they can write. Such a
// user could swap a table or day directory for a symlink and have root create
// files elsewhere. Every existing component of the path, as given and with
// symlinks resolved, must be owned by root or by the user who ran sudo
// (SUDO_UID: bench and test runs keep their data in their own home), and none
// may be writable by group or others, except a sticky directory above the
// data directory (/tmp: others cannot rename or replace what they do not
// own). Not run as root, clifrd can only touch its own user's files: no check.
func checkDataDir(dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	allowed := map[uint32]bool{0: true}
	if u, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32); err == nil {
		allowed[uint32(u)] = true
	}
	return checkDataDirOwners(dir, allowed)
}

func checkDataDirOwners(dir string, allowed map[uint32]bool) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := checkPathOwners(abs, abs, allowed); err != nil {
		return err
	}
	// The same with symlinks resolved, up to the deepest part that exists
	// (clifrd creates the rest, as root).
	existing := abs
	for {
		if _, err := os.Lstat(existing); err == nil || existing == "/" {
			break
		}
		existing = filepath.Dir(existing)
	}
	real, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return fmt.Errorf("--data-dir %s: %w", dir, err)
	}
	if real != existing {
		return checkPathOwners(real, real, allowed)
	}
	return nil
}

// checkPathOwners checks each existing component of p from / down
// (symlinks themselves, not their targets); last is the data directory.
func checkPathOwners(p, last string, allowed map[uint32]bool) error {
	var parts []string
	for q := p; ; q = filepath.Dir(q) {
		parts = append(parts, q)
		if q == "/" || q == "." {
			break
		}
	}
	for i := len(parts) - 1; i >= 0; i-- {
		q := parts[i]
		fi, err := os.Lstat(q)
		if errors.Is(err, fs.ErrNotExist) {
			return nil // created by clifrd from here on
		}
		if err != nil {
			return fmt.Errorf("--data-dir %s: %w", last, err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if !allowed[st.Uid] {
			return fmt.Errorf("--data-dir %s: %s belongs to uid %d, not root: another user could redirect what clifrd writes and deletes there as root (use a directory owned by root, e.g. one made with sudo mktemp -d)", last, q, st.Uid)
		}
		if fi.Mode()&fs.ModeSymlink == 0 && fi.Mode().Perm()&0o022 != 0 && (q == last || fi.Mode()&fs.ModeSticky == 0) {
			return fmt.Errorf("--data-dir %s: %s is writable by group or others (%v): another user could redirect what clifrd writes and deletes there as root", last, q, fi.Mode().Perm())
		}
	}
	return nil
}
