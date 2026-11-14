package pqstore

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// A file written to a temporary name, fsynced and renamed has its data on
// disk, but the rename itself is a change to the directory: until the
// directory is fsynced, a power loss can leave the old name (or none). Its
// order against later changes is not guaranteed either: compaction deletes
// an hour's parts after renaming the merged file, and without a directory
// sync the deletes could reach the disk and the rename not, losing the hour.

// onDirSync is called before each directory sync (tests).
var onDirSync func(dir string)

// SyncDir fsyncs a directory, making the renames, creations and deletions in
// it durable.
func SyncDir(dir string) error {
	if onDirSync != nil {
		onDirSync(dir)
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// RenameDurable renames from to to and fsyncs to's directory (and from's,
// when it is another one).
func RenameDurable(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	err := SyncDir(filepath.Dir(to))
	if fd := filepath.Dir(from); fd != filepath.Dir(to) {
		err = errors.Join(err, SyncDir(fd))
	}
	return err
}

// mkdirDurable is os.MkdirAll that also fsyncs the parent of every
// directory it creates, so a new day directory cannot vanish with the files
// renamed into it.
func mkdirDurable(dir string, perm fs.FileMode) error {
	var created []string
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		created = append(created, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	if len(created) == 0 {
		return nil
	}
	if err := os.MkdirAll(dir, perm); err != nil {
		return err
	}
	var errs []error
	for _, d := range created { // deepest first; each parent once
		errs = append(errs, SyncDir(filepath.Dir(d)))
	}
	return errors.Join(errs...)
}
