package recorder

import (
	"strings"

	"golang.org/x/sys/unix"

	"sosv/internal/procfs"
	"sosv/internal/store"
)

type fileKey struct {
	fd     int
	target string
}

type fileEntry struct {
	id   int64
	gen  uint64
	last int64
}

// sockNames holds lsof names for non-inet sockets, read once per full walk.
type sockNames struct {
	unix, netlink map[uint64]string
}

// walkFDs reads /proc/<pid>/fd. With all=false it only walks processes that
// held inet sockets at their last walk and processes first seen in this
// sample, and only looks at socket fds (ownership). With all=true it walks
// every process and also records open files. It returns the number of fds read.
func (r *Recorder) walkFDs(ts int64, all bool, b *store.Batch) int {
	var names sockNames
	if all {
		names.unix, _ = r.fs.ReadNetUnix()
		names.netlink, _ = r.fs.ReadNetNetlink()
	}
	nfd := 0
	for _, p := range r.procs {
		if p.closed || !(all || p.owns || p.born == r.gen) {
			continue
		}
		fds, err := r.fs.ReadFDs(p.key.pid, !all)
		if err != nil {
			continue // vanished or not permitted; entries are kept until the process closes
		}
		nfd += len(fds)
		r.observeOwners(p, fds, ts, b)
		if all {
			fds = append(fds, r.fs.ReadSpecialLinks(p.key.pid)...)
			r.observeFiles(p, fds, ts, names, b)
		}
	}
	return nfd
}

// observeFiles records one fully walked process's open files. Inet sockets
// are skipped: sock_owners already tracks them every interval.
func (r *Recorder) observeFiles(p *procEntry, fds []procfs.FD, ts int64, names sockNames, b *store.Batch) {
	if p.files == nil {
		p.files = map[fileKey]*fileEntry{}
	}
	for _, fd := range fds {
		if ino, ok := procfs.SocketInode(fd.Target); ok && r.byInode[ino] != nil {
			continue
		}
		k := fileKey{fd: fd.Num, target: fd.Target}
		e := p.files[k]
		if e == nil {
			e = &fileEntry{id: r.nextID("open_files")}
			p.files[k] = e
			row := store.FileRow{ID: e.id, ProcID: p.id, FD: fd.Num, Target: fd.Target,
				Deleted: strings.HasSuffix(fd.Target, " (deleted)"), FirstSeen: ts}
			var flags uint64
			hasFlags := false
			var st *procfs.FDStat
			if fd.Num >= 0 {
				if f, err := r.fs.ReadFDFlags(p.key.pid, fd.Num); err == nil {
					flags, hasFlags = f, true
				}
				if x, err := r.fs.StatFD(p.key.pid, fd.Num); err == nil {
					st = &x
					row.Node = int64(x.Inode)
				}
			}
			row.FType, row.Mode, row.Name = classifyFD(fd, flags, hasFlags, st, names)
			b.FileInserts = append(b.FileInserts, row)
		}
		e.gen, e.last = r.gen, ts
	}
	for k, e := range p.files {
		if e.gen != r.gen {
			b.FileCloses = append(b.FileCloses, store.Close{ID: e.id, LastSeen: e.last})
			delete(p.files, k)
		}
	}
}

// closeFiles closes all open-file rows of a process that ended.
func closeFiles(p *procEntry, b *store.Batch) {
	for _, e := range p.files {
		b.FileCloses = append(b.FileCloses, store.Close{ID: e.id, LastSeen: e.last})
	}
	p.files = nil
}

const (
	oDirectory = 0o200000
	oPath      = 0o10000000
	oAccMode   = 0o3
)

// classifyFD derives lsof's TYPE, FD mode letter and NAME (when it differs
// from the link target). st may be nil if statx failed.
func classifyFD(fd procfs.FD, flags uint64, hasFlags bool, st *procfs.FDStat, names sockNames) (ftype, mode, name string) {
	switch fd.Num {
	case procfs.FDCwd, procfs.FDRtd:
		return "DIR", "", ""
	case procfs.FDTxt:
		return "REG", "", ""
	}
	if hasFlags {
		mode = [...]string{"r", "w", "u", "u"}[flags&oAccMode]
		if flags&oPath != 0 {
			mode = "u" // what lsof shows for O_PATH descriptors
		}
	}
	t := fd.Target
	switch {
	case strings.HasPrefix(t, "socket:["):
		ino, _ := procfs.SocketInode(t)
		if n, ok := names.unix[ino]; ok {
			return "unix", mode, n
		}
		if n, ok := names.netlink[ino]; ok {
			return "netlink", mode, n
		}
		return "sock", mode, ""
	case strings.HasPrefix(t, "pipe:["):
		return "FIFO", mode, "pipe"
	case strings.HasPrefix(t, "anon_inode:"):
		return "a_inode", mode, strings.TrimPrefix(t, "anon_inode:")
	case st != nil:
		switch st.Mode {
		case unix.S_IFREG:
			return "REG", mode, ""
		case unix.S_IFDIR:
			return "DIR", mode, ""
		case unix.S_IFCHR:
			return "CHR", mode, ""
		case unix.S_IFBLK:
			return "BLK", mode, ""
		case unix.S_IFIFO:
			return "FIFO", mode, ""
		}
	case strings.HasPrefix(t, "/dev/") && !strings.HasPrefix(t, "/dev/shm/") && !strings.HasPrefix(t, "/dev/mqueue/"):
		return "CHR", mode, ""
	case hasFlags && flags&oDirectory != 0:
		return "DIR", mode, ""
	case strings.HasPrefix(t, "/"):
		return "REG", mode, ""
	}
	return "unknown", mode, "" // e.g. net:[...], mnt:[...]
}
