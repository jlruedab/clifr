package recorder

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

type fileKey struct {
	fd     int
	target string
}

func (k fileKey) procFD() procfs.FD { return procfs.FD{Num: k.fd, Target: k.target} }

// fileEntry has no pointers (the target is the key's). The map holds
// pointers to entries, so updating one never reassigns its key: that would
// replace the stored target string with the one just read, and the held-fd
// row would keep the old one.
type fileEntry struct {
	id    int64 // row id; held mode: 0 until stored
	gen   uint64
	first int64 // walk that first saw it
	last  int64 // last walk that saw it
	walks int   // consecutive walks of its process that saw it
}

// sockNames holds lsof names for non-inet sockets, read once per full walk.
type sockNames struct {
	unix, netlink map[uint64]string
}

// heldMode: v2 stores only fds held across two consecutive walks of their
// process (and deleted files at once) in fds_held; "all" is v1 (open_files).
func (r *Recorder) heldMode() bool { return r.cfg.FDMode != "all" }

// walkCheckFDs: the memory guard runs during an open-file walk every this
// many fds read (a heap reading: microseconds).
var walkCheckFDs = 64 << 10

// maxNewHeldPerWalk: new held files recorded in one walk at most; the rest
// on the next ones. A variable for tests.
var maxNewHeldPerWalk = 200_000

// walkFDs reads /proc/<pid>/fd. With all=false it only walks processes that
// held inet sockets at their last walk and processes first seen in this
// sample, and only looks at socket fds (v1 ownership). With all=true it
// walks every process and records open files. In held mode a process whose
// fd count (the size of /proc/<pid>/fd) did not change since its last walk
// is presumed unchanged and not read, except on every FDFullEvery-th walk.
// It returns the number of fds read.
func (r *Recorder) walkFDs(ts int64, all bool, b *store.Batch) int {
	var names sockNames
	if all {
		names.unix, _ = r.fs.ReadNetUnix()
		names.netlink, _ = r.fs.ReadNetNetlink()
	}
	nfd := 0
	if all && r.tcp != nil {
		r.tcp.holders = map[uint64]holder{} // rebuilt by observeFiles
	}
	full := true
	if all && r.tcp != nil {
		r.tcp.markQueued()
	}
	if all {
		r.walkNewHeld, r.walkHeldDeferred = 0, 0
	}
	if all && r.heldMode() {
		r.fdWalks++
		every := r.cfg.FDFullEvery
		full = every <= 1 || r.fdWalks%uint64(every) == 1
	}
	walked, presumed := 0, 0
	checked, refused := 0, 0 // work at the last memory check; processes refused this walk
	var refusedTop string
	work := 0 // fds read plus entries presumed unchanged: what the walk costs
	capped, cappedMax := 0, 0
	var cappedTop string
	// overCap stops tracking a process holding more open files than
	// --max-files-per-process: one such process costs about 200 bytes per
	// entry, 100 MB for the half million an unprivileged user may hold
	// (attack test, 2026-11-10). Its TCP connections and owners come from
	// the events; it stays untracked until it exits.
	// refuse untracks a process holding many files while the guard sheds
	// and the heap is still above it.
	refuse := func(p *procEntry) bool {
		if p.noFiles || !r.memShed || r.cfg.MemoryGuard <= 0 || r.heapNow() <= uint64(r.cfg.MemoryGuard) {
			return false
		}
		if refused == 0 {
			refusedTop = fmt.Sprintf(" (first: pid %d (%s))", p.key.pid, p.upd.Comm)
		}
		refused++
		r.closeFiles(p, b)
		p.noFiles = true
		return true
	}
	overCap := func(p *procEntry, n int) bool {
		if r.cfg.MaxFilesPerProcess <= 0 || n <= r.cfg.MaxFilesPerProcess {
			return false
		}
		if n > cappedMax {
			cappedMax, cappedTop = n, fmt.Sprintf(" (most: pid %d (%s) with %d)", p.key.pid, p.upd.Comm, n)
		}
		capped++
		r.closeFiles(p, b)
		p.noFiles = true
		return true
	}
	for _, p := range r.procs {
		if p.closed || !(all || p.owns || p.born == r.gen) {
			continue
		}
		// Untracked by the memory guard: with TCP from events nothing in its
		// fds is needed (owners come from the events), so it is not read at
		// all; a process can hold half a million fds, and reading them took
		// up to 74 s a walk in the attack test (2026-11-10).
		if all && p.noFiles && r.tcp != nil {
			continue
		}
		count, haveCount := 0, false
		if all {
			count, haveCount = r.fs.FDCount(p.key.pid) // Linux 6.2+: the size of /proc/<pid>/fd
			if haveCount && !p.noFiles && overCap(p, count) && r.tcp != nil {
				continue // not even read
			}
		}
		if all && !full && p.files != nil && p.born != r.gen && !(r.tcp != nil && r.tcp.fdActive[p.key.pid]) {
			if haveCount && count == p.fdCount {
				work += len(p.files)
				r.presumeFiles(p, ts, names, b)
				presumed++
				continue
			}
		}
		// The memory guard during the walk: one walk once took the recorder
		// from 136 to 761 MiB (4 million fds in 8 processes) before the
		// per-sample check could act. Every walkCheckFDs fds read the guard
		// runs; while it sheds and the heap is still above it, the processes
		// walked after that are not tracked (with TCP from events, not even
		// read).
		if all && r.cfg.MemoryGuard > 0 {
			if work-checked >= walkCheckFDs {
				checked = work
				r.checkMemoryAt(time.UnixMilli(ts), b, r.heapNow())
			}
			big := len(p.files) > shedMinFiles || haveCount && count > shedMinFiles
			if big && refuse(p) && r.tcp != nil {
				continue
			}
		}
		fds, err := r.fs.ReadFDs(p.key.pid, !all)
		if err != nil {
			continue // vanished or not permitted; entries are kept until the process closes
		}
		nfd += len(fds)
		work += len(fds)
		if all && len(fds) > shedMinFiles && refuse(p) && r.tcp != nil {
			continue // no fd count before reading (kernels before 6.2)
		}
		if all && !p.noFiles && overCap(p, len(fds)) && r.tcp != nil {
			continue // older kernels: known only once read
		}
		r.observeOwners(p, fds, ts, b)
		if all && p.noFiles {
			for _, fd := range fds {
				r.noteSocket(p, fd) // socket holders still, no files
			}
		} else if all {
			p.fdCount = len(fds)
			fds = append(fds, r.fs.ReadSpecialLinks(p.key.pid)...)
			r.observeFiles(p, fds, ts, names, b)
			walked++
		}
	}
	if r.walkHeldDeferred > 0 {
		b.Stats = append(b.Stats, store.StatRow{TS: ts, Source: "fd_walk_held_deferred", Events: int64(r.walkHeldDeferred)})
	}
	if capped > 0 {
		detail := fmt.Sprintf("%d processes hold more than %d open files (--max-files-per-process): their open files are not tracked%s",
			capped, r.cfg.MaxFilesPerProcess, cappedTop)
		b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "files_capped", Detail: detail})
		r.log.Warnf("%s", detail)
	}
	if refused > 0 {
		detail := fmt.Sprintf("recorder live heap still above the %d MiB memory guard during the open-file walk: %d more processes not tracked%s",
			r.cfg.MemoryGuard>>20, refused, refusedTop)
		b.Guard = append(b.Guard, store.GuardEvent{TS: ts, Kind: "memory_shed", Detail: detail})
		r.log.Warnf("memory guard: %s", detail)
		freeOSMemory()
	}
	if all && r.tcp != nil {
		r.tcp.fdActive = map[int]bool{}
	}
	if all && r.heldMode() {
		b.Stats = append(b.Stats, store.StatRow{TS: ts, Source: "fd_walk_processes", Events: int64(walked)},
			store.StatRow{TS: ts, Source: "fd_walk_presumed_unchanged", Events: int64(presumed)})
	}
	return nfd
}

// noteSocket records who holds a socket inode (events mode) and reports
// whether the fd should be left out of the files: in v1 mode inet sockets
// are tracked by sock_owners.
func (r *Recorder) noteSocket(p *procEntry, fd procfs.FD) (skip bool) {
	ino, ok := procfs.SocketInode(fd.Target)
	if !ok {
		return false
	}
	if r.tcp != nil {
		if _, seen := r.tcp.holders[ino]; !seen {
			r.tcp.holders[ino] = holder{key: p.key, fd: fd.Num}
		}
		return !r.heldMode() && r.tcp.isInetInode(ino)
	}
	return r.byInode[ino] != nil
}

// observeFiles records one walked process's open files.
func (r *Recorder) observeFiles(p *procEntry, fds []procfs.FD, ts int64, names sockNames, b *store.Batch) {
	if p.files == nil {
		p.files = map[fileKey]*fileEntry{}
	}
	for _, fd := range fds {
		if r.noteSocket(p, fd) {
			continue
		}
		k := fileKey{fd: fd.Num, target: fd.Target}
		e := p.files[k]
		if e == nil {
			e = &fileEntry{first: ts}
			p.files[k] = e
			if !r.heldMode() {
				e.id = r.nextID("open_files")
				row := r.fileRow(p, fd, names)
				row.ID, row.FirstSeen = e.id, ts
				b.FileInserts = append(b.FileInserts, row)
			}
		}
		e.gen, e.last = r.gen, ts
		e.walks++
		r.storeHeld(p, k, e, names, b)
	}
	for k, e := range p.files {
		if e.gen != r.gen {
			r.closeFile(e, b)
			delete(p.files, k)
		}
	}
}

// presumeFiles: the process's fd count did not change, so its fds are
// taken to be the ones of its last walk (without reading them).
func (r *Recorder) presumeFiles(p *procEntry, ts int64, names sockNames, b *store.Batch) {
	for k, e := range p.files {
		r.noteSocket(p, k.procFD())
		e.gen, e.last = r.gen, ts
		e.walks++
		r.storeHeld(p, k, e, names, b)
	}
}

// storeHeld writes a held-mode entry once it qualifies: seen in two
// consecutive walks, or a deleted file (at once).
func (r *Recorder) storeHeld(p *procEntry, k fileKey, e *fileEntry, names sockNames, b *store.Batch) {
	if !r.heldMode() || e.id != 0 {
		return
	}
	deleted := strings.HasSuffix(k.target, " (deleted)")
	if e.walks < 2 && !deleted {
		return
	}
	// Each new held file costs a stat, an fdinfo read and a row: 2.4
	// million of them took one walk 78 s in the attack test (2026-11-10).
	// Beyond the limit they wait for the next walk (first_seen stays).
	if r.walkNewHeld >= maxNewHeldPerWalk {
		r.walkHeldDeferred++
		return
	}
	r.walkNewHeld++
	if r.ownedSocket(p, k.procFD()) {
		e.id = -1 // tcp_conns (or the keyframe) already says who holds it
		return
	}
	e.id = r.nextID("fds_held")
	f := r.fileRow(p, k.procFD(), names)
	b.HeldInserts = append(b.HeldInserts, store.HeldFD{ID: e.id, PID: p.key.pid, StartTime: p.key.start, FD: k.fd,
		Target: k.target, Deleted: deleted, FType: f.FType, Mode: f.Mode, Name: f.Name, Node: f.Node, FirstSeen: e.first})
}

// fileRow reads what lsof shows about an fd (type, mode, inode).
func (r *Recorder) fileRow(p *procEntry, fd procfs.FD, names sockNames) store.FileRow {
	row := store.FileRow{ProcID: p.id, FD: fd.Num, Target: fd.Target, Deleted: strings.HasSuffix(fd.Target, " (deleted)")}
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
	return row
}

// ownedSocket: an inet socket fd that is the one tcp_conns records as the
// connection's owner (or the keyframe as the UDP socket's holder). Only other
// holders need a held-fd row.
func (r *Recorder) ownedSocket(p *procEntry, fd procfs.FD) bool {
	ino, ok := procfs.SocketInode(fd.Target)
	if !ok || r.tcp == nil {
		return false
	}
	if c := r.tcp.byInode[ino]; c != nil {
		return int(c.row.PID) == p.key.pid && int(c.row.FD) == fd.Num
	}
	if r.tcp.udpInodes[ino] {
		h, ok := r.tcp.holders[ino]
		return ok && h.key == p.key && h.fd == fd.Num
	}
	return false
}

func (r *Recorder) closeFile(e *fileEntry, b *store.Batch) {
	switch {
	case e.id <= 0:
	case r.heldMode():
		b.HeldCloses = append(b.HeldCloses, store.Close{ID: e.id, LastSeen: e.last})
	default:
		b.FileCloses = append(b.FileCloses, store.Close{ID: e.id, LastSeen: e.last})
	}
}

// closeFiles closes the file rows of a process that ended.
func (r *Recorder) closeFiles(p *procEntry, b *store.Batch) {
	for _, e := range p.files {
		r.closeFile(e, b)
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
