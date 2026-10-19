package store

import (
	"database/sql"
	"strings"
)

type Sample struct {
	TS                                     int64
	FDWalk, Skipped                        bool
	DurProcUS, DurSockUS, DurFDUS, DurDBUS int64
	NProc, NSock, NFD, NEvents, Rows       int
	CPUUS, RSSKB, DBBytes, FDIntervalS     int64
}

type ProcRow struct {
	ID, StartTime   int64
	PID, PPID, UID  int
	Comm, Cmdline   string
	Argv0Len        int // length of argv[0] in Cmdline (0: unknown)
	TTY, SID, PGRP  int
	Locked          bool
	FirstSeen       int64
	LastSeen, Ended *int64 // set for event-only processes that are already gone
	Source          string // sample, ebpf or proc_connector
	// From process events (eBPF); empty/nil when unknown.
	Exe              string
	ExecTS, ExitTS   *int64
	ExitCode, Signal *int
	OOMKilled        bool
}

// ProcUpdate changes slow-moving attributes (re-read at exec or fd walks).
type ProcUpdate struct {
	ID            int64
	UID, PPID     int
	Comm, Cmdline string
	Argv0Len      int
	Source        string
	Exe           string
	ExecTS        int64 // 0: no exec seen
}

// ProcExit records how a process ended (an exit event or an OOM kill); nil
// fields leave the stored value unchanged.
type ProcExit struct {
	ID               int64
	ExitTS           *int64
	ExitCode, Signal *int
	OOMKilled        bool
}

// OOMEvent is an OOM kill. The victim is identified by pid and start time
// (it may never have been sampled); RSSKB is its memory at the kill.
type OOMEvent struct {
	TS        int64
	PID       int
	StartTime int64 // 0 if the victim was gone before /proc could be read
	Comm      string
	RSSKB     int64
	Snapshot  bool // a proc_samples row was written for the victim at TS
}

// HeldFD is an fd held across at least two consecutive walks of its process,
// or a deleted file still open (stored at once). Identified by the process
// key (pid, start time).
type HeldFD struct {
	ID        int64
	PID       int
	StartTime int64
	FD        int // -1 cwd, -2 rtd, -3 txt
	Target    string
	Deleted   bool
	FType     string
	Mode      string
	Name      string
	Node      int64
	FirstSeen int64
}

// MountEvent is a change of the mount table (or, with Action "present", a
// mount that existed when recording started).
type MountEvent struct {
	TS           int64
	Action       string // mount, unmount, remount, present
	MountID      int
	Point        string
	Source       string
	FSType       string
	Options      string
	SuperOptions string
	Dev, Root    string
	Seq          int    // position in mountinfo when recorded (mount lists in that order)
	LoopFile     string // backing file of a loop device source
	UserOptions  string // libmount's userspace options (/run/mount/utab)
}

// FSSample is a file system's usage (statfs) at a sample, written when it
// changed. Counts are in FrSize units, inodes in Files/FFree.
type FSSample struct {
	TS                    int64
	MountID               int
	FrSize                int64
	Blocks, BFree, BAvail int64
	Files, FFree          int64
}

// SysSample is the system-wide state at one sample: the kernel's raw values
// behind uptime, vmstat, mpstat and iostat. Counters are cumulative since
// boot; loads are in hundredths, memory in kB.
type SysSample struct {
	TS                                                    int64
	UptimeMS                                              int64 // since boot
	Load1, Load5, Load15                                  int
	Runnable, Threads                                     int // /proc/loadavg: scheduling entities
	ProcsRunning, ProcsBlocked                            int
	Intr, Ctxt, Forks, SoftIRQ                            int64
	MemTotal, MemFree, MemAvailable, Buffers, Cached      int64
	SwapCached, Active, Inactive, SwapTotal, SwapFree     int64
	Dirty, Writeback, Shmem, Slab, SReclaimable           int64
	PgpgIn, PgpgOut, PswpIn, PswpOut, PgFault, PgMajFault int64
}

// CPUCols names CPUSample.T, DiskCols DiskSample.V (the table columns).
var (
	CPUCols  = []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice"}
	DiskCols = []string{"rd_ios", "rd_merges", "rd_sectors", "rd_ticks", "wr_ios", "wr_merges", "wr_sectors", "wr_ticks",
		"dc_ios", "dc_merges", "dc_sectors", "dc_ticks", "in_flight", "io_ticks", "time_in_queue", "fl_ios", "fl_ticks"}
)

// CPUSample is one CPU's times in clock ticks; CPU -1 is the total.
type CPUSample struct {
	TS  int64
	CPU int
	T   [10]int64
}

// DiskSample is one /proc/diskstats line (sectors of 512 bytes, times in ms).
type DiskSample struct {
	TS           int64
	Major, Minor int
	Name         string
	Part         bool // a partition: iostat lists only whole devices
	V            [17]int64
}

// TCPConn is one TCP connection (or listening socket) from eBPF events, or
// first seen in a keyframe. Rows are written whole: a later row with the same
// ID replaces the earlier one (the connection's newest state). The recorder
// holds one per connection: no strings or pointers (see compact.go), and at
// most 128 bytes (an allocation size class). Times are Unix ms; 0 is "none"
// (NULL in the tables).
type TCPConn struct {
	ID          int64
	StartTime   int64 // owner's start time (with PID, the process key)
	OwnerUntil  int64 // the application closed the socket
	Inode       uint64
	OpenTS      int64
	CloseTS     int64
	LingerUntil int64 // the time-wait socket's end (estimated, or exact from an event)
	LastSeen    int64 // time of this version of the row
	LAddr       Addr
	RAddr       Addr
	PID         int32 // owner (connect, listen or accept); 0: unknown
	FD          int32 // owner's fd; -1: unknown
	LPort       uint16
	RPort       uint16
	Retransmits uint32
	// ResetsSent and ResetsReceived stop at 65,535.
	ResetsSent     uint16
	ResetsReceived uint16
	Family         uint8 // 4 or 6; 0: addresses not known yet
	FirstState     uint8 // state when first seen (keyframe-adopted connections have no transitions)
	FinalState     uint8 // state just before TCP_CLOSE
	// LingerState (TIME_WAIT or FIN_WAIT2) is the time-wait socket that
	// continues after CloseTS, until about LingerUntil.
	LingerState uint8
	Direction   Direction
	Source      ConnSource
	V6Only      bool // IPv6 socket that does not accept IPv4 (known for listeners)
	IfName      Name // bound to a device (from a keyframe), as ss shows "addr%if"
}

type TCPTransition struct {
	ConnID   int64
	TS       int64
	Seq      int // order within the connection (several changes can share a millisecond)
	Old, New int
}

// KeyframeRow is one socket of a full sock_diag dump (TCP and UDP): the only
// place with exact queues, and UDP's only record. No strings or pointers,
// like TCPConn.
type KeyframeRow struct {
	TS           int64
	Inode        uint64
	RecvQ, SendQ int64
	ConnID       int64 // TCP: the matching connection, 0 if none
	StartTime    int64
	LAddr        Addr
	RAddr        Addr
	PID          int32 // holder from events or the last fd walk; 0: unknown
	FD           int32
	UID          int32
	LPort        uint16
	RPort        uint16
	Family       uint8
	State        uint8
	Proto        Proto
	V6Only       bool
}

// ReconcileRow compares a keyframe with the event state: connections in the
// dump that events did not know, and open in events but not in the dump.
type ReconcileRow struct {
	TS                int64
	Kind              string
	DumpRows          int
	MissingFromEvents int
	ExtraInEvents     int
	Initial           bool // the first keyframe of a run: everything was unknown
}

// StatRow is one recorder counter for the interval ending at TS, e.g.
// events received and dropped per event source.
type StatRow struct {
	TS              int64
	Source          string
	Events, Dropped int64
}

type ProcSample struct {
	ProcID, TS             int64
	State                  string
	Nice, TPGID            int
	CPUTicks, RSSKB, VSZKB int64
	Threads                int
	// Cumulative I/O (/proc/<pid>/io); all 0 when not read.
	RChar, WChar, ReadBytes, WriteBytes, CancelledWrite int64
}

// Close ends a time range. Ended is only used for processes.
type Close struct {
	ID       int64
	LastSeen int64
	Ended    *int64
}

type SockRow struct {
	ID           int64
	Inode        uint64
	Proto        string
	Family       int
	LAddr, RAddr string
	LPort, RPort int
	IfName       string
	UID          int
	FirstSeen    int64
}

type SockSample struct {
	SockID, TS int64
	State      int
	RxQ, TxQ   int64
}

type OwnerRow struct {
	ID, SockID, ProcID int64
	FD                 int
	FirstSeen          int64
}

type FileRow struct {
	ID, ProcID        int64
	FD                int
	Target            string
	Deleted           bool
	FType, Mode, Name string
	Node              int64
	FirstSeen         int64
}

type GuardEvent struct {
	TS           int64
	Kind, Detail string
}

type VerifySnap struct {
	TS, EndTS, SampleTS int64
	Cmd, IgnorePIDs     string
	Output              string
}

// Batch is everything one sample writes. It is applied in one transaction.
type Batch struct {
	Sample      Sample
	ProcInserts []ProcRow
	ProcUpdates []ProcUpdate
	ProcCloses  []Close
	ProcSamples []ProcSample
	SockInserts []SockRow
	SockCloses  []Close
	SockSamples []SockSample
	OwnInserts  []OwnerRow
	OwnCloses   []Close
	FileInserts []FileRow
	FileCloses  []Close
	HeldInserts []HeldFD
	HeldCloses  []Close
	Mounts      []MountEvent
	FSSamples   []FSSample
	TCPConns    []TCPConn
	TCPTrans    []TCPTransition
	Keyframes   []KeyframeRow
	Reconcile   []ReconcileRow
	ProcExits   []ProcExit
	OOMEvents   []OOMEvent
	Stats       []StatRow
	Guard       []GuardEvent
	Verify      []VerifySnap
	Skips       []int64     // timestamps of skipped sample slots
	Sys         []SysSample // one per system sample (several when the system interval is shorter)
	CPUs        []CPUSample
	Disks       []DiskSample
}

// Rows is the number of row writes in the batch, excluding the sample row.
func (b *Batch) Rows() int {
	return len(b.ProcInserts) + len(b.ProcUpdates) + len(b.ProcCloses) + len(b.ProcSamples) +
		len(b.SockInserts) + len(b.SockCloses) + len(b.SockSamples) +
		len(b.OwnInserts) + len(b.OwnCloses) + len(b.FileInserts) + len(b.FileCloses) +
		len(b.Guard) + len(b.Verify) + len(b.Skips) + len(b.ProcExits) + len(b.OOMEvents) + len(b.Stats) +
		len(b.HeldInserts) + len(b.HeldCloses) + len(b.Mounts) +
		len(b.TCPConns) + len(b.TCPTrans) + len(b.Keyframes) + len(b.Reconcile) +
		len(b.CPUs) + len(b.Disks) + len(b.FSSamples)
}

func nullInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// nullTS is a time, NULL when 0.
func nullTS(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullIntp(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Write applies the batch in a single transaction.
func (d *DB) Write(b *Batch) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// each runs fn for n items with one prepared statement.
	each := func(q string, n int, fn func(st *sql.Stmt, i int) error) error {
		if n == 0 {
			return nil
		}
		st, err := tx.Prepare(q)
		if err != nil {
			return err
		}
		defer st.Close()
		for i := 0; i < n; i++ {
			if err := fn(st, i); err != nil {
				return err
			}
		}
		return nil
	}
	closeQ := func(table string) string {
		return `UPDATE ` + table + ` SET last_seen = ? WHERE id = ?`
	}
	closes := func(table string, cs []Close) error {
		return each(closeQ(table), len(cs), func(st *sql.Stmt, i int) error {
			_, err := st.Exec(cs[i].LastSeen, cs[i].ID)
			return err
		})
	}

	s := b.Sample
	steps := []func() error{
		func() error {
			return each(`INSERT INTO samples(ts, fd_walk, skipped) VALUES(?, 0, 1)`, len(b.Skips),
				func(st *sql.Stmt, i int) error {
					_, err := st.Exec(b.Skips[i])
					return err
				})
		},
		func() error {
			if s.TS == 0 {
				return nil // e.g. the shutdown batch only closes rows
			}
			_, err := tx.Exec(`INSERT INTO samples(ts, fd_walk, skipped, dur_proc_us, dur_sock_us, dur_fd_us,
				dur_db_us, nproc, nsock, nfd, nevents, rows, cpu_us, rss_kb, db_bytes, fd_interval_s)
				VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				s.TS, b2i(s.FDWalk), b2i(s.Skipped), s.DurProcUS, s.DurSockUS, s.DurFDUS, s.DurDBUS,
				s.NProc, s.NSock, s.NFD, s.NEvents, s.Rows, s.CPUUS, s.RSSKB, s.DBBytes, s.FDIntervalS)
			return err
		},
		func() error {
			return each(`INSERT INTO processes(id, pid, start_time, ppid, uid, comm, cmdline, tty, sid, pgrp,
				locked, first_seen, last_seen, ended, source, exe, exec_ts, exit_ts, exit_code, signal, oom_killed, argv0_len)
				VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				len(b.ProcInserts), func(st *sql.Stmt, i int) error {
					p := b.ProcInserts[i]
					_, err := st.Exec(p.ID, p.PID, p.StartTime, p.PPID, p.UID, p.Comm, p.Cmdline, p.TTY,
						p.SID, p.PGRP, b2i(p.Locked), p.FirstSeen, nullInt(p.LastSeen), nullInt(p.Ended), p.Source,
						p.Exe, nullInt(p.ExecTS), nullInt(p.ExitTS), nullIntp(p.ExitCode), nullIntp(p.Signal), b2i(p.OOMKilled), p.Argv0Len)
					return err
				})
		},
		func() error {
			return each(`UPDATE processes SET uid = ?, ppid = ?, comm = ?, cmdline = ?, argv0_len = ?, source = ?, exe = ?, exec_ts = ? WHERE id = ?`,
				len(b.ProcUpdates), func(st *sql.Stmt, i int) error {
					u := b.ProcUpdates[i]
					var execTS any
					if u.ExecTS != 0 {
						execTS = u.ExecTS
					}
					_, err := st.Exec(u.UID, u.PPID, u.Comm, u.Cmdline, u.Argv0Len, u.Source, u.Exe, execTS, u.ID)
					return err
				})
		},
		func() error {
			return each(`UPDATE processes SET exit_ts = COALESCE(?, exit_ts), exit_code = COALESCE(?, exit_code),
				signal = COALESCE(?, signal), oom_killed = MAX(oom_killed, ?) WHERE id = ?`,
				len(b.ProcExits), func(st *sql.Stmt, i int) error {
					x := b.ProcExits[i]
					_, err := st.Exec(nullInt(x.ExitTS), nullIntp(x.ExitCode), nullIntp(x.Signal), b2i(x.OOMKilled), x.ID)
					return err
				})
		},
		func() error {
			return each(`INSERT INTO oom_events(ts, pid, start_time, comm, rss_kb, snapshot) VALUES(?,?,?,?,?,?)`,
				len(b.OOMEvents), func(st *sql.Stmt, i int) error {
					o := b.OOMEvents[i]
					_, err := st.Exec(o.TS, o.PID, o.StartTime, o.Comm, o.RSSKB, b2i(o.Snapshot))
					return err
				})
		},
		func() error {
			return each(`INSERT OR REPLACE INTO tcp_conns(id, pid, start_time, fd, owner_until, ifname, inode, family, laddr, lport,
				raddr, rport, direction, open_ts, close_ts, first_state, final_state, linger_state, linger_until,
				retransmits, resets_sent, resets_received, source, last_seen, v6only) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				len(b.TCPConns), func(st *sql.Stmt, i int) error {
					c := &b.TCPConns[i]
					f := int(c.Family)
					_, err := st.Exec(c.ID, c.PID, c.StartTime, c.FD, nullTS(c.OwnerUntil), c.IfName.String(), int64(c.Inode), c.Family,
						c.LAddr.String(f), c.LPort, c.RAddr.String(f), c.RPort, c.Direction.String(), c.OpenTS, nullTS(c.CloseTS),
						c.FirstState, c.FinalState, c.LingerState, nullTS(c.LingerUntil), c.Retransmits, c.ResetsSent,
						c.ResetsReceived, c.Source.String(), c.LastSeen, b2i(c.V6Only))
					return err
				})
		},
		func() error {
			return each(`INSERT INTO tcp_transitions(conn_id, ts, seq, old_state, new_state) VALUES(?,?,?,?,?)`,
				len(b.TCPTrans), func(st *sql.Stmt, i int) error {
					t := b.TCPTrans[i]
					_, err := st.Exec(t.ConnID, t.TS, t.Seq, t.Old, t.New)
					return err
				})
		},
		func() error {
			return each(`INSERT INTO tcp_keyframes(ts, proto, family, laddr, lport, raddr, rport, inode, state, recv_q, send_q,
				uid, conn_id, pid, start_time, fd, v6only) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				len(b.Keyframes), func(st *sql.Stmt, i int) error {
					k := &b.Keyframes[i]
					f := int(k.Family)
					_, err := st.Exec(k.TS, k.Proto.String(), k.Family, k.LAddr.String(f), k.LPort, k.RAddr.String(f), k.RPort, int64(k.Inode), k.State,
						k.RecvQ, k.SendQ, k.UID, k.ConnID, k.PID, k.StartTime, k.FD, b2i(k.V6Only))
					return err
				})
		},
		func() error {
			return each(`INSERT INTO reconcile(ts, kind, dump_rows, missing_from_events, extra_in_events, initial) VALUES(?,?,?,?,?,?)`,
				len(b.Reconcile), func(st *sql.Stmt, i int) error {
					r := b.Reconcile[i]
					_, err := st.Exec(r.TS, r.Kind, r.DumpRows, r.MissingFromEvents, r.ExtraInEvents, b2i(r.Initial))
					return err
				})
		},
		func() error {
			return each(`INSERT INTO recorder_stats(ts, source, events, dropped) VALUES(?,?,?,?)`,
				len(b.Stats), func(st *sql.Stmt, i int) error {
					r := b.Stats[i]
					_, err := st.Exec(r.TS, r.Source, r.Events, r.Dropped)
					return err
				})
		},
		func() error {
			return each(`UPDATE processes SET last_seen = ?, ended = ? WHERE id = ?`,
				len(b.ProcCloses), func(st *sql.Stmt, i int) error {
					c := b.ProcCloses[i]
					_, err := st.Exec(c.LastSeen, nullInt(c.Ended), c.ID)
					return err
				})
		},
		func() error {
			return each(`INSERT OR REPLACE INTO proc_samples(proc_id, ts, state, nice, tpgid, cpu_ticks, rss_kb,
				vsz_kb, threads, rchar, wchar, read_bytes, write_bytes, cancelled_write_bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				len(b.ProcSamples), func(st *sql.Stmt, i int) error {
					p := b.ProcSamples[i]
					_, err := st.Exec(p.ProcID, p.TS, p.State, p.Nice, p.TPGID, p.CPUTicks, p.RSSKB, p.VSZKB, p.Threads,
						p.RChar, p.WChar, p.ReadBytes, p.WriteBytes, p.CancelledWrite)
					return err
				})
		},
		func() error {
			return each(`INSERT INTO sockets(id, inode, proto, family, laddr, lport, raddr, rport, ifname, uid,
				first_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
				len(b.SockInserts), func(st *sql.Stmt, i int) error {
					s := b.SockInserts[i]
					_, err := st.Exec(s.ID, int64(s.Inode), s.Proto, s.Family, s.LAddr, s.LPort, s.RAddr, s.RPort,
						s.IfName, s.UID, s.FirstSeen)
					return err
				})
		},
		func() error { return closes("sockets", b.SockCloses) },
		func() error {
			return each(`INSERT OR REPLACE INTO sock_samples(sock_id, ts, state, rxq, txq) VALUES(?,?,?,?,?)`,
				len(b.SockSamples), func(st *sql.Stmt, i int) error {
					s := b.SockSamples[i]
					_, err := st.Exec(s.SockID, s.TS, s.State, s.RxQ, s.TxQ)
					return err
				})
		},
		func() error {
			return each(`INSERT INTO sock_owners(id, sock_id, proc_id, fd, first_seen) VALUES(?,?,?,?,?)`,
				len(b.OwnInserts), func(st *sql.Stmt, i int) error {
					o := b.OwnInserts[i]
					_, err := st.Exec(o.ID, o.SockID, o.ProcID, o.FD, o.FirstSeen)
					return err
				})
		},
		func() error { return closes("sock_owners", b.OwnCloses) },
		func() error {
			return each(`INSERT INTO open_files(id, proc_id, fd, target, deleted, ftype, mode, name, node, first_seen)
				VALUES(?,?,?,?,?,?,?,?,?,?)`,
				len(b.FileInserts), func(st *sql.Stmt, i int) error {
					f := b.FileInserts[i]
					var name any
					if f.Name != "" {
						name = f.Name
					}
					_, err := st.Exec(f.ID, f.ProcID, f.FD, f.Target, b2i(f.Deleted), f.FType, f.Mode, name, f.Node, f.FirstSeen)
					return err
				})
		},
		func() error { return closes("open_files", b.FileCloses) },
		func() error {
			return each(`INSERT INTO fds_held(id, pid, start_time, fd, target, deleted, ftype, mode, name, node, first_seen)
				VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
				len(b.HeldInserts), func(st *sql.Stmt, i int) error {
					f := b.HeldInserts[i]
					_, err := st.Exec(f.ID, f.PID, f.StartTime, f.FD, f.Target, b2i(f.Deleted), f.FType, f.Mode, f.Name, f.Node, f.FirstSeen)
					return err
				})
		},
		func() error { return closes("fds_held", b.HeldCloses) },
		func() error {
			return each(`INSERT INTO mounts(ts, action, mount_id, mount_point, source, fstype, options, super_options, dev, root, seq,
				loop_file, user_options) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				len(b.Mounts), func(st *sql.Stmt, i int) error {
					m := b.Mounts[i]
					_, err := st.Exec(m.TS, m.Action, m.MountID, m.Point, m.Source, m.FSType, m.Options, m.SuperOptions, m.Dev, m.Root, m.Seq,
						m.LoopFile, m.UserOptions)
					return err
				})
		},
		func() error {
			return each(`INSERT INTO fs_samples(ts, mount_id, frsize, blocks, bfree, bavail, files, ffree) VALUES(?,?,?,?,?,?,?,?)`,
				len(b.FSSamples), func(st *sql.Stmt, i int) error {
					f := b.FSSamples[i]
					_, err := st.Exec(f.TS, f.MountID, f.FrSize, f.Blocks, f.BFree, f.BAvail, f.Files, f.FFree)
					return err
				})
		},
		func() error {
			for i := range b.Sys {
				s := &b.Sys[i]
				if _, err := tx.Exec(`INSERT INTO sys_samples VALUES(`+marks(34)+`)`, s.TS, s.UptimeMS, s.Load1, s.Load5, s.Load15,
					s.Runnable, s.Threads, s.ProcsRunning, s.ProcsBlocked, s.Intr, s.Ctxt, s.Forks, s.SoftIRQ,
					s.MemTotal, s.MemFree, s.MemAvailable, s.Buffers, s.Cached, s.SwapCached, s.Active, s.Inactive,
					s.SwapTotal, s.SwapFree, s.Dirty, s.Writeback, s.Shmem, s.Slab, s.SReclaimable,
					s.PgpgIn, s.PgpgOut, s.PswpIn, s.PswpOut, s.PgFault, s.PgMajFault); err != nil {
					return err
				}
			}
			if err := each(`INSERT INTO cpu_samples VALUES(`+marks(2+len(CPUCols))+`)`,
				len(b.CPUs), func(st *sql.Stmt, i int) error {
					c := b.CPUs[i]
					args := []any{c.TS, c.CPU}
					for _, v := range c.T {
						args = append(args, v)
					}
					_, err := st.Exec(args...)
					return err
				}); err != nil {
				return err
			}
			return each(`INSERT INTO disk_samples VALUES(`+marks(5+len(DiskCols))+`)`,
				len(b.Disks), func(st *sql.Stmt, i int) error {
					d := b.Disks[i]
					args := []any{d.TS, d.Major, d.Minor, d.Name, b2i(d.Part)}
					for _, v := range d.V {
						args = append(args, v)
					}
					_, err := st.Exec(args...)
					return err
				})
		},
		func() error {
			return each(`INSERT INTO guard_events(ts, kind, detail) VALUES(?,?,?)`,
				len(b.Guard), func(st *sql.Stmt, i int) error {
					g := b.Guard[i]
					_, err := st.Exec(g.TS, g.Kind, g.Detail)
					return err
				})
		},
		func() error {
			return each(`INSERT INTO verify_snapshots(ts, end_ts, cmd, sample_ts, ignore_pids, output)
				VALUES(?,?,?,?,?,?)`,
				len(b.Verify), func(st *sql.Stmt, i int) error {
					v := b.Verify[i]
					_, err := st.Exec(v.TS, v.EndTS, v.Cmd, v.SampleTS, v.IgnorePIDs, v.Output)
					return err
				})
		},
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// marks returns n comma-separated SQL placeholders.
func marks(n int) string { return strings.TrimSuffix(strings.Repeat("?,", n), ",") }
