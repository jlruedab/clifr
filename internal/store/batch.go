package store

import (
	"database/sql"
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
	TS      int64
	Action  string // mount, unmount, present
	MountID int
	Point   string
	Source  string
	FSType  string
	Options string
}

// TCPConn is one TCP connection (or listening socket) from eBPF events, or
// first seen in a keyframe. Rows are written whole: a later row with the same
// ID replaces the earlier one (the connection's newest state).
type TCPConn struct {
	ID         int64
	PID        int    // owner (connect, listen or accept); 0: unknown
	StartTime  int64  // owner's start time (with PID, the process key)
	FD         int    // owner's fd; -1: unknown
	OwnerUntil *int64 // the application closed the socket
	IfName     string // bound to a device (from a keyframe), as ss shows "addr%if"
	Inode      uint64
	Family     int
	LAddr      string
	LPort      int
	RAddr      string
	RPort      int
	Direction  string // active, passive, listen or unknown
	OpenTS     int64
	CloseTS    *int64
	FirstState int // state when first seen (keyframe-adopted connections have no transitions)
	FinalState int // state just before TCP_CLOSE
	// LingerState (TIME_WAIT or FIN_WAIT2) is the time-wait socket that
	// continues after CloseTS, until about LingerUntil (estimated).
	LingerState    int
	LingerUntil    *int64
	Retransmits    int
	ResetsSent     int
	ResetsReceived int
	Source         string // ebpf or keyframe
	LastSeen       int64  // time of this version of the row
}

type TCPTransition struct {
	ConnID   int64
	TS       int64
	Seq      int // order within the connection (several changes can share a millisecond)
	Old, New int
}

// KeyframeRow is one socket of a full sock_diag dump (TCP and UDP): the only
// place with exact queues, and UDP's only record.
type KeyframeRow struct {
	TS           int64
	Proto        string
	Family       int
	LAddr        string
	LPort        int
	RAddr        string
	RPort        int
	Inode        uint64
	State        int
	RecvQ, SendQ int64
	UID          int
	ConnID       int64 // TCP: the matching connection, 0 if none
	PID          int   // holder from events or the last fd walk; 0: unknown
	StartTime    int64
	FD           int
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
	TCPConns    []TCPConn
	TCPTrans    []TCPTransition
	Keyframes   []KeyframeRow
	Reconcile   []ReconcileRow
	ProcExits   []ProcExit
	OOMEvents   []OOMEvent
	Stats       []StatRow
	Guard       []GuardEvent
	Verify      []VerifySnap
	Skips       []int64 // timestamps of skipped sample slots
}

// Rows is the number of row writes in the batch, excluding the sample row.
func (b *Batch) Rows() int {
	return len(b.ProcInserts) + len(b.ProcUpdates) + len(b.ProcCloses) + len(b.ProcSamples) +
		len(b.SockInserts) + len(b.SockCloses) + len(b.SockSamples) +
		len(b.OwnInserts) + len(b.OwnCloses) + len(b.FileInserts) + len(b.FileCloses) +
		len(b.Guard) + len(b.Verify) + len(b.Skips) + len(b.ProcExits) + len(b.OOMEvents) + len(b.Stats) +
		len(b.HeldInserts) + len(b.HeldCloses) + len(b.Mounts) +
		len(b.TCPConns) + len(b.TCPTrans) + len(b.Keyframes) + len(b.Reconcile)
}

func nullInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
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
				locked, first_seen, last_seen, ended, source, exe, exec_ts, exit_ts, exit_code, signal, oom_killed)
				VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				len(b.ProcInserts), func(st *sql.Stmt, i int) error {
					p := b.ProcInserts[i]
					_, err := st.Exec(p.ID, p.PID, p.StartTime, p.PPID, p.UID, p.Comm, p.Cmdline, p.TTY,
						p.SID, p.PGRP, b2i(p.Locked), p.FirstSeen, nullInt(p.LastSeen), nullInt(p.Ended), p.Source,
						p.Exe, nullInt(p.ExecTS), nullInt(p.ExitTS), nullIntp(p.ExitCode), nullIntp(p.Signal), b2i(p.OOMKilled))
					return err
				})
		},
		func() error {
			return each(`UPDATE processes SET uid = ?, ppid = ?, comm = ?, cmdline = ?, source = ?, exe = ?, exec_ts = ? WHERE id = ?`,
				len(b.ProcUpdates), func(st *sql.Stmt, i int) error {
					u := b.ProcUpdates[i]
					var execTS any
					if u.ExecTS != 0 {
						execTS = u.ExecTS
					}
					_, err := st.Exec(u.UID, u.PPID, u.Comm, u.Cmdline, u.Source, u.Exe, execTS, u.ID)
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
				retransmits, resets_sent, resets_received, source, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				len(b.TCPConns), func(st *sql.Stmt, i int) error {
					c := b.TCPConns[i]
					_, err := st.Exec(c.ID, c.PID, c.StartTime, c.FD, nullInt(c.OwnerUntil), c.IfName, int64(c.Inode), c.Family, c.LAddr, c.LPort,
						c.RAddr, c.RPort, c.Direction, c.OpenTS, nullInt(c.CloseTS), c.FirstState, c.FinalState, c.LingerState,
						nullInt(c.LingerUntil), c.Retransmits, c.ResetsSent, c.ResetsReceived, c.Source, c.LastSeen)
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
				uid, conn_id, pid, start_time, fd) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				len(b.Keyframes), func(st *sql.Stmt, i int) error {
					k := b.Keyframes[i]
					_, err := st.Exec(k.TS, k.Proto, k.Family, k.LAddr, k.LPort, k.RAddr, k.RPort, int64(k.Inode), k.State,
						k.RecvQ, k.SendQ, k.UID, k.ConnID, k.PID, k.StartTime, k.FD)
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
				vsz_kb, threads) VALUES(?,?,?,?,?,?,?,?,?)`,
				len(b.ProcSamples), func(st *sql.Stmt, i int) error {
					p := b.ProcSamples[i]
					_, err := st.Exec(p.ProcID, p.TS, p.State, p.Nice, p.TPGID, p.CPUTicks, p.RSSKB, p.VSZKB, p.Threads)
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
			return each(`INSERT INTO mounts(ts, action, mount_id, mount_point, source, fstype, options) VALUES(?,?,?,?,?,?,?)`,
				len(b.Mounts), func(st *sql.Stmt, i int) error {
					m := b.Mounts[i]
					_, err := st.Exec(m.TS, m.Action, m.MountID, m.Point, m.Source, m.FSType, m.Options)
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
