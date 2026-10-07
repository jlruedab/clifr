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
	Source          string
}

// ProcUpdate changes slow-moving attributes (re-read at exec or fd walks).
type ProcUpdate struct {
	ID            int64
	UID, PPID     int
	Comm, Cmdline string
	Source        string
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
	TS, SampleTS int64
	Cmd, Output  string
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
	Guard       []GuardEvent
	Verify      []VerifySnap
	Skips       []int64 // timestamps of skipped sample slots
}

// Rows is the number of row writes in the batch, excluding the sample row.
func (b *Batch) Rows() int {
	return len(b.ProcInserts) + len(b.ProcUpdates) + len(b.ProcCloses) + len(b.ProcSamples) +
		len(b.SockInserts) + len(b.SockCloses) + len(b.SockSamples) +
		len(b.OwnInserts) + len(b.OwnCloses) + len(b.FileInserts) + len(b.FileCloses) +
		len(b.Guard) + len(b.Verify) + len(b.Skips)
}

func nullInt(p *int64) any {
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
				locked, first_seen, last_seen, ended, source) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				len(b.ProcInserts), func(st *sql.Stmt, i int) error {
					p := b.ProcInserts[i]
					_, err := st.Exec(p.ID, p.PID, p.StartTime, p.PPID, p.UID, p.Comm, p.Cmdline, p.TTY,
						p.SID, p.PGRP, b2i(p.Locked), p.FirstSeen, nullInt(p.LastSeen), nullInt(p.Ended), p.Source)
					return err
				})
		},
		func() error {
			return each(`UPDATE processes SET uid = ?, ppid = ?, comm = ?, cmdline = ?, source = ? WHERE id = ?`,
				len(b.ProcUpdates), func(st *sql.Stmt, i int) error {
					u := b.ProcUpdates[i]
					_, err := st.Exec(u.UID, u.PPID, u.Comm, u.Cmdline, u.Source, u.ID)
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
			return each(`INSERT INTO guard_events(ts, kind, detail) VALUES(?,?,?)`,
				len(b.Guard), func(st *sql.Stmt, i int) error {
					g := b.Guard[i]
					_, err := st.Exec(g.TS, g.Kind, g.Detail)
					return err
				})
		},
		func() error {
			return each(`INSERT INTO verify_snapshots(ts, cmd, sample_ts, output) VALUES(?,?,?,?)`,
				len(b.Verify), func(st *sql.Stmt, i int) error {
					v := b.Verify[i]
					_, err := st.Exec(v.TS, v.Cmd, v.SampleTS, v.Output)
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
