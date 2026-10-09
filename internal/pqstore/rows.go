package pqstore

import "sosv/internal/store"

// Parquet rows mirror the v1 SQLite schema (internal/store) column for
// column, so the same queries run on both. Repetitive strings use dictionary
// encoding; nullable columns are pointers.

type sampleRow struct {
	TS          int64  `parquet:"ts"`
	FDWalk      int32  `parquet:"fd_walk"`
	Skipped     int32  `parquet:"skipped"`
	DurProcUS   *int64 `parquet:"dur_proc_us,optional"`
	DurSockUS   *int64 `parquet:"dur_sock_us,optional"`
	DurFDUS     *int64 `parquet:"dur_fd_us,optional"`
	DurDBUS     *int64 `parquet:"dur_db_us,optional"`
	NProc       *int64 `parquet:"nproc,optional"`
	NSock       *int64 `parquet:"nsock,optional"`
	NFD         *int64 `parquet:"nfd,optional"`
	NEvents     *int64 `parquet:"nevents,optional"`
	Rows        *int64 `parquet:"rows,optional"`
	CPUUS       *int64 `parquet:"cpu_us,optional"`
	RSSKB       *int64 `parquet:"rss_kb,optional"`
	DBBytes     *int64 `parquet:"db_bytes,optional"`
	FDIntervalS *int64 `parquet:"fd_interval_s,optional"`
}

type processRow struct {
	ID        int64  `parquet:"id"`
	PID       int32  `parquet:"pid"`
	StartTime int64  `parquet:"start_time"`
	PPID      int32  `parquet:"ppid"`
	UID       int32  `parquet:"uid"`
	Comm      string `parquet:"comm,dict"`
	Cmdline   string `parquet:"cmdline,dict"`
	TTY       int32  `parquet:"tty"`
	SID       int32  `parquet:"sid"`
	PGRP      int32  `parquet:"pgrp"`
	Locked    int32  `parquet:"locked"`
	FirstSeen int64  `parquet:"first_seen"`
	LastSeen  *int64 `parquet:"last_seen,optional"`
	Ended     *int64 `parquet:"ended,optional"`
	Source    string `parquet:"source,dict"`
	Exe       string `parquet:"exe,dict"`
	ExecTS    *int64 `parquet:"exec_ts,optional"`
	ExitTS    *int64 `parquet:"exit_ts,optional"`
	ExitCode  *int32 `parquet:"exit_code,optional"`
	Signal    *int32 `parquet:"signal,optional"`
	OOMKilled int32  `parquet:"oom_killed"`
}

type procSampleRow struct {
	ProcID   int64  `parquet:"proc_id"`
	TS       int64  `parquet:"ts"`
	State    string `parquet:"state,dict"`
	Nice     int32  `parquet:"nice"`
	TPGID    int32  `parquet:"tpgid"`
	CPUTicks int64  `parquet:"cpu_ticks"`
	RSSKB    int64  `parquet:"rss_kb"`
	VSZKB    int64  `parquet:"vsz_kb"`
	Threads  int32  `parquet:"threads"`
}

type socketRow struct {
	ID        int64  `parquet:"id"`
	Inode     int64  `parquet:"inode"`
	Proto     string `parquet:"proto,dict"`
	Family    int32  `parquet:"family"`
	LAddr     string `parquet:"laddr,dict"`
	LPort     int32  `parquet:"lport"`
	RAddr     string `parquet:"raddr,dict"`
	RPort     int32  `parquet:"rport"`
	IfName    string `parquet:"ifname,dict"`
	UID       int32  `parquet:"uid"`
	FirstSeen int64  `parquet:"first_seen"`
	LastSeen  *int64 `parquet:"last_seen,optional"`
}

type sockSampleRow struct {
	SockID int64 `parquet:"sock_id"`
	TS     int64 `parquet:"ts"`
	State  int32 `parquet:"state"`
	RxQ    int64 `parquet:"rxq"`
	TxQ    int64 `parquet:"txq"`
}

type ownerRow struct {
	ID        int64  `parquet:"id"`
	SockID    int64  `parquet:"sock_id"`
	ProcID    int64  `parquet:"proc_id"`
	FD        int32  `parquet:"fd"`
	FirstSeen int64  `parquet:"first_seen"`
	LastSeen  *int64 `parquet:"last_seen,optional"`
}

type fileRow struct {
	ID        int64   `parquet:"id"`
	ProcID    int64   `parquet:"proc_id"`
	FD        int32   `parquet:"fd"`
	Target    string  `parquet:"target"`
	Deleted   int32   `parquet:"deleted"`
	FType     string  `parquet:"ftype,dict"`
	Mode      string  `parquet:"mode,dict"`
	Name      *string `parquet:"name,optional"`
	Node      int64   `parquet:"node"`
	FirstSeen int64   `parquet:"first_seen"`
	LastSeen  *int64  `parquet:"last_seen,optional"`
}

type guardRow struct {
	TS     int64  `parquet:"ts"`
	Kind   string `parquet:"kind,dict"`
	Detail string `parquet:"detail"`
}

type verifyRow struct {
	ID         int64  `parquet:"id"`
	TS         int64  `parquet:"ts"`
	EndTS      int64  `parquet:"end_ts"`
	Cmd        string `parquet:"cmd,dict"`
	SampleTS   int64  `parquet:"sample_ts"`
	IgnorePIDs string `parquet:"ignore_pids"`
	Output     string `parquet:"output"`
}

type oomRow struct {
	TS        int64  `parquet:"ts"`
	PID       int32  `parquet:"pid"`
	StartTime int64  `parquet:"start_time"`
	Comm      string `parquet:"comm"`
	RSSKB     int64  `parquet:"rss_kb"`
	Snapshot  int32  `parquet:"snapshot"`
}

type statRow struct {
	TS      int64  `parquet:"ts"`
	Source  string `parquet:"source,dict"`
	Events  int64  `parquet:"events"`
	Dropped int64  `parquet:"dropped"`
}

type tcpConnRow struct {
	ID             int64  `parquet:"id"`
	PID            int32  `parquet:"pid"`
	StartTime      int64  `parquet:"start_time"`
	FD             int32  `parquet:"fd"`
	OwnerUntil     *int64 `parquet:"owner_until,optional"`
	IfName         string `parquet:"ifname,dict"`
	Inode          int64  `parquet:"inode"`
	Family         int32  `parquet:"family"`
	LAddr          string `parquet:"laddr,dict"`
	LPort          int32  `parquet:"lport"`
	RAddr          string `parquet:"raddr,dict"`
	RPort          int32  `parquet:"rport"`
	Direction      string `parquet:"direction,dict"`
	OpenTS         int64  `parquet:"open_ts"`
	CloseTS        *int64 `parquet:"close_ts,optional"`
	FirstState     int32  `parquet:"first_state"`
	FinalState     int32  `parquet:"final_state"`
	LingerState    int32  `parquet:"linger_state"`
	LingerUntil    *int64 `parquet:"linger_until,optional"`
	Retransmits    int32  `parquet:"retransmits"`
	ResetsSent     int32  `parquet:"resets_sent"`
	ResetsReceived int32  `parquet:"resets_received"`
	Source         string `parquet:"source,dict"`
	LastSeen       *int64 `parquet:"last_seen,optional"`
}

type tcpTransRow struct {
	ConnID int64 `parquet:"conn_id"`
	TS     int64 `parquet:"ts"`
	Seq    int32 `parquet:"seq"`
	Old    int32 `parquet:"old_state"`
	New    int32 `parquet:"new_state"`
}

type keyframeRow struct {
	TS        int64  `parquet:"ts"`
	Proto     string `parquet:"proto,dict"`
	Family    int32  `parquet:"family"`
	LAddr     string `parquet:"laddr,dict"`
	LPort     int32  `parquet:"lport"`
	RAddr     string `parquet:"raddr,dict"`
	RPort     int32  `parquet:"rport"`
	Inode     int64  `parquet:"inode"`
	State     int32  `parquet:"state"`
	RecvQ     int64  `parquet:"recv_q"`
	SendQ     int64  `parquet:"send_q"`
	UID       int32  `parquet:"uid"`
	ConnID    int64  `parquet:"conn_id"`
	PID       int32  `parquet:"pid"`
	StartTime int64  `parquet:"start_time"`
	FD        int32  `parquet:"fd"`
}

type reconcileRow struct {
	TS       int64  `parquet:"ts"`
	Kind     string `parquet:"kind,dict"`
	DumpRows int32  `parquet:"dump_rows"`
	Missing  int32  `parquet:"missing_from_events"`
	Extra    int32  `parquet:"extra_in_events"`
	Initial  int32  `parquet:"initial"`
}

func tcpConnOf(c store.TCPConn) tcpConnRow {
	return tcpConnRow{ID: c.ID, PID: int32(c.PID), StartTime: c.StartTime, FD: int32(c.FD), OwnerUntil: c.OwnerUntil, IfName: c.IfName,
		Inode: int64(c.Inode), Family: int32(c.Family), LAddr: c.LAddr, LPort: int32(c.LPort), RAddr: c.RAddr,
		RPort: int32(c.RPort), Direction: c.Direction, OpenTS: c.OpenTS, CloseTS: c.CloseTS,
		FirstState: int32(c.FirstState), FinalState: int32(c.FinalState), LingerState: int32(c.LingerState),
		LingerUntil: c.LingerUntil, Retransmits: int32(c.Retransmits), ResetsSent: int32(c.ResetsSent),
		ResetsReceived: int32(c.ResetsReceived), Source: c.Source, LastSeen: ptr(c.LastSeen)}
}

func keyframeOf(k store.KeyframeRow) keyframeRow {
	return keyframeRow{TS: k.TS, Proto: k.Proto, Family: int32(k.Family), LAddr: k.LAddr, LPort: int32(k.LPort),
		RAddr: k.RAddr, RPort: int32(k.RPort), Inode: int64(k.Inode), State: int32(k.State), RecvQ: k.RecvQ,
		SendQ: k.SendQ, UID: int32(k.UID), ConnID: k.ConnID, PID: int32(k.PID), StartTime: k.StartTime, FD: int32(k.FD)}
}

type metaRow struct {
	Run   int64  `parquet:"run"`
	TS    int64  `parquet:"ts"`
	Key   string `parquet:"key"`
	Value string `parquet:"value"`
}

func ptr[T any](v T) *T { return &v }

func b2i(b bool) int32 {
	if b {
		return 1
	}
	return 0
}

func sampleOf(s store.Sample) sampleRow {
	return sampleRow{TS: s.TS, FDWalk: b2i(s.FDWalk), Skipped: b2i(s.Skipped),
		DurProcUS: ptr(s.DurProcUS), DurSockUS: ptr(s.DurSockUS), DurFDUS: ptr(s.DurFDUS), DurDBUS: ptr(s.DurDBUS),
		NProc: ptr(int64(s.NProc)), NSock: ptr(int64(s.NSock)), NFD: ptr(int64(s.NFD)), NEvents: ptr(int64(s.NEvents)),
		Rows: ptr(int64(s.Rows)), CPUUS: ptr(s.CPUUS), RSSKB: ptr(s.RSSKB), DBBytes: ptr(s.DBBytes),
		FDIntervalS: ptr(s.FDIntervalS)}
}

func processOf(p store.ProcRow) processRow {
	return processRow{ID: p.ID, PID: int32(p.PID), StartTime: p.StartTime, PPID: int32(p.PPID), UID: int32(p.UID),
		Comm: p.Comm, Cmdline: p.Cmdline, TTY: int32(p.TTY), SID: int32(p.SID), PGRP: int32(p.PGRP),
		Locked: b2i(p.Locked), FirstSeen: p.FirstSeen, LastSeen: p.LastSeen, Ended: p.Ended, Source: p.Source,
		Exe: p.Exe, ExecTS: p.ExecTS, ExitTS: p.ExitTS, ExitCode: i32p(p.ExitCode), Signal: i32p(p.Signal),
		OOMKilled: b2i(p.OOMKilled)}
}

func i32p(p *int) *int32 {
	if p == nil {
		return nil
	}
	return ptr(int32(*p))
}

func procSampleOf(p store.ProcSample) procSampleRow {
	return procSampleRow{ProcID: p.ProcID, TS: p.TS, State: p.State, Nice: int32(p.Nice), TPGID: int32(p.TPGID),
		CPUTicks: p.CPUTicks, RSSKB: p.RSSKB, VSZKB: p.VSZKB, Threads: int32(p.Threads)}
}

func socketOf(s store.SockRow) socketRow {
	return socketRow{ID: s.ID, Inode: int64(s.Inode), Proto: s.Proto, Family: int32(s.Family),
		LAddr: s.LAddr, LPort: int32(s.LPort), RAddr: s.RAddr, RPort: int32(s.RPort),
		IfName: s.IfName, UID: int32(s.UID), FirstSeen: s.FirstSeen}
}

func fileOf(f store.FileRow) fileRow {
	r := fileRow{ID: f.ID, ProcID: f.ProcID, FD: int32(f.FD), Target: f.Target, Deleted: b2i(f.Deleted),
		FType: f.FType, Mode: f.Mode, Node: f.Node, FirstSeen: f.FirstSeen}
	if f.Name != "" {
		r.Name = ptr(f.Name)
	}
	return r
}
