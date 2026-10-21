package pqstore

import "clifr/internal/store"

// Parquet rows: the tables the queries read (internal/duck loads them under
// these names). Repetitive strings use dictionary encoding; nullable columns
// are pointers or optional.

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
	Argv0Len  int32  `parquet:"argv0_len"` // 0: unknown (recordings before schema 2 have no column: NULL)
	TTY       int32  `parquet:"tty"`
	SID       int32  `parquet:"sid"`
	PGRP      int32  `parquet:"pgrp"`
	Locked    int32  `parquet:"locked"`
	FirstSeen int64  `parquet:"first_seen"`
	LastSeen  int64  `parquet:"last_seen,optional"`
	Ended     int64  `parquet:"ended,optional"`
	Source    string `parquet:"source,dict"`
	Exe       string `parquet:"exe,dict"`
	ExecTS    int64  `parquet:"exec_ts,optional"`
	ExitTS    int64  `parquet:"exit_ts,optional"`
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
	// /proc/<pid>/io (schema 2; 0 when not read)
	RChar          int64 `parquet:"rchar"`
	WChar          int64 `parquet:"wchar"`
	ReadBytes      int64 `parquet:"read_bytes"`
	WriteBytes     int64 `parquet:"write_bytes"`
	CancelledWrite int64 `parquet:"cancelled_write_bytes"`
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
	LastSeen  int64  `parquet:"last_seen,optional"`
}

type sockSampleRow struct {
	SockID int64 `parquet:"sock_id"`
	TS     int64 `parquet:"ts"`
	State  int32 `parquet:"state"`
	RxQ    int64 `parquet:"rxq"`
	TxQ    int64 `parquet:"txq"`
}

type ownerRow struct {
	ID        int64 `parquet:"id"`
	SockID    int64 `parquet:"sock_id"`
	ProcID    int64 `parquet:"proc_id"`
	FD        int32 `parquet:"fd"`
	FirstSeen int64 `parquet:"first_seen"`
	LastSeen  int64 `parquet:"last_seen,optional"`
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
	LastSeen  int64   `parquet:"last_seen,optional"`
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

type heldRow struct {
	ID        int64  `parquet:"id"`
	PID       int32  `parquet:"pid"`
	StartTime int64  `parquet:"start_time"`
	FD        int32  `parquet:"fd"`
	Target    string `parquet:"target"`
	Deleted   int32  `parquet:"deleted"`
	FType     string `parquet:"ftype,dict"`
	Mode      string `parquet:"mode,dict"`
	Name      string `parquet:"name"`
	Node      int64  `parquet:"node"`
	FirstSeen int64  `parquet:"first_seen"`
	LastSeen  int64  `parquet:"last_seen,optional"` // 0 is written as NULL
}

func heldOf(r *heldRow, h *heldRec) {
	*r = heldRow{ID: h.ID, PID: int32(h.PID), StartTime: h.StartTime, FD: int32(h.FD), Target: h.Target,
		Deleted: b2i(h.Deleted), FType: h.FType, Mode: h.Mode, Name: h.Name, Node: h.Node, FirstSeen: h.FirstSeen,
		LastSeen: h.LastSeen}
}

type mountRow struct {
	TS           int64  `parquet:"ts"`
	Action       string `parquet:"action,dict"`
	MountID      int32  `parquet:"mount_id"`
	Point        string `parquet:"mount_point"`
	Source       string `parquet:"source,dict"`
	FSType       string `parquet:"fstype,dict"`
	Options      string `parquet:"options"`
	SuperOptions string `parquet:"super_options"`
	Dev          string `parquet:"dev,dict"`
	Root         string `parquet:"root,dict"`
	Seq          int32  `parquet:"seq"`
	LoopFile     string `parquet:"loop_file"`
	UserOptions  string `parquet:"user_options,dict"`
}

type fsRow struct {
	TS      int64 `parquet:"ts"`
	MountID int32 `parquet:"mount_id"`
	FrSize  int64 `parquet:"frsize"`
	Blocks  int64 `parquet:"blocks"`
	BFree   int64 `parquet:"bfree"`
	BAvail  int64 `parquet:"bavail"`
	Files   int64 `parquet:"files"`
	FFree   int64 `parquet:"ffree"`
}

type tcpConnRow struct {
	ID             int64  `parquet:"id"`
	PID            int32  `parquet:"pid"`
	StartTime      int64  `parquet:"start_time"`
	FD             int32  `parquet:"fd"`
	OwnerUntil     int64  `parquet:"owner_until,optional"` // optional: 0 is written as NULL
	IfName         string `parquet:"ifname,dict"`
	Inode          int64  `parquet:"inode"`
	Family         int32  `parquet:"family"`
	LAddr          string `parquet:"laddr,dict"`
	LPort          int32  `parquet:"lport"`
	RAddr          string `parquet:"raddr,dict"`
	RPort          int32  `parquet:"rport"`
	Direction      string `parquet:"direction,dict"`
	OpenTS         int64  `parquet:"open_ts"`
	CloseTS        int64  `parquet:"close_ts,optional"`
	FirstState     int32  `parquet:"first_state"`
	FinalState     int32  `parquet:"final_state"`
	LingerState    int32  `parquet:"linger_state"`
	LingerUntil    int64  `parquet:"linger_until,optional"`
	Retransmits    int32  `parquet:"retransmits"`
	ResetsSent     int32  `parquet:"resets_sent"`
	ResetsReceived int32  `parquet:"resets_received"`
	Source         string `parquet:"source,dict"`
	LastSeen       int64  `parquet:"last_seen,optional"`
	V6Only         int32  `parquet:"v6only"`
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
	V6Only    int32  `parquet:"v6only"`
}

type reconcileRow struct {
	TS       int64  `parquet:"ts"`
	Kind     string `parquet:"kind,dict"`
	DumpRows int32  `parquet:"dump_rows"`
	Missing  int32  `parquet:"missing_from_events"`
	Extra    int32  `parquet:"extra_in_events"`
	Initial  int32  `parquet:"initial"`
}

// tcpConnOf converts a connection to its file row; a is the store's
// address text cache.
func tcpConnOf(r *tcpConnRow, c *store.TCPConn, a *addrCache) {
	*r = tcpConnRow{ID: c.ID, PID: c.PID, StartTime: c.StartTime, FD: c.FD, OwnerUntil: c.OwnerUntil, IfName: c.IfName.String(),
		Inode: int64(c.Inode), Family: int32(c.Family), LAddr: a.text(c.LAddr, c.Family), LPort: int32(c.LPort),
		RAddr: a.text(c.RAddr, c.Family), RPort: int32(c.RPort), Direction: c.Direction.String(), OpenTS: c.OpenTS,
		CloseTS: c.CloseTS, FirstState: int32(c.FirstState), FinalState: int32(c.FinalState),
		LingerState: int32(c.LingerState), LingerUntil: c.LingerUntil, Retransmits: int32(c.Retransmits),
		ResetsSent: int32(c.ResetsSent), ResetsReceived: int32(c.ResetsReceived), Source: c.Source.String(),
		LastSeen: c.LastSeen, V6Only: b2i(c.V6Only)}
}

func keyframeOf(r *keyframeRow, k *store.KeyframeRow, a *addrCache) {
	*r = keyframeRow{TS: k.TS, Proto: k.Proto.String(), Family: int32(k.Family), LAddr: a.text(k.LAddr, k.Family),
		LPort: int32(k.LPort), RAddr: a.text(k.RAddr, k.Family), RPort: int32(k.RPort), Inode: int64(k.Inode),
		State: int32(k.State), RecvQ: k.RecvQ, SendQ: k.SendQ, UID: k.UID, ConnID: k.ConnID, PID: k.PID,
		StartTime: k.StartTime, FD: k.FD, V6Only: b2i(k.V6Only)}
}

// addrCache keeps the text of the addresses written recently: a busy
// server's connections share few addresses, and each one converted anew
// was an allocation per row.
type addrCache struct {
	m map[addrKey]string
}

type addrKey struct {
	a store.Addr
	f uint8
}

func (c *addrCache) text(a store.Addr, family uint8) string {
	k := addrKey{a, family}
	if s, ok := c.m[k]; ok {
		return s
	}
	if c.m == nil || len(c.m) >= 1<<16 {
		c.m = map[addrKey]string{}
	}
	s := a.String(int(family))
	c.m[k] = s
	return s
}

type metaRow struct {
	Run   int64  `parquet:"run"`
	TS    int64  `parquet:"ts"`
	Key   string `parquet:"key"`
	Value string `parquet:"value"`
}

func ptr[T any](v T) *T { return &v }

// val is *p, 0 for nil: optional int64 columns write 0 as NULL, so times
// need no pointer per row.
func val(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

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
		Comm: p.Comm, Cmdline: p.Cmdline, Argv0Len: int32(p.Argv0Len), TTY: int32(p.TTY), SID: int32(p.SID), PGRP: int32(p.PGRP),
		Locked: b2i(p.Locked), FirstSeen: p.FirstSeen, LastSeen: val(p.LastSeen), Ended: val(p.Ended), Source: p.Source,
		Exe: p.Exe, ExecTS: val(p.ExecTS), ExitTS: val(p.ExitTS), ExitCode: i32p(p.ExitCode), Signal: i32p(p.Signal),
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
		CPUTicks: p.CPUTicks, RSSKB: p.RSSKB, VSZKB: p.VSZKB, Threads: int32(p.Threads),
		RChar: p.RChar, WChar: p.WChar, ReadBytes: p.ReadBytes, WriteBytes: p.WriteBytes, CancelledWrite: p.CancelledWrite}
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

// The system-wide counter tables (sys_samples, cpu_samples, disk_samples).
type sysRow struct {
	TS           int64 `parquet:"ts"`
	UptimeMS     int64 `parquet:"uptime_ms"`
	Load1        int32 `parquet:"load1"`
	Load5        int32 `parquet:"load5"`
	Load15       int32 `parquet:"load15"`
	Runnable     int32 `parquet:"runnable"`
	Threads      int32 `parquet:"threads"`
	ProcsRunning int32 `parquet:"procs_running"`
	ProcsBlocked int32 `parquet:"procs_blocked"`
	Intr         int64 `parquet:"intr"`
	Ctxt         int64 `parquet:"ctxt"`
	Forks        int64 `parquet:"forks"`
	SoftIRQ      int64 `parquet:"softirq"`
	MemTotal     int64 `parquet:"mem_total"`
	MemFree      int64 `parquet:"mem_free"`
	MemAvailable int64 `parquet:"mem_available"`
	Buffers      int64 `parquet:"buffers"`
	Cached       int64 `parquet:"cached"`
	SwapCached   int64 `parquet:"swap_cached"`
	Active       int64 `parquet:"active"`
	Inactive     int64 `parquet:"inactive"`
	SwapTotal    int64 `parquet:"swap_total"`
	SwapFree     int64 `parquet:"swap_free"`
	Dirty        int64 `parquet:"dirty"`
	Writeback    int64 `parquet:"writeback"`
	Shmem        int64 `parquet:"shmem"`
	Slab         int64 `parquet:"slab"`
	SReclaimable int64 `parquet:"sreclaimable"`
	PgpgIn       int64 `parquet:"pgpgin"`
	PgpgOut      int64 `parquet:"pgpgout"`
	PswpIn       int64 `parquet:"pswpin"`
	PswpOut      int64 `parquet:"pswpout"`
	PgFault      int64 `parquet:"pgfault"`
	PgMajFault   int64 `parquet:"pgmajfault"`
	// sockstat (schema 3; absent, so NULL, in older files)
	SockUsed      int64 `parquet:"sock_used"`
	TCPInUse      int64 `parquet:"tcp_inuse"`
	TCPOrphan     int64 `parquet:"tcp_orphan"`
	TCPTW         int64 `parquet:"tcp_tw"`
	TCPAlloc      int64 `parquet:"tcp_alloc"`
	TCPMem        int64 `parquet:"tcp_mem"`
	UDPInUse      int64 `parquet:"udp_inuse"`
	UDPMem        int64 `parquet:"udp_mem"`
	UDPLiteInUse  int64 `parquet:"udplite_inuse"`
	RawInUse      int64 `parquet:"raw_inuse"`
	FragInUse     int64 `parquet:"frag_inuse"`
	FragMemory    int64 `parquet:"frag_memory"`
	TCP6InUse     int64 `parquet:"tcp6_inuse"`
	UDP6InUse     int64 `parquet:"udp6_inuse"`
	UDPLite6InUse int64 `parquet:"udplite6_inuse"`
	Raw6InUse     int64 `parquet:"raw6_inuse"`
	Frag6InUse    int64 `parquet:"frag6_inuse"`
	Frag6Memory   int64 `parquet:"frag6_memory"`
}

func sysOf(s *store.SysSample) sysRow {
	return sysRow{TS: s.TS, UptimeMS: s.UptimeMS,
		Load1: int32(s.Load1), Load5: int32(s.Load5), Load15: int32(s.Load15), Runnable: int32(s.Runnable), Threads: int32(s.Threads), ProcsRunning: int32(s.ProcsRunning), ProcsBlocked: int32(s.ProcsBlocked),
		Intr: s.Intr, Ctxt: s.Ctxt, Forks: s.Forks, SoftIRQ: s.SoftIRQ, MemTotal: s.MemTotal, MemFree: s.MemFree, MemAvailable: s.MemAvailable, Buffers: s.Buffers, Cached: s.Cached, SwapCached: s.SwapCached, Active: s.Active, Inactive: s.Inactive, SwapTotal: s.SwapTotal, SwapFree: s.SwapFree, Dirty: s.Dirty, Writeback: s.Writeback, Shmem: s.Shmem, Slab: s.Slab, SReclaimable: s.SReclaimable, PgpgIn: s.PgpgIn, PgpgOut: s.PgpgOut, PswpIn: s.PswpIn, PswpOut: s.PswpOut, PgFault: s.PgFault, PgMajFault: s.PgMajFault,
		SockUsed: s.SockUsed, TCPInUse: s.TCPInUse, TCPOrphan: s.TCPOrphan, TCPTW: s.TCPTW, TCPAlloc: s.TCPAlloc, TCPMem: s.TCPMem,
		UDPInUse: s.UDPInUse, UDPMem: s.UDPMem, UDPLiteInUse: s.UDPLiteInUse, RawInUse: s.RawInUse, FragInUse: s.FragInUse,
		FragMemory: s.FragMemory, TCP6InUse: s.TCP6InUse, UDP6InUse: s.UDP6InUse, UDPLite6InUse: s.UDPLite6InUse,
		Raw6InUse: s.Raw6InUse, Frag6InUse: s.Frag6InUse, Frag6Memory: s.Frag6Memory}
}

type cpuRow struct {
	TS        int64 `parquet:"ts"`
	CPU       int32 `parquet:"cpu"`
	User      int64 `parquet:"user"`
	Nice      int64 `parquet:"nice"`
	System    int64 `parquet:"system"`
	Idle      int64 `parquet:"idle"`
	IOWait    int64 `parquet:"iowait"`
	IRQ       int64 `parquet:"irq"`
	SoftIRQ   int64 `parquet:"softirq"`
	Steal     int64 `parquet:"steal"`
	Guest     int64 `parquet:"guest"`
	GuestNice int64 `parquet:"guest_nice"`
}

func cpuOf(c store.CPUSample) cpuRow {
	return cpuRow{TS: c.TS, CPU: int32(c.CPU), User: c.T[0], Nice: c.T[1], System: c.T[2], Idle: c.T[3], IOWait: c.T[4], IRQ: c.T[5], SoftIRQ: c.T[6], Steal: c.T[7], Guest: c.T[8], GuestNice: c.T[9]}
}

type diskRow struct {
	TS          int64  `parquet:"ts"`
	Major       int32  `parquet:"major"`
	Minor       int32  `parquet:"minor"`
	Name        string `parquet:"name,dict"`
	Part        int32  `parquet:"part"`
	RdIOs       int64  `parquet:"rd_ios"`
	RdMerges    int64  `parquet:"rd_merges"`
	RdSectors   int64  `parquet:"rd_sectors"`
	RdTicks     int64  `parquet:"rd_ticks"`
	WrIOs       int64  `parquet:"wr_ios"`
	WrMerges    int64  `parquet:"wr_merges"`
	WrSectors   int64  `parquet:"wr_sectors"`
	WrTicks     int64  `parquet:"wr_ticks"`
	DcIOs       int64  `parquet:"dc_ios"`
	DcMerges    int64  `parquet:"dc_merges"`
	DcSectors   int64  `parquet:"dc_sectors"`
	DcTicks     int64  `parquet:"dc_ticks"`
	InFlight    int64  `parquet:"in_flight"`
	IOTicks     int64  `parquet:"io_ticks"`
	TimeInQueue int64  `parquet:"time_in_queue"`
	FlIOs       int64  `parquet:"fl_ios"`
	FlTicks     int64  `parquet:"fl_ticks"`
}

func diskOf(d store.DiskSample) diskRow {
	return diskRow{TS: d.TS, Major: int32(d.Major), Minor: int32(d.Minor), Name: d.Name, Part: int32(b2i(d.Part)),
		RdIOs: d.V[0], RdMerges: d.V[1], RdSectors: d.V[2], RdTicks: d.V[3], WrIOs: d.V[4], WrMerges: d.V[5], WrSectors: d.V[6], WrTicks: d.V[7], DcIOs: d.V[8], DcMerges: d.V[9], DcSectors: d.V[10], DcTicks: d.V[11], InFlight: d.V[12], IOTicks: d.V[13], TimeInQueue: d.V[14], FlIOs: d.V[15], FlTicks: d.V[16]}
}

type netCounterRow struct {
	TS      int64  `parquet:"ts"`
	Pos     int32  `parquet:"pos"`
	Section string `parquet:"section,dict"`
	Name    string `parquet:"name,dict"`
	Value   int64  `parquet:"value"`
}

// linkRow: store.LinkRow. LinkStatCols names its Stats columns, in order.
type linkRow struct {
	TS             int64  `parquet:"ts"`
	Index          int32  `parquet:"ifindex"`
	Type           int32  `parquet:"type"`
	Gone           int32  `parquet:"gone"`
	Flags          int64  `parquet:"flags"`
	XDP            int32  `parquet:"xdp"`
	HasStats       int32  `parquet:"has_stats"`
	Name           string `parquet:"name,dict"`
	Qdisc          string `parquet:"qdisc,dict"`
	Alias          string `parquet:"alias,dict"`
	Kind           string `parquet:"kind,dict"`
	SlaveKind      string `parquet:"slave_kind,dict"`
	PhysPortName   string `parquet:"phys_port_name,dict"`
	ParentBus      string `parquet:"parent_bus,dict"`
	ParentDev      string `parquet:"parent_dev,dict"`
	AltNames       string `parquet:"alt_names,dict"`
	MTU            int64  `parquet:"mtu"`
	Master         int64  `parquet:"master"`
	Link           int64  `parquet:"link"`
	LinkNetnsID    int64  `parquet:"link_netnsid"`
	OperState      int64  `parquet:"operstate"`
	LinkMode       int64  `parquet:"linkmode"`
	Group          int64  `parquet:"grp"`
	TxQLen         int64  `parquet:"txqlen"`
	Promiscuity    int64  `parquet:"promiscuity"`
	Allmulti       int64  `parquet:"allmulti"`
	MinMTU         int64  `parquet:"min_mtu"`
	MaxMTU         int64  `parquet:"max_mtu"`
	NetnsImmutable int64  `parquet:"netns_immutable"`
	AddrGenMode    int64  `parquet:"addr_gen_mode"`
	NumTxQueues    int64  `parquet:"num_tx_queues"`
	NumRxQueues    int64  `parquet:"num_rx_queues"`
	GSOMaxSize     int64  `parquet:"gso_max_size"`
	GSOMaxSegs     int64  `parquet:"gso_max_segs"`
	TSOMaxSize     int64  `parquet:"tso_max_size"`
	TSOMaxSegs     int64  `parquet:"tso_max_segs"`
	GROMaxSize     int64  `parquet:"gro_max_size"`
	GSOIPv4MaxSize int64  `parquet:"gso_ipv4_max_size"`
	GROIPv4MaxSize int64  `parquet:"gro_ipv4_max_size"`
	ProtoDown      int64  `parquet:"proto_down"`
	CarrierChanges int64  `parquet:"carrier_changes"`
	Address        []byte `parquet:"address"`
	Broadcast      []byte `parquet:"broadcast"`
	PermAddress    []byte `parquet:"perm_address"`
	PhysPortID     []byte `parquet:"phys_port_id"`
	PhysSwitchID   []byte `parquet:"phys_switch_id"`
	InfoData       []byte `parquet:"info_data"`
	SlaveData      []byte `parquet:"slave_data"`
	S0             int64  `parquet:"rx_packets"`
	S1             int64  `parquet:"tx_packets"`
	S2             int64  `parquet:"rx_bytes"`
	S3             int64  `parquet:"tx_bytes"`
	S4             int64  `parquet:"rx_errors"`
	S5             int64  `parquet:"tx_errors"`
	S6             int64  `parquet:"rx_dropped"`
	S7             int64  `parquet:"tx_dropped"`
	S8             int64  `parquet:"multicast"`
	S9             int64  `parquet:"collisions"`
	S10            int64  `parquet:"rx_length_errors"`
	S11            int64  `parquet:"rx_over_errors"`
	S12            int64  `parquet:"rx_crc_errors"`
	S13            int64  `parquet:"rx_frame_errors"`
	S14            int64  `parquet:"rx_fifo_errors"`
	S15            int64  `parquet:"rx_missed_errors"`
	S16            int64  `parquet:"tx_aborted_errors"`
	S17            int64  `parquet:"tx_carrier_errors"`
	S18            int64  `parquet:"tx_fifo_errors"`
	S19            int64  `parquet:"tx_heartbeat_errors"`
	S20            int64  `parquet:"tx_window_errors"`
	S21            int64  `parquet:"rx_compressed"`
	S22            int64  `parquet:"tx_compressed"`
	S23            int64  `parquet:"rx_nohandler"`
	S24            int64  `parquet:"rx_otherhost_dropped"`
}

// LinkStatCols are the links table's statistics columns, in store.LinkRow.Stats order.
var LinkStatCols = []string{"rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped", "multicast", "collisions", "rx_length_errors", "rx_over_errors", "rx_crc_errors", "rx_frame_errors", "rx_fifo_errors", "rx_missed_errors", "tx_aborted_errors", "tx_carrier_errors", "tx_fifo_errors", "tx_heartbeat_errors", "tx_window_errors", "rx_compressed", "tx_compressed", "rx_nohandler", "rx_otherhost_dropped"}

func linkOf(l *store.LinkRow) linkRow {
	return linkRow{TS: l.TS, Index: int32(l.Index), Type: int32(l.Type), Gone: b2i(l.Gone), Flags: l.Flags, XDP: b2i(l.XDP), HasStats: b2i(l.HasStats),
		Name: l.Name, Qdisc: l.Qdisc, Alias: l.Alias, Kind: l.Kind, SlaveKind: l.SlaveKind, PhysPortName: l.PhysPortName, ParentBus: l.ParentBus, ParentDev: l.ParentDev, AltNames: l.AltNames, MTU: l.MTU, Master: l.Master, Link: l.Link, LinkNetnsID: l.LinkNetnsID, OperState: l.OperState, LinkMode: l.LinkMode, Group: l.Group, TxQLen: l.TxQLen, Promiscuity: l.Promiscuity, Allmulti: l.Allmulti, MinMTU: l.MinMTU, MaxMTU: l.MaxMTU, NetnsImmutable: l.NetnsImmutable, AddrGenMode: l.AddrGenMode, NumTxQueues: l.NumTxQueues, NumRxQueues: l.NumRxQueues, GSOMaxSize: l.GSOMaxSize, GSOMaxSegs: l.GSOMaxSegs, TSOMaxSize: l.TSOMaxSize, TSOMaxSegs: l.TSOMaxSegs, GROMaxSize: l.GROMaxSize, GSOIPv4MaxSize: l.GSOIPv4MaxSize, GROIPv4MaxSize: l.GROIPv4MaxSize, ProtoDown: l.ProtoDown, CarrierChanges: l.CarrierChanges, Address: l.Address, Broadcast: l.Broadcast, PermAddress: l.PermAddress, PhysPortID: l.PhysPortID, PhysSwitchID: l.PhysSwitchID, InfoData: l.InfoData, SlaveData: l.SlaveData,
		S0: l.Stats[0], S1: l.Stats[1], S2: l.Stats[2], S3: l.Stats[3], S4: l.Stats[4], S5: l.Stats[5], S6: l.Stats[6], S7: l.Stats[7], S8: l.Stats[8], S9: l.Stats[9], S10: l.Stats[10], S11: l.Stats[11], S12: l.Stats[12], S13: l.Stats[13], S14: l.Stats[14], S15: l.Stats[15], S16: l.Stats[16], S17: l.Stats[17], S18: l.Stats[18], S19: l.Stats[19], S20: l.Stats[20], S21: l.Stats[21], S22: l.Stats[22], S23: l.Stats[23], S24: l.Stats[24]}
}

type addrRow struct {
	TS        int64  `parquet:"ts"`
	Action    string `parquet:"action,dict"`
	Seq       int32  `parquet:"seq"`
	Family    int32  `parquet:"family"`
	PrefixLen int32  `parquet:"prefixlen"`
	Scope     int32  `parquet:"scope"`
	Index     int32  `parquet:"ifindex"`
	Flags     int64  `parquet:"flags"`
	Local     []byte `parquet:"local"`
	Address   []byte `parquet:"address"`
	Broadcast []byte `parquet:"broadcast"`
	Anycast   []byte `parquet:"anycast"`
	Multicast []byte `parquet:"multicast"`
	Label     string `parquet:"label,dict"`
	Metric    int64  `parquet:"metric"`
	Proto     int64  `parquet:"proto"`
	Valid     int64  `parquet:"valid_lft"`
	Preferred int64  `parquet:"preferred_lft"`
}

func addrOf(a *store.AddrRow) addrRow {
	return addrRow{TS: a.TS, Action: a.Action, Seq: int32(a.Seq), Family: int32(a.Family), PrefixLen: int32(a.PrefixLen),
		Scope: int32(a.Scope), Index: int32(a.Index), Flags: a.Flags, Local: a.Local, Address: a.Address,
		Broadcast: a.Broadcast, Anycast: a.Anycast, Multicast: a.Multicast, Label: a.Label, Metric: a.Metric,
		Proto: a.Proto, Valid: a.Valid, Preferred: a.Preferred}
}

type routingRow struct {
	TS     int64  `parquet:"ts"`
	Kind   string `parquet:"kind,dict"`
	Action string `parquet:"action,dict"`
	Key    string `parquet:"key"`
	Seq    int32  `parquet:"seq"`
	Family int32  `parquet:"family"`
	Msg    []byte `parquet:"msg"`
}

type kmsgRow struct {
	TS     int64  `parquet:"ts"`
	BootID string `parquet:"boot_id,dict"`
	Kind   string `parquet:"kind,dict"`
	Seq    int64  `parquet:"seq"`
	Prio   int32  `parquet:"prio"`
	MonoUS int64  `parquet:"mono_us"`
	Caller string `parquet:"caller,dict"`
	Msg    string `parquet:"msg"`
	BootUS int64  `parquet:"boot_us"`
	SuspUS int64  `parquet:"susp_us"`
}

type unitRow struct {
	TS          int64  `parquet:"ts"`
	Action      string `parquet:"action,dict"`
	Seq         int32  `parquet:"seq"`
	Name        string `parquet:"name,dict"`
	Description string `parquet:"description,dict"`
	Load        string `parquet:"load,dict"`
	Active      string `parquet:"active,dict"`
	Sub         string `parquet:"sub,dict"`
	Following   string `parquet:"following,dict"`
	JobID       int64  `parquet:"job_id"`
	JobType     string `parquet:"job_type,dict"`
}
