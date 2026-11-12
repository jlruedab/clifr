package store

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
	// Read from /proc when the process is first sampled, at its exec and on
	// fd walks (schema 8); empty for event-only processes.
	Label string // /proc/<pid>/attr/current (ps -Z)
	RUID  int    // real uid (pidstat); the effective one (UID) when not read from /proc
	// NUL bytes after the command line in /proc/<pid>/cmdline (normally 1;
	// 0: unknown, an event-only process).
	CmdlinePad int
	Cgroup     string // /proc/<pid>/cgroup
	// NetNS: the network namespace (inode of /proc/<pid>/ns/net), 0 for the
	// host's (schema 10), read when the process is first sampled and at an exec.
	NetNS uint32
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
	Label, Cgroup string
	RUID          int
	CmdlinePad    int
	NetNS         uint32
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
	// /proc/net/sockstat and sockstat6 (schema 3): socket counts, mem in pages.
	SockUsed, TCPInUse, TCPOrphan, TCPTW, TCPAlloc, TCPMem int64
	UDPInUse, UDPMem, UDPLiteInUse, RawInUse, FragInUse    int64
	FragMemory, TCP6InUse, UDP6InUse, UDPLite6InUse        int64
	Raw6InUse, Frag6InUse, Frag6Memory                     int64
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
	OpenTS      int64
	CloseTS     int64
	LingerUntil int64 // the time-wait socket's end (estimated, or exact from an event)
	LastSeen    int64 // time of this version of the row
	LAddr       Addr
	RAddr       Addr
	PID         int32 // owner (connect, listen or accept); 0: unknown
	FD          int32 // owner's fd; -1: unknown
	// Inode: 32 bits (sockfs numbers come from get_next_ino, and sock_diag
	// reports them as 32-bit idiag_inode); with NetNS the row stays 128 bytes.
	Inode       uint32
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
	// NetNS: the socket's network namespace (inode number), 0 for the host's
	// (schema 10): the same addresses exist in many (containers, pods).
	NetNS uint32
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
	NetNS        uint32 // 0: the host's
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
	// Schema 8. From stat and statm at every sample: page faults
	// (cumulative), priority as top's PR, policy, real-time priority, the
	// CPU it last ran on, shared memory (top's SHR).
	MinFlt, MajFlt, ShrKB             int64
	Priority, Policy, RTPriority, CPU int
	PSFlags                           int // ps's F: (PF_* >> 6) & 7 (forked without exec, used superuser privileges)
	// pidstat: system time (CPUTicks - STimeTicks = user time, guest time
	// included), guest time, block I/O delay (ticks) and RSS as stat reports
	// it (an approximate counter since Linux 6.2; RSSKB is statm's).
	STimeTicks, GuestTicks, BlkioTicks, RSSStatKB int64
	// From status and wchan when the process used CPU since its last sample,
	// and on fd-walk samples: context switches (cumulative) and the kernel
	// function it waits in ("0": running).
	VolCtx, NonVolCtx int64
	Wchan             string
	WaitNS            int64 // run-queue wait (schedstat; pidstat's %wait)
}

// NetCounter is one protocol counter (/proc/net/snmp, netstat, snmp6), named
// as nstat names it, at its position in those files. Written when it
// changed, and all of them at a run's first sample and every
// NetCountersFullMS.
type NetCounter struct {
	TS      int64
	Pos     int
	Section string // in /proc/net/snmp or netstat; "" in snmp6
	Name    string
	Value   int64
}

// LinkRow is one network interface (rtnl.Link) at a system sample: written
// when anything about it changed (its counters included), all of them every
// NetCountersFullMS, and with Gone when it went away. Numbers are -1 when the
// kernel did not report them.
type LinkRow struct {
	TS                                    int64
	Index, Type                           int
	Gone                                  bool
	Flags                                 int64
	Name, Qdisc, Alias, Kind, SlaveKind   string
	PhysPortName, ParentBus, ParentDev    string
	AltNames                              string // newline-separated
	MTU, Master, Link, LinkNetnsID        int64
	OperState, LinkMode, Group, TxQLen    int64
	Promiscuity, Allmulti, MinMTU, MaxMTU int64
	NetnsImmutable, AddrGenMode           int64
	NumTxQueues, NumRxQueues              int64
	GSOMaxSize, GSOMaxSegs                int64
	TSOMaxSize, TSOMaxSegs, GROMaxSize    int64
	GSOIPv4MaxSize, GROIPv4MaxSize        int64
	ProtoDown, CarrierChanges             int64
	Address, Broadcast, PermAddress       []byte
	PhysPortID, PhysSwitchID              []byte
	InfoData, SlaveData                   []byte
	XDP, HasStats                         bool
	Stats                                 [25]int64 // rtnl_link_stats64, rx_packets .. rx_otherhost_dropped
}

// AddrRow is one interface address (rtnl.Addr): Action "present" for the
// addresses of a snapshot (at a run's start, every NetSnapshotMS and after
// lost notifications; Seq: their order), "add" for a new or changed one and
// "del" for one removed, at the time the kernel announced it. Valid and
// Preferred are the lifetimes left at TS, in seconds (0xffffffff: forever).
type AddrRow struct {
	TS                              int64
	Action                          string
	Seq                             int
	Family, PrefixLen, Scope, Index int
	Flags                           int64
	Local, Address                  []byte
	Broadcast, Anycast, Multicast   []byte
	Label                           string
	Metric, Proto, Valid, Preferred int64
}

// RoutingRow is a route or a policy routing rule (Kind "route", "rule") as
// the kernel sent it: Msg is the rtnetlink body (struct rtmsg or
// fib_rule_hdr and attributes), parsed when printed. Action and Seq as in
// AddrRow; Key identifies it across changes.
type RoutingRow struct {
	TS                int64
	Kind, Action, Key string
	Seq, Family       int
	Msg               []byte
}

// KmsgRow is a kernel log record from /dev/kmsg (Kind "msg"), or the state
// of the kernel's log buffer (Kind "ring"). A record: Seq, Prio (facility <<
// 3 | level), MonoUS (the kernel's timestamp, µs since boot without
// suspends), Caller (PRINTK_CALLER, e.g. "T123", "" without it) and Msg (the
// text as /dev/kmsg escapes it, redacted). A ring row: Seq is the oldest
// record still in the buffer, BootUS the boot time as dmesg computes it
// (CLOCK_REALTIME - CLOCK_BOOTTIME) and SuspUS the time suspended
// (CLOCK_BOOTTIME - CLOCK_MONOTONIC), both in µs. TS is when it was read.
type KmsgRow struct {
	TS             int64
	BootID, Kind   string
	Seq, MonoUS    int64
	Prio           int
	Caller, Msg    string
	BootUS, SuspUS int64
}

// UnitRow is a systemd unit as ListUnits returns it: Action "present" (a
// snapshot of every loaded unit, Seq its place), "change" (a new unit, or
// one whose values changed) or "gone" (no longer loaded).
type UnitRow struct {
	TS                                              int64
	Action                                          string
	Seq                                             int
	Name, Description, Load, Active, Sub, Following string
	JobID                                           int64
	JobType                                         string
}

// CgroupRow is a cgroup of the hierarchy systemd uses (procfs.SystemdCgroup):
// written the first time a run sees it (as a process's cgroup or an
// ancestor of one), again every NetSnapshotMS and when the cgroup was
// recreated (a new ID). Delegate: systemd's trusted.delegate or
// user.delegate attribute (systemd-cgls marks it). ID: the cgroup's id (its
// inode); Xattrs: its user.* and trusted.* attributes as "name=value" lines
// in the kernel's order (systemd 252's systemd-cgls prints both).
type CgroupRow struct {
	TS       int64
	Path     string
	Delegate bool
	ID       int64
	Xattrs   string
}

// SnapshotRow is one line of a file recorded whole (procfs.SnapSources) at
// a system sample. Full rows: the whole file, written at a run's first
// read, every NetCountersFullMS and whenever its lines' keys or their order
// changed (a file without lines: one Full row with Pos -1). Otherwise only
// the lines that changed, at the position of the last full copy.
type SnapshotRow struct {
	TS          int64
	Source, Key string
	Pos         int
	Full        bool
	Line        string
}

// BlockDevRow is a block device of /sys/block or one of its partitions
// (Parent: its disk) at a system sample, as lsblk reads it: written when
// anything changed, all of them every NetCountersFullMS, and with Gone when
// it went away. Size in bytes; RO, RM and SCSIType -1 when sysfs has no such
// attribute; Holders and Slaves comma-separated; FSType, FSVer, Label (as
// udev encodes it: \x20) and UUID from udev's database.
type BlockDevRow struct {
	TS                     int64
	Name, Parent           string
	Gone, Hidden           bool
	Maj, Min               int
	Size, RO, RM, SCSIType int64
	DMName, DMUUID         string
	MDLevel, LoopFile      string
	Holders, Slaves        string
	FSType, FSVer          string
	Label, UUID            string
}

// NeighRow is one neighbour entry (rtnl.Neigh) at a system sample, Pos its
// place in the dump. Whole: every entry, written at a run's first dump,
// every NetCountersFullMS and when the entries or their order changed (no
// entries: one Whole row with Pos -1); otherwise only the changed ones.
// The cacheinfo ages are kept as times (ms): when the entry was last
// confirmed, used and updated (0: the kernel sent no cacheinfo).
type NeighRow struct {
	TS, Pos                        int64
	Whole                          bool
	Family, Index                  int
	State                          int
	Flags, Type                    int
	ExtFlags                       int64
	Dst, LLAddr                    []byte
	HasLLAddr                      bool
	Probes, Protocol               int64
	ConfirmedMS, UsedMS, UpdatedMS int64
	RefCnt                         int64
}

// NetSnapshotMS: how often the addresses (later routes and rules) are
// written whole between their change notifications, and everything else
// that is written again hourly (OtherHour).
const NetSnapshotMS = 60 * 60 * 1000

// OtherHour reports whether Unix ms times a and b are in different UTC
// hours. The hourly rewrites (the run's meta, the mount table, values of
// idle processes and sockets, file-system usage, cgroups, units, addresses
// and routes) happen at the first chance in each UTC hour, not an hour after
// the previous one: retention deletes whole UTC hours, so each hour kept
// begins with its own copy. A run-phased rewrite left the oldest hour kept
// without one for up to an hour (2026-11-12, retention run in the VMs).
func OtherHour(a, b int64) bool { return a/NetSnapshotMS != b/NetSnapshotMS }

// NetCountersFullMS: how often every protocol counter is written, so a moment
// needs only the rows of the 5 minutes before it.
const NetCountersFullMS = 5 * 60 * 1000

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

// Batch is everything one sample writes.
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
	NetCounters []NetCounter
	Links       []LinkRow
	Addrs       []AddrRow
	Routing     []RoutingRow
	Kmsg        []KmsgRow
	Units       []UnitRow
	Cgroups     []CgroupRow
	Snapshots   []SnapshotRow
	BlockDevs   []BlockDevRow
	Neighs      []NeighRow
}

// Rows is the number of row writes in the batch, excluding the sample row.
func (b *Batch) Rows() int {
	return len(b.ProcInserts) + len(b.ProcUpdates) + len(b.ProcCloses) + len(b.ProcSamples) +
		len(b.SockInserts) + len(b.SockCloses) + len(b.SockSamples) +
		len(b.OwnInserts) + len(b.OwnCloses) + len(b.FileInserts) + len(b.FileCloses) +
		len(b.Guard) + len(b.Verify) + len(b.Skips) + len(b.ProcExits) + len(b.OOMEvents) + len(b.Stats) +
		len(b.HeldInserts) + len(b.HeldCloses) + len(b.Mounts) +
		len(b.TCPConns) + len(b.TCPTrans) + len(b.Keyframes) + len(b.Reconcile) +
		len(b.CPUs) + len(b.Disks) + len(b.FSSamples) + len(b.NetCounters) + len(b.Links) + len(b.Addrs) + len(b.Routing) + len(b.Kmsg) + len(b.Units) + len(b.Cgroups) + len(b.Snapshots) + len(b.BlockDevs) + len(b.Neighs)
}
