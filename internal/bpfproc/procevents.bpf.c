//go:build ignore

// SPDX-License-Identifier: GPL-2.0
//
// Process lifecycle and OOM events for sosv-record.
//
// No vmlinux.h: the few kernel structures read here are declared below with
// preserve_access_index, so CO-RE relocates every field to the running
// kernel's layout. Built twice by bpf2go (see gen.go): with a ring buffer,
// and with -DUSE_PERF for kernels without one.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define FILENAME_MAX_ 256
#define ARGS_MAX 1024 // command line bytes kept (more is marked truncated)

// ---- the kernel structures we read (CO-RE) ----

typedef struct { int counter; } atomic_t;

struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
} __attribute__((preserve_access_index));

struct tty_driver {
	int major;
	int minor_start;
} __attribute__((preserve_access_index));

struct tty_struct {
	int index;
	struct tty_driver *driver;
} __attribute__((preserve_access_index));

struct upid { int nr; } __attribute__((preserve_access_index));
struct pid { struct upid numbers[1]; } __attribute__((preserve_access_index));

// enum pid_type since Linux 4.19, when the process group and session moved
// to signal_struct (pids[]) and PIDTYPE_TGID was added. RHEL 8's 4.18 has
// signal->pids[] with the old order (PID, PGID, SID, TGID): the indices are
// taken from the running kernel's enum (CO-RE).
enum pid_type { PIDTYPE_PID, PIDTYPE_TGID, PIDTYPE_PGID, PIDTYPE_SID, PIDTYPE_MAX };

struct signal_struct {
	atomic_t live; // threads still running; 0 once the whole process has exited
	struct pid *pids[4];
	struct tty_struct *tty; // controlling terminal
} __attribute__((preserve_access_index));

struct task_struct {
	int pid; // thread id
	int tgid; // process id
	int exit_code;
	char comm[TASK_COMM_LEN];
	struct task_struct *group_leader; // the process's main thread
	struct task_struct *real_parent;
	struct mm_struct *mm;
	struct signal_struct *signal;
} __attribute__((preserve_access_index));

// The start time /proc/<pid>/stat reports: start_boottime since 5.5,
// real_start_time before.
struct task_struct___new { __u64 start_boottime; } __attribute__((preserve_access_index));
struct task_struct___old { __u64 real_start_time; } __attribute__((preserve_access_index));

struct linux_binprm { const char *filename; } __attribute__((preserve_access_index));

struct trace_event_raw_sched_process_exec {
	__u32 __data_loc_filename;
} __attribute__((preserve_access_index));

struct trace_event_raw_sched_process_fork {
	int child_pid;
} __attribute__((preserve_access_index));

struct trace_event_raw_mark_victim {
	int pid;
	unsigned long anon_rss; // kB; these three exist since Linux 6.x
	unsigned long file_rss;
	unsigned long shmem_rss;
} __attribute__((preserve_access_index));

// ---- events ----

enum kind { EV_FORK = 1, EV_EXEC = 2, EV_EXIT = 3, EV_OOM = 4 };
#define NKINDS 5 // indexes of the drops map: one per kind

struct event {
	__u32 kind;
	__u32 pid; // process (tgid); fork: the child
	__u32 ppid;
	__u32 uid;
	__u64 mono_ns; // CLOCK_MONOTONIC when the event happened
	__u64 start_ns; // process start, ns since boot (0: unknown)
	__s32 exit_code; // exit: raw wait status; oom: -1
	__u32 args_len; // exec: full length of the argument area (may exceed ARGS_MAX)
	__u64 rss_kb; // oom: victim RSS from the tracepoint (0: unknown)
	__u32 tty_nr; // controlling terminal, encoded as /proc/<pid>/stat shows it (0: none)
	__s32 sid; // session and process group ids (init pid namespace)
	__s32 pgrp;
	__u32 flags; // FLAG_*
	char comm[TASK_COMM_LEN];
	char filename[FILENAME_MAX_];
	char args[ARGS_MAX];
};

#define FLAG_TTY 1 // tty_nr, sid and pgrp are set

// Fork, exit and OOM events are sent without filename and args.
#define SHORT_EVENT __builtin_offsetof(struct event, filename)

#ifdef USE_PERF
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");
#define OUTPUT(ctx, e, size, wake) bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, size)
#else
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 << 20); // userspace may resize
} events SEC(".maps");
// The reader is woken only for events it must act on at once (it reads
// /proc while the process still exists) and when the buffer is a quarter
// full; otherwise it takes what has gathered once a second and before each
// sample. One wake-up per event cost the recorder more than handling it.
#define OUTPUT(ctx, e, size, wake) bpf_ringbuf_output(&events, e, size, \
	(wake) || bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA) > bpf_ringbuf_query(&events, BPF_RB_RING_SIZE) / 4 \
		? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP)
#endif

// Events that could not be sent (buffer full), per kind.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NKINDS);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

// Scratch space: struct event is larger than the 512-byte BPF stack. One
// slot per program: a program that was interrupted or preempted may find
// another one running on its CPU, but never itself.
enum slot { SLOT_FORK, SLOT_EXEC, SLOT_EXEC2, SLOT_EXIT, SLOT_EXIT2, SLOT_OOM, NSLOTS };
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NSLOTS);
	__type(key, __u32);
	__type(value, struct event);
} scratch SEC(".maps");

static __always_inline struct event *new_event(__u32 kind, __u32 slot)
{
	struct event *e = bpf_map_lookup_elem(&scratch, &slot);
	if (!e)
		return 0;
	e->kind = kind;
	e->mono_ns = bpf_ktime_get_ns();
	e->pid = 0;
	e->ppid = 0;
	e->uid = 0;
	e->comm[0] = 0;
	e->exit_code = 0;
	e->args_len = 0;
	e->rss_kb = 0;
	e->start_ns = 0;
	e->tty_nr = 0;
	e->sid = 0;
	e->pgrp = 0;
	e->flags = 0;
	return e;
}

// send outputs e; wake: userspace must see it at once (see OUTPUT).
static __always_inline void send(void *ctx, struct event *e, __u64 size, int wake)
{
	if (OUTPUT(ctx, e, size, wake) != 0) {
		__u32 k = e->kind;
		__u64 *n = bpf_map_lookup_elem(&drops, &k);
		if (n)
			__sync_fetch_and_add(n, 1);
	}
}

static __always_inline __u64 task_start(struct task_struct *t)
{
	struct task_struct___new *n = (void *)t;
	if (bpf_core_field_exists(n->start_boottime))
		return BPF_CORE_READ(n, start_boottime);
	struct task_struct___old *o = (void *)t;
	return BPF_CORE_READ(o, real_start_time);
}

// fill_tty: terminal, session and process group of t's process, as
// /proc/<pid>/stat shows them (tty_nr: new_encode_dev of the terminal's
// device number), so that userspace need not read /proc for them. Not on
// kernels before 4.19 (no signal->pids): userspace reads /proc there.
static __always_inline void fill_tty(struct event *e, struct task_struct *t)
{
	struct signal_struct *sig = BPF_CORE_READ(t, signal);
	if (!sig || !bpf_core_field_exists(sig->pids))
		return;
	struct pid **pids = (struct pid **)__builtin_preserve_access_index(&sig->pids[0]);
	__u64 sid_i = bpf_core_enum_value(enum pid_type, PIDTYPE_SID);
	__u64 pgid_i = bpf_core_enum_value(enum pid_type, PIDTYPE_PGID);
	struct pid *p = 0;
	if (sid_i < 4)
		bpf_probe_read_kernel(&p, sizeof(p), pids + sid_i);
	if (p)
		e->sid = BPF_CORE_READ(p, numbers[0].nr);
	p = 0;
	if (pgid_i < 4)
		bpf_probe_read_kernel(&p, sizeof(p), pids + pgid_i);
	if (p)
		e->pgrp = BPF_CORE_READ(p, numbers[0].nr);
	struct tty_struct *tty = BPF_CORE_READ(sig, tty);
	if (tty) {
		__u32 major = BPF_CORE_READ(tty, driver, major);
		__u32 minor = BPF_CORE_READ(tty, driver, minor_start) + BPF_CORE_READ(tty, index);
		e->tty_nr = (minor & 0xff) | (major << 8) | ((minor & ~0xffu) << 12);
	}
	e->flags |= FLAG_TTY;
}

// fill_current: the calling process's identity. The current task may be any
// of its threads (at exit, whichever exits last), so start time and comm
// come from the thread group leader, as in /proc/<pid>/stat.
static __always_inline void fill_current(struct event *e, struct task_struct *t)
{
	struct task_struct *leader = BPF_CORE_READ(t, group_leader);
	e->pid = BPF_CORE_READ(t, tgid);
	e->ppid = BPF_CORE_READ(leader, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->start_ns = task_start(leader);
	BPF_CORE_READ_STR_INTO(&e->comm, leader, comm);
	fill_tty(e, t);
}

static __always_inline int exec_event(void *ctx, __u32 slot, const char *filename)
{
	struct event *e = new_event(EV_EXEC, slot);
	if (!e)
		return 0;
	struct task_struct *t = (void *)bpf_get_current_task();
	fill_current(e, t);
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), filename);

	unsigned long start = BPF_CORE_READ(t, mm, arg_start);
	unsigned long end = BPF_CORE_READ(t, mm, arg_end);
	__u64 len = end > start ? end - start : 0;
	e->args_len = len;
	if (len > ARGS_MAX - 1)
		len = ARGS_MAX - 1;
	if (bpf_probe_read_user(e->args, len & (ARGS_MAX - 1), (void *)start) != 0)
		e->args_len = 0;
	// A long command line is completed from /proc, and without terminal
	// information (kernels before 4.19) the stat file is read.
	send(ctx, e, sizeof(*e), e->args_len > ARGS_MAX - 1 || !(e->flags & FLAG_TTY));
	return 0;
}

static __always_inline int exit_event(void *ctx, __u32 slot)
{
	struct task_struct *t = (void *)bpf_get_current_task();
	// One event per process: the last thread to exit (signal->live is
	// decremented before this tracepoint).
	if (BPF_CORE_READ(t, signal, live.counter) != 0)
		return 0;
	struct event *e = new_event(EV_EXIT, slot);
	if (!e)
		return 0;
	fill_current(e, t);
	e->exit_code = BPF_CORE_READ(t, exit_code);
	send(ctx, e, SHORT_EVENT, 0);
	return 0;
}

// Exec and exit, preferred: BTF tracepoints, two programs each.
//
// The kernel does not run a tracing program on a CPU where that program is
// already running: one that was interrupted, or preempted, when another
// process execs or exits there. (A classic tracepoint program is skipped
// while any tracepoint or kprobe program runs.) So the first program marks
// the CPU while it runs, and the second, a program of its own, reports the
// events that find the mark: the ones the first could not see.
enum { BUSY_EXEC, BUSY_EXIT, RESCUED_EXEC, RESCUED_EXIT, NBUSY };
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NBUSY);
	__type(key, __u32);
	__type(value, __u64);
} busy SEC(".maps");

static __always_inline __u64 *busy_slot(__u32 k)
{
	return bpf_map_lookup_elem(&busy, &k);
}

// rescue reports whether the first program is stopped on this CPU.
static __always_inline int rescue(__u32 busy_key, __u32 count_key)
{
	__u64 *b = busy_slot(busy_key);
	if (!b || !*b)
		return 0;
	__u64 *n = busy_slot(count_key);
	if (n)
		*n += 1;
	return 1;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(handle_exec_btf, struct task_struct *p, int old_pid, struct linux_binprm *bprm)
{
	__u64 *b = busy_slot(BUSY_EXEC);
	if (b)
		*b = 1;
	exec_event(ctx, SLOT_EXEC, BPF_CORE_READ(bprm, filename));
	if (b)
		*b = 0;
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(handle_exec_btf2, struct task_struct *p, int old_pid, struct linux_binprm *bprm)
{
	if (!rescue(BUSY_EXEC, RESCUED_EXEC))
		return 0;
	return exec_event(ctx, SLOT_EXEC2, BPF_CORE_READ(bprm, filename));
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_exit_btf, struct task_struct *p)
{
	__u64 *b = busy_slot(BUSY_EXIT);
	if (b)
		*b = 1;
	exit_event(ctx, SLOT_EXIT);
	if (b)
		*b = 0;
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_exit_btf2, struct task_struct *p)
{
	if (!rescue(BUSY_EXIT, RESCUED_EXIT))
		return 0;
	return exit_event(ctx, SLOT_EXIT2);
}

// Exec and exit, fallback: the classic tracepoints.
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	__u32 loc = BPF_CORE_READ(ctx, __data_loc_filename);
	return exec_event(ctx, SLOT_EXEC, (void *)ctx + (loc & 0xffff));
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
	return exit_event(ctx, SLOT_EXIT);
}

// Fork, preferred: a BTF tracepoint gives the child task, so threads can be
// skipped and the child's exact start time is known.
SEC("tp_btf/sched_process_fork")
int BPF_PROG(handle_fork_btf, struct task_struct *parent, struct task_struct *child)
{
	int pid = BPF_CORE_READ(child, pid);
	if (pid != BPF_CORE_READ(child, tgid))
		return 0; // a new thread, not a process
	struct event *e = new_event(EV_FORK, SLOT_FORK);
	if (!e)
		return 0;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->start_ns = task_start(child);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	fill_tty(e, child);
	send(ctx, e, SHORT_EVENT, !(e->flags & FLAG_TTY));
	return 0;
}

// Fork, fallback: the classic tracepoint only has the two pids (threads
// included; userspace drops what /proc shows to be a thread).
SEC("tracepoint/sched/sched_process_fork")
int handle_fork_tp(struct trace_event_raw_sched_process_fork *ctx)
{
	struct event *e = new_event(EV_FORK, SLOT_FORK);
	if (!e)
		return 0;
	e->pid = BPF_CORE_READ(ctx, child_pid);
	e->ppid = bpf_get_current_pid_tgid() >> 32; // the tracepoint's parent_pid is a thread id
	e->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	send(ctx, e, SHORT_EVENT, 1); // userspace reads the child's /proc entries
	return 0;
}

SEC("tracepoint/oom/mark_victim")
int handle_oom(struct trace_event_raw_mark_victim *ctx)
{
	struct event *e = new_event(EV_OOM, SLOT_OOM);
	if (!e)
		return 0;
	e->pid = BPF_CORE_READ(ctx, pid);
	e->exit_code = -1;
	if (bpf_core_field_exists(ctx->anon_rss))
		e->rss_kb = BPF_CORE_READ(ctx, anon_rss) + BPF_CORE_READ(ctx, file_rss) + BPF_CORE_READ(ctx, shmem_rss);
	send(ctx, e, SHORT_EVENT, 1); // userspace reads the victim's /proc entries
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
