//go:build ignore

// SPDX-License-Identifier: GPL-2.0
//
// TCP connection events for sosv-record.
//
// - sock:inet_sock_set_state: every TCP state change. SYN_SENT (connect)
//   and LISTEN happen in the owning process, which becomes the socket's
//   owner; the fd comes from the connect/listen syscall in progress.
// - inet_csk_accept (fexit, or kretprobe): the owner of an accepted
//   connection; the accept syscall's return gives its fd.
// - tcp_close (fentry, or kprobe): the application closed the socket; from
//   then on no process holds it (ss shows no users).
// - tcp_time_wait (fentry, or kprobe): the connection continues as a
//   time-wait socket (TIME_WAIT, or FIN_WAIT2 after an orphaned close) that
//   no state change reports; newstate carries which.
// - tcp:tcp_retransmit_skb / tcp_send_reset / tcp_receive_reset and
//   counted per connection in the kernel and sent with the close.
// - tcp_send_active_reset (RST on abort or SO_LINGER 0, fentry or kprobe):
//   an event of its own, since the kernel sends it after TCP_CLOSE.
//
// Owners are kept in a hash map keyed by the sock pointer and deleted when
// the connection reaches TCP_CLOSE. Tracepoint arguments are read at their
// fixed offsets (stable since Linux 4.16); kernel structures through CO-RE.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// The kprobe argument macros read the kernel's struct pt_regs. Without
// vmlinux.h we declare the registers they use (CO-RE relocates them) and
// tell bpf_tracing.h to use the kernel's field names.
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long di, si, dx, cx, r8, r9, ax, sp, bp, ip;
} __attribute__((preserve_access_index));
#elif defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
} __attribute__((preserve_access_index));
struct pt_regs {
	struct user_pt_regs user_regs;
} __attribute__((preserve_access_index));
#endif
#define __VMLINUX_H__
#include <bpf/bpf_tracing.h>

#define TCP_SYN_SENT 2
#define TCP_CLOSE 7
#define TCP_LISTEN 10
#define IPPROTO_TCP_ 6

// ---- kernel structures (CO-RE) ----

struct inode { unsigned long i_ino; } __attribute__((preserve_access_index));

struct in6_addr {
	union {
		__u8 u6_addr8[16];
	} in6_u;
} __attribute__((preserve_access_index));

// The addresses of a time-wait socket (its struct sock_common).
struct sock_common {
	union {
		struct {
			__u32 skc_daddr;
			__u32 skc_rcv_saddr;
		};
	};
	union {
		struct {
			__u16 skc_dport; // network order
			__u16 skc_num; // local port, host order
		};
	};
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct inet_timewait_sock {
	struct sock_common __tw_common;
} __attribute__((preserve_access_index));
struct file { struct inode *f_inode; } __attribute__((preserve_access_index));
struct socket { struct file *file; } __attribute__((preserve_access_index));
struct sock {
	struct sock_common __sk_common;
	struct socket *sk_socket;
	__u16 sk_protocol; // a bit-field before Linux 5.6: the BTF tracepoint program then fails to load
} __attribute__((preserve_access_index));
struct inet_sock {
	__u32 inet_saddr;
	__u16 inet_sport; // network order
} __attribute__((preserve_access_index));

struct task_struct {
	int tgid;
	struct task_struct *group_leader;
} __attribute__((preserve_access_index));
struct task_struct___new { __u64 start_boottime; } __attribute__((preserve_access_index));
struct task_struct___old { __u64 real_start_time; } __attribute__((preserve_access_index));

// ---- tracepoint arguments (fixed layouts) ----

struct set_state_args {
	__u64 common;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

struct sk_skb_args { // tcp_retransmit_skb, tcp_send_reset
	__u64 common;
	const void *skbaddr;
	const void *skaddr;
};

struct sk_args { // tcp_receive_reset
	__u64 common;
	const void *skaddr;
};

struct sys_enter_fd_args { // sys_enter_connect, sys_enter_listen
	__u64 common;
	__s32 nr;
	__u32 pad;
	__u64 fd;
};

struct sys_exit_args {
	__u64 common;
	__s32 nr;
	__u32 pad;
	__s64 ret;
};

// ---- events ----

enum kind { EV_STATE = 1, EV_ACCEPT = 2, EV_ACCEPT_FD = 3, EV_APP_CLOSE = 4, EV_TIME_WAIT = 5, EV_ACTIVE_RESET = 6,
	EV_TW_END = 7 };
#define NKINDS 8

struct owner {
	__u32 pid; // process (tgid); 0: unknown
	__s32 fd; // -1: unknown
	__u64 start_ns; // process start, ns since boot
	__u64 inode;
};

struct counters {
	__u32 retransmits;
	__u32 resets_sent;
	__u32 resets_received;
	__u32 pad;
};

struct tcp_event {
	__u32 kind;
	__s32 oldstate;
	__s32 newstate;
	__u16 family;
	__u16 sport;
	__u16 dport;
	__u16 pad;
	__u32 pad2;
	__u64 mono_ns;
	__u64 sk;
	struct owner owner;
	struct counters counters; // EV_STATE to TCP_CLOSE only
	__u8 saddr[16];
	__u8 daddr[16];
};

// Keeps struct tcp_event in the BTF for bpf2go (it only lives on the stack).
const struct tcp_event *unused_tcp_event __attribute__((unused));

#ifdef USE_PERF
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");
#define OUTPUT(ctx, e) bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e))
#else
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 << 20); // userspace may resize
} events SEC(".maps");
#define OUTPUT(ctx, e) bpf_ringbuf_output(&events, e, sizeof(*e), 0)
#endif

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072); // userspace may resize
	__type(key, __u64); // struct sock *
	__type(value, struct owner);
} owners SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 131072);
	__type(key, __u64);
	__type(value, struct counters);
} counters SEC(".maps");

// Resets sent without a socket (e.g. to a port nobody listens on).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} nosock_resets SEC(".maps");

// fd of the connect/listen syscall in progress, per thread.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __s32);
} syscall_fd SEC(".maps");

// Socket returned by inet_csk_accept, until the accept syscall returns its fd.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u64);
} accepting SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NKINDS);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

static __always_inline void send(void *ctx, struct tcp_event *e)
{
	if (OUTPUT(ctx, e) != 0) {
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

static __always_inline void current_owner(struct owner *o)
{
	struct task_struct *t = (void *)bpf_get_current_task();
	o->pid = bpf_get_current_pid_tgid() >> 32;
	o->start_ns = task_start(BPF_CORE_READ(t, group_leader));
	o->fd = -1;
	o->inode = 0;
}

static __always_inline __u64 sock_inode(const void *sk)
{
	return BPF_CORE_READ((struct sock *)sk, sk_socket, file, f_inode, i_ino);
}

// The common end of a state change: its owner, the counters at TCP_CLOSE.
static __always_inline int state_event(void *ctx, struct tcp_event *e)
{
	if (e->newstate == TCP_SYN_SENT || e->newstate == TCP_LISTEN) {
		// connect() or listen(): we are in the owning process.
		struct owner o;
		current_owner(&o);
		__u32 tid = (__u32)bpf_get_current_pid_tgid();
		__s32 *fd = bpf_map_lookup_elem(&syscall_fd, &tid);
		if (fd)
			o.fd = *fd;
		o.inode = sock_inode((void *)e->sk);
		bpf_map_update_elem(&owners, &e->sk, &o, BPF_ANY);
	}
	struct owner *o = bpf_map_lookup_elem(&owners, &e->sk);
	if (o)
		e->owner = *o;
	else
		e->owner.fd = -1;
	if (e->newstate == TCP_CLOSE) {
		struct counters *c = bpf_map_lookup_elem(&counters, &e->sk);
		if (c) {
			e->counters = *c;
			bpf_map_delete_elem(&counters, &e->sk);
		}
		bpf_map_delete_elem(&owners, &e->sk);
	}
	send(ctx, e);
	return 0;
}

// State changes, preferred: the BTF tracepoint, with two programs.
//
// The kernel does not run a tracing program on a CPU where that program is
// already running: one that was interrupted, or preempted, when another
// socket changes state there. (A classic tracepoint program is skipped
// while any tracepoint or kprobe program runs.) A missed TCP_CLOSE would
// merge two connections. So the first program marks the CPU while it runs,
// and the second, a program of its own, reports the changes that find the
// mark: the ones the first could not see.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2); // 0: the first program is running; 1: changes the second reported
	__type(key, __u32);
	__type(value, __u64);
} state_busy SEC(".maps");

static __always_inline int state_btf(void *ctx, struct sock *sk, int oldstate, int newstate)
{
	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP_)
		return 0;
	struct inet_sock *inet = (void *)sk;
	struct tcp_event e = {};
	e.kind = EV_STATE;
	e.mono_ns = bpf_ktime_get_ns();
	e.sk = (__u64)sk;
	e.oldstate = oldstate;
	e.newstate = newstate;
	// The same values the classic tracepoint reports.
	e.family = BPF_CORE_READ(sk, __sk_common.skc_family);
	e.sport = __builtin_bswap16(BPF_CORE_READ(inet, inet_sport));
	e.dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (e.family == 2 /* AF_INET */) {
		__u32 s = BPF_CORE_READ(inet, inet_saddr);
		__u32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memcpy(e.saddr, &s, 4);
		__builtin_memcpy(e.daddr, &d, 4);
	} else {
		BPF_CORE_READ_INTO(&e.saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&e.daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}
	return state_event(ctx, &e);
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(handle_set_state_btf, struct sock *sk, int oldstate, int newstate)
{
	__u32 zero = 0;
	__u64 *busy = bpf_map_lookup_elem(&state_busy, &zero);
	if (busy)
		*busy = 1;
	state_btf(ctx, sk, oldstate, newstate);
	if (busy)
		*busy = 0;
	return 0;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(handle_set_state_btf2, struct sock *sk, int oldstate, int newstate)
{
	__u32 zero = 0, one = 1;
	__u64 *busy = bpf_map_lookup_elem(&state_busy, &zero);
	if (!busy || !*busy)
		return 0; // the first program reports this change
	__u64 *n = bpf_map_lookup_elem(&state_busy, &one);
	if (n)
		*n += 1;
	return state_btf(ctx, sk, oldstate, newstate);
}

// State changes, fallback: the classic tracepoint.
SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct set_state_args *ctx)
{
	if (ctx->protocol != IPPROTO_TCP_)
		return 0;
	struct tcp_event e = {};
	e.kind = EV_STATE;
	e.mono_ns = bpf_ktime_get_ns();
	e.sk = (__u64)ctx->skaddr;
	e.oldstate = ctx->oldstate;
	e.newstate = ctx->newstate;
	e.family = ctx->family;
	e.sport = ctx->sport;
	e.dport = ctx->dport;
	if (e.family == 2 /* AF_INET */) {
		__builtin_memcpy(e.saddr, ctx->saddr, 4);
		__builtin_memcpy(e.daddr, ctx->daddr, 4);
	} else {
		__builtin_memcpy(e.saddr, ctx->saddr_v6, 16);
		__builtin_memcpy(e.daddr, ctx->daddr_v6, 16);
	}
	return state_event(ctx, &e);
}

static __always_inline int save_fd(struct sys_enter_fd_args *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__s32 fd = (__s32)ctx->fd;
	bpf_map_update_elem(&syscall_fd, &tid, &fd, BPF_ANY);
	return 0;
}

static __always_inline int drop_fd(void)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&syscall_fd, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_enter_connect(struct sys_enter_fd_args *ctx) { return save_fd(ctx); }
SEC("tracepoint/syscalls/sys_exit_connect")
int handle_exit_connect(void *ctx) { return drop_fd(); }
SEC("tracepoint/syscalls/sys_enter_listen")
int handle_enter_listen(struct sys_enter_fd_args *ctx) { return save_fd(ctx); }
SEC("tracepoint/syscalls/sys_exit_listen")
int handle_exit_listen(void *ctx) { return drop_fd(); }

static __always_inline int accepted(void *ctx, __u64 sk)
{
	if (!sk)
		return 0;
	struct tcp_event e = {};
	e.kind = EV_ACCEPT;
	e.mono_ns = bpf_ktime_get_ns();
	e.sk = sk;
	current_owner(&e.owner);
	bpf_map_update_elem(&owners, &sk, &e.owner, BPF_ANY);
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&accepting, &tid, &sk, BPF_ANY);
	send(ctx, &e);
	return 0;
}

// fexit: bpf_get_func_ret works whatever the argument list (it changed in 6.10).
SEC("fexit/inet_csk_accept")
int handle_accept_fexit(void *ctx)
{
	__u64 ret = 0;
	bpf_get_func_ret(ctx, &ret);
	return accepted(ctx, ret);
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_accept_kret, void *ret)
{
	return accepted(ctx, (__u64)ret);
}

// The accept syscall returned: the socket is now grafted to a file with an fd.
static __always_inline int accept_fd(struct sys_exit_args *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 *skp = bpf_map_lookup_elem(&accepting, &tid);
	if (!skp)
		return 0;
	__u64 sk = *skp;
	bpf_map_delete_elem(&accepting, &tid);
	if (ctx->ret < 0)
		return 0;
	struct owner *o = bpf_map_lookup_elem(&owners, &sk);
	if (!o)
		return 0;
	o->fd = ctx->ret;
	o->inode = sock_inode((void *)sk);
	struct tcp_event e = {};
	e.kind = EV_ACCEPT_FD;
	e.mono_ns = bpf_ktime_get_ns();
	e.sk = sk;
	e.owner = *o;
	send(ctx, &e);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int handle_exit_accept4(struct sys_exit_args *ctx) { return accept_fd(ctx); }
SEC("tracepoint/syscalls/sys_exit_accept")
int handle_exit_accept(struct sys_exit_args *ctx) { return accept_fd(ctx); }

static __always_inline int app_close(void *ctx, __u64 sk)
{
	struct tcp_event e = {};
	e.kind = EV_APP_CLOSE;
	e.mono_ns = bpf_ktime_get_ns();
	e.sk = sk;
	e.owner.fd = -1;
	send(ctx, &e);
	return 0;
}

SEC("fentry/tcp_close")
int BPF_PROG(handle_close_fentry, void *sk)
{
	return app_close(ctx, (__u64)sk);
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(handle_close_kprobe, void *sk)
{
	return app_close(ctx, (__u64)sk);
}

static __always_inline int time_wait(void *ctx, __u64 sk, int state)
{
	struct tcp_event e = {};
	e.kind = EV_TIME_WAIT;
	e.mono_ns = bpf_ktime_get_ns();
	e.sk = sk;
	e.newstate = state;
	e.owner.fd = -1;
	send(ctx, &e);
	return 0;
}

SEC("fentry/tcp_time_wait")
int BPF_PROG(handle_tw_fentry, void *sk, int state)
{
	return time_wait(ctx, (__u64)sk, state);
}

SEC("kprobe/tcp_time_wait")
int BPF_KPROBE(handle_tw_kprobe, void *sk, int state)
{
	return time_wait(ctx, (__u64)sk, state);
}

// A time-wait socket goes away (its timer fired, or the addresses were
// reused). inet_twsk_kill is static: optional, the end is estimated without.
static __always_inline int tw_end(void *ctx, struct inet_timewait_sock *tw)
{
	struct tcp_event e = {};
	e.kind = EV_TW_END;
	e.mono_ns = bpf_ktime_get_ns();
	e.sk = (__u64)tw;
	e.owner.fd = -1;
	e.family = BPF_CORE_READ(tw, __tw_common.skc_family);
	e.sport = BPF_CORE_READ(tw, __tw_common.skc_num);
	e.dport = __builtin_bswap16(BPF_CORE_READ(tw, __tw_common.skc_dport));
	if (e.family == 2) {
		__u32 s = BPF_CORE_READ(tw, __tw_common.skc_rcv_saddr);
		__u32 d = BPF_CORE_READ(tw, __tw_common.skc_daddr);
		__builtin_memcpy(e.saddr, &s, 4);
		__builtin_memcpy(e.daddr, &d, 4);
	} else {
		BPF_CORE_READ_INTO(&e.saddr, tw, __tw_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&e.daddr, tw, __tw_common.skc_v6_daddr.in6_u.u6_addr8);
	}
	send(ctx, &e);
	return 0;
}

SEC("fentry/inet_twsk_kill")
int BPF_PROG(handle_tw_end_fentry, struct inet_timewait_sock *tw)
{
	return tw_end(ctx, tw);
}

SEC("kprobe/inet_twsk_kill")
int BPF_KPROBE(handle_tw_end_kprobe, struct inet_timewait_sock *tw)
{
	return tw_end(ctx, tw);
}

static __always_inline int active_reset(void *ctx, __u64 sk)
{
	struct tcp_event e = {};
	e.kind = EV_ACTIVE_RESET;
	e.mono_ns = bpf_ktime_get_ns();
	e.sk = sk;
	e.owner.fd = -1;
	send(ctx, &e);
	return 0;
}

SEC("fentry/tcp_send_active_reset")
int BPF_PROG(handle_active_reset_fentry, void *sk)
{
	return active_reset(ctx, (__u64)sk);
}

SEC("kprobe/tcp_send_active_reset")
int BPF_KPROBE(handle_active_reset_kprobe, void *sk)
{
	return active_reset(ctx, (__u64)sk);
}

static __always_inline void count(const void *skaddr, int field)
{
	__u64 sk = (__u64)skaddr;
	if (!sk) {
		__u32 zero = 0;
		__u64 *n = bpf_map_lookup_elem(&nosock_resets, &zero);
		if (n && field == 1)
			__sync_fetch_and_add(n, 1);
		return;
	}
	struct counters *c = bpf_map_lookup_elem(&counters, &sk);
	if (!c) {
		struct counters z = {};
		bpf_map_update_elem(&counters, &sk, &z, BPF_NOEXIST);
		c = bpf_map_lookup_elem(&counters, &sk);
		if (!c)
			return;
	}
	if (field == 0)
		__sync_fetch_and_add(&c->retransmits, 1);
	else if (field == 1)
		__sync_fetch_and_add(&c->resets_sent, 1);
	else
		__sync_fetch_and_add(&c->resets_received, 1);
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int handle_retransmit(struct sk_skb_args *ctx) { count(ctx->skaddr, 0); return 0; }
SEC("tracepoint/tcp/tcp_send_reset")
int handle_send_reset(struct sk_skb_args *ctx)
{
	// Since Linux 6.10 tcp_send_active_reset fires this tracepoint too, with
	// no skb. EV_ACTIVE_RESET reports those; counting them here as well
	// would leave a count behind for the next socket at this address.
	if (ctx->skaddr && !ctx->skbaddr)
		return 0;
	count(ctx->skaddr, 1);
	return 0;
}
SEC("tracepoint/tcp/tcp_receive_reset")
int handle_receive_reset(struct sk_args *ctx) { count(ctx->skaddr, 2); return 0; }

char LICENSE[] SEC("license") = "GPL";
