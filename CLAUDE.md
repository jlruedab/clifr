# clifr — Linux flight recorder (working prototype)

`clifrd` continuously records which processes existed, which sockets and open
files each one held, short-lived process start/exit events and the system-wide
counters, as Parquet files.
`clifr` reconstructs the output of the real tools (`ps`, `top`, `atop`, `iotop`, `htop`, `sar`, `pstree`, `pidstat`, `systemd-cgls`, `date`, `hostname`, `uname`, `who`, `w`, `last`, `nstat`, `ip link|address|route|rule|neigh|netns`, `dmesg`, `systemctl list-units`, `swapon`, `lsmod`, `lsblk`, `lslocks`, `ipcs`, `sysctl`, `slabtop`, `numastat`, `conntrack -S|-C`, `nfsstat`, `mountstats`, `findmnt`, `lsof`, `ss`, `netstat`, `free`,
`uptime`, `vmstat`, `mpstat`, `iostat`; clifr-only `events`, `life`, `oom`, `mounts`, `containers`, `pstore`) for a
past moment or time range;
`clifr info` and `clifr verify` describe and check the recording.

It began as a proof of concept to prove two things with evidence: **accuracy**
(reconstruction vs. the real tools) and **cost** (CPU / memory / disk of recording and
its impact on a busy workload). Both are shown; since 2026-10-17 the user calls it a
working prototype, not yet viable (no soak test, one machine, synthetic load only,
no packaging: README "Status"). The benchmark results under `bench/` remain the main
evidence, not CLI polish.

Renamed from sosv on 2026-10-19 (module `clifr`, `cmd/clifrd`, `cmd/clifr`,
`/var/lib/clifr`); the v1 tag, the bench database `sosvbench`, its slice and
result file names (`sosv-stats.*`, `sosv.db`, `sosv_commit`) keep the old name.
The product plan (phases 1–7) is in `docs/clifr-plan.md`.

**Current state:** v2 (event-based recorder, Parquet, DuckDB CLI): milestones
1–9 done. v1 (snapshot-based, SQLite) is tagged `v1-snapshot`; its benchmark
configuration and the SQLite backend were removed on 2026-10-21 (the user). `HANDOFF.md` (local, not in git) has the current results, the open
items and the history. Do one step at a time, run it, report results, and
wait for the user's go-ahead.

## Hard constraints (v2)
- Two binaries. `clifrd`: pure Go, static, `CGO_ENABLED=0`, runs on the
  recorded server. `clifr`: the CLI, DuckDB (`github.com/duckdb/duckdb-go`,
  cgo allowed), may run on another machine.
- eBPF via `github.com/cilium/ebpf` (CO-RE, bpf2go; clang only at build time).
  Prefer tracepoints, then fentry/fexit if available, else kprobes; ring buffer
  if supported, else perf event array. Count drops per source. Targets:
  RHEL 8.2+/9, Ubuntu 22.04+ (BTF at /sys/kernel/btf/vmlinux). Needs
  CAP_BPF + CAP_PERFMON (CAP_SYS_ADMIN on older kernels). Netlink proc
  connector stays as the fallback for process events.
- Storage: Parquet (`github.com/parquet-go/parquet-go`, zstd, dictionary
  encoding) behind a small interface (`store.Backend`). No SQLite.
- Other dependencies only with the user's approval.
- License: `AGPL-3.0-only` (`LICENSING.md`; no commercial license and no licence checks: the
  user, 2026-11-09); contributions signed off under the DCO (`DCO`, `CONTRIBUTING.md`); the
  `.bpf.c` files are `GPL-2.0-only OR BSD-2-Clause` and
  declare "Dual BSD/GPL" (the kernel's GPL-only helpers need a GPL-compatible string);
  the sos plugin `deploy/sos/clifr.py` is `GPL-2.0-only` with sos's header (2026-11-07: it
  runs inside sos, which is GPLv2-only; flake8- and pylint-clean with sos's settings).
  A new dependency must be AGPL-compatible; updating duckdb-go-bindings to another DuckDB
  version needs `packaging/notices/duckdb-<version>.txt` (`packaging/notices.sh` stops
  the build without it).
  Code that follows another tool's code (to match its output) is derived from it: only from code
  under a license combinable with the AGPL-3.0 (GPL-2.0-or-later, GPL-3.0+, LGPL-2.1, permissive;
  never GPL-2.0-only, as nfs-utils' mountstats.py: clean-room then), with a top-of-file comment,
  a row in LICENSING.md's "Code derived from other projects" and `packaging/notices/NAME.txt`
  (listed in `packaging/notices.sh`; audit 2026-11-21).
- Parse /proc ourselves. **Never read `/proc/*/environ`.**
- All /proc access goes through `procfs.FS` so `--proc-root` fixtures work.
- Network only for phase 7's opt-in features, each off by default (the user, 2026-11-07,
  `docs/clifr-plan.md`): `--metrics` (Prometheus text format written by hand; loopback
  addresses only, unless `--metrics-tls-config` gives TLS: then any address); `--serve` (7.2: any address, but every request needs a token, and
  TLS with clifrd's self-signed certificate, pinned by clifr, except on loopback, or with the
  admin's (`--serve-tls-config`, Node Exporter's format, TLS 1.3, also on loopback), checked by
  clifr against `--tls-ca` or the system's CAs; only the
  recording's Parquet files are served, never the token file or the TLS key). A default
  install opens no port and makes no connection; the
  unit keeps `RestrictAddressFamilies=AF_NETLINK AF_UNIX` (a drop-in adds AF_INET for a
  feature turned on). No phone-home or telemetry.
- No encryption, obfuscation or web UI. One exception (the user, 2026-11-01, against
  copy-cats): table directories are named by a fixed hash, `pqstore.Dir` (8 hex digits of
  SHA-256("clifr/" + table)), the same on every host; never change it (bundles move between
  hosts). Column names inside the Parquet files stay readable. Readers take the old plain names
  too (`pqstore.TableDir`); clifrd renames them when it opens the store.
- Forward-secure sealing of the integrity log (the user, 2026-11-16, `docs/sealing.md`): an
  HMAC-SHA256 chain with a one-way evolving key (standard library only), authentication, not
  encryption. Opt-in: sealing starts only after `clifrd seal-setup`, which prints the
  verification key once; that key (k0) is never stored on the host, and clifrd never starts a
  new chain by itself (a lost `seal.state` = "unsealed" + a warning until `seal-setup --new`).
  The previous epoch's key is overwritten in place, not left in a renamed-away file.

## Layout
- `cmd/clifrd/` — the recorder binary (static, no cgo).
- `cmd/clifr/` — the query CLI (DuckDB via cgo): `clifr [--at T | --since A --until B] [OPTIONS] "COMMAND [ARGS]"`;
  per-command option tables in `tools.go`, `tools2.go`, `systools.go` (unsupported options
  are rejected);
  `--data-dir` Parquet.
- `internal/procfs/` — /proc parsers (stat, status, cmdline, fd, net/*, meminfo; `system.go`: the
  system-wide stat, loadavg, meminfo, vmstat, diskstats).
- `internal/sockdiag/` — NETLINK_SOCK_DIAG (inet_diag) dumps.
- `internal/bpfproc/` — eBPF process events (fork/exec/exit, OOM): `procevents.bpf.c`
  (CO-RE, no vmlinux.h) and the committed bpf2go objects; `go generate ./internal/bpfproc`
  rebuilds them (clang-18, llvm-strip-18, libbpf-dev).
- `internal/bpftcp/` — eBPF TCP events: `tcpevents.bpf.c` (state changes with owners,
  accept fds, app close, time-wait start/end, retransmits/resets); objects for amd64 and arm64.
- `internal/cnproc/` — kernel proc connector (fork/exec/exit events), the fallback.
- `internal/sdunits/` — systemd units over D-Bus (ListUnits, Subscribe).
- `internal/rtnl/` — rtnetlink reads (network interfaces; later addresses, routes, rules).
- `internal/store/` — `Backend` interface, the per-sample `Batch` and its rows, `DB` (a
  recording loaded into DuckDB). `internal/testrec/` — small recordings for tests (Parquet,
  read back through DuckDB). `internal/duck/testdata/roundtrip.golden`: every table as
  written and read back (`go test ./internal/duck -run RoundTrip -update` rewrites it).
- `internal/pqstore/` — Parquet backend: flush windows, open-entity files, compaction, retention;
  renames made durable (`durable.go`), early flush (`early.go`), the previous run's end (`prevrun.go`),
  the integrity log of every file written (`integrity.go`, `integrity/DAY.log`; `clifr verify --integrity`).
- `internal/duck/` — loads a Parquet data directory into in-memory DuckDB with the v1 table names.
- `internal/recorder/` — sampling loop, interval trackers, self-metrics, guard rails.
- `internal/query/` — reconstruction and formatting of ps/lsof/ss/life/stats.
- `internal/verify/` — compare saved real tool output with reconstructions.
- `internal/remote/` — `clifrd --serve` (pure Go): tokens stored hashed (`clifrd token`), the
  self-signed certificate (fingerprint = SHA-256 of the public key, OpenSSH style), `/v1/info`,
  `/v1/files` (bundle.Select's set), `/v1/file` (only `TABLEDIR/DAY|open/NAME.parquet`,
  `ValidPath`); `cmd/clifr/remote.go` is `clifr --host` (a CA-verified certificate for the host
  name is accepted, `--tls-ca` = only that CA; otherwise pinning in known_hosts, cache by
  SHA-256, a query directory of exactly the listed files). `deploy/clifrd-serve.conf` is the
  opt-in unit drop-in.
- `internal/metrics/` — `clifrd --metrics`: the Prometheus text format written by hand, Node
  Exporter's names, from the recorder's last published `Snapshot` (no read per scrape);
  loopback addresses only without TLS; `--metrics-tls-config` (`internal/webconfig`, shared with
  `--serve-tls-config`, 2026-11-08):
  Node Exporter's web configuration file (TLS, client certificates, bcrypt basic auth via
  golang.org/x/crypto, unknown keys refused, reloaded when its files change) allows any address
  with TLS; `deploy/clifrd-metrics.conf` is the opt-in unit drop-in (TCP, loopback-only IP
  unless its `IPAddressAllow=` line is uncommented). A failed listen is logged and clifrd
  records without metrics; an invalid web config at start stops it.
- `internal/bundle/` — `clifrd bundle` (pure Go): a window's data files as one tar with
  `bundle.json`; `Extract` for `clifr --data-dir FILE.tar`. `deploy/sos/clifr.py` — sos plugin.
- `packaging/vm.sh` — KVM test VMs (Rocky 8, Alma 9, Ubuntu 22.04 cloud images in
  /var/lib/libvirt/images; `up`, `bins`, `test`, `down`); `vm-test.sh` runs inside: service,
  `--test-ebpf` x3, e2e and truth from prebuilt test binaries (`CLIFR_TEST_BIN`), sos.
- `packaging/` — `build.sh` (.deb/.rpm of clifr and clifrd into `dist/`; clifr built in a
  Rocky 8 container for glibc 2.28), `test.sh` (install test in containers), man pages from
  the help texts (`genman.sh`), bash completion (clifr's checked by `TestCompletion`).
- `deploy/` — systemd unit. `bench/` — load generator, benchmark runner, report. `test/e2e/` — end-to-end test.
- `test/truth/` — ground-truth test (found/expected per check; `truthproc/` is its helper binary).

## Data model notes
- Entities are time ranges: `first_seen`, `last_seen`. While an entity is still open,
  `last_seen` is NULL in the DB and lives only in memory ("seen at every sample since
  first_seen"); it is written when the entity closes, on clean shutdown, or recovered
  from the last sample timestamp on the next start after a crash.
- Parquet: append-only. A closed entity is written once; open ones are rewritten each
  flush to `<Dir(table)>/open/<run>.parquet` with last_seen = last sample. Readers keep one
  row per id (closed row first). Ids = run start (Unix s) × 1e9 + counter, for every table
  of `pqstore.EntityTables` (fds_held's began at 1 in every run until 2026-11-07, so readers
  keep one fds_held row per id and first_seen: older recordings reuse its ids across runs).
- Network namespaces (schema 10, 2026-11-08): `netns` in `processes`, `tcp_conns` and
  `tcp_keyframes` (the namespace's inode number; 0 = the host's, init's; NULL before). The eBPF
  events carry it (`skc_net.net->ns.inum`, in the former padding); connections are keyed by
  namespace and addresses (127.0.0.1 exists in every pod). A process's namespace is read when it is
  first sampled and at an exec (not on fd walks: 20-50 ms a walk). Keyframes read each other namespace through one of its processes' /proc/PID/net/*
  (no setns: that needs CAP_SYS_ADMIN) and judge only the namespaces they read. Each tcp/tcp6
  read walks the kernel's whole established hash (~2 ms each on 64 GB, whatever the socket
  count; udp ~50 µs): UDP files every keyframe, TCP files only for namespaces with open TCP
  connections, once when first seen and all at a run's first keyframe, within 100 ms a keyframe
  (`netnsTCPBudget`, least recently read first); a namespace's first TCP read adopts as an
  initial keyframe. 100 namespaces, 2,100 sockets: keyframe sample 127 ms (host only 17 ms). `ss`/`netstat`
  show the host's; `ss -N CONTAINER|PID` another (`query.NetNSOf`); `ps --container X` filters by cgroup (`query.ContainerFilter`, the same container names: `ctrSpecMatch`). TCPConn.Inode is 32 bits
  (socket inodes are) so the row stays 128 bytes.
- Container names (2026-11-09, `recorder/ctrnames.go`): `snapshots` source "containers", one
  line per container id, "runtime\tname\timage\tpod\tnamespace\tproject", every 5 min and at
  the next system sample after a process shows up in a new container (`noteContainer`, cached
  per cgroup text). From Docker's API (`GET /containers/json` on /var/run/docker.sock, the
  user's choice), rootful Podman's containers.json (id, names, image only), the kubelet's
  /var/log/containers link names (a listing). Never a file with a container's environment
  (Docker's config.v2.json, OCI config.json). `internal/ctr`: container ids from cgroups (pure
  Go, shared). `query.nameContainers`: the newest names from 10 min before a window.
- TCP with events (`meta tcp` starts with "events"): `tcp_conns` (one row per connection,
  newest version wins), `tcp_transitions` (ordered by ts, seq), `tcp_keyframes` (full dumps:
  queues, UDP), `reconcile`. The v1 sockets/sock_samples/sock_owners stay empty then;
  `--tcp sample` keeps v1 sampling. `v6only` (tcp_conns, tcp_keyframes): 1 = an IPv6 socket
  that does not accept IPv4, from the listen event and from sock_diag (listening and
  unconnected sockets); `ss` prints `::` of the others as `*`. NULL in older recordings
  (printed as before, `[::]`). Kernel sock pointers are reused quickly: never key
  anything that must survive a close by the pointer alone.
- eBPF losses that leave no trace in the drop counters: the kernel does not run a tracing
  program on a CPU where it is already running (interrupted or preempted), and no classic
  tracepoint/kprobe program while another one runs. TCP state changes, exec and exit
  therefore use two `tp_btf` programs each (the second reports what the first misses;
  per-program scratch slots); the recorder closes a connection whose close was missed
  when its sock pointer is reused (`tcp_close_missed` guard event); `recorder_stats` has
  `tcp_missed_runs` / `ebpf_missed_runs` (dropped). OOM, the syscall fd hooks and the
  reset/retransmit counters are still classic tracepoints. A missed time-wait start
  (RHEL 8's kprobe) is inferred: a CLOSE from FIN_WAIT2/CLOSING without resets means
  tcp_time_wait ran (`tcp_time_wait_inferred` in `recorder_stats`).
- Kernel differences found in VMs (2026-10-20; keep reading through CO-RE): RHEL 8's
  `sk_protocol` is a bitfield (`BPF_CORE_READ_BITFIELD_PROBED`) and `inet_sock_set_state`'s
  protocol one byte; RHEL 8 keeps the old `pid_type` order (PID, PGID, SID, TGID:
  `bpf_core_enum_value`); RHEL 9 adds a byte to every classic tracepoint record's header (all
  fields move by 8), and the tcp record types are named per kernel (`bpf_core_type_exists`).
  Classic tracepoint records with relocated offsets are read with probe reads (the verifier
  refuses dereferencing a moved ctx pointer). RHEL 8 has cgroup v1 by default.
  OOM RSS where `mark_victim` lacks it (before 6.x): `tp_btf/signal_generate` stores the RSS
  (pages, `mm->rss_stat` in both layouts) of a kernel-sent SIGKILL's target, sent just before
  the victim is marked; `FLAG_RSS_PAGES`, converted with the page size in Go.
  Signal senders (schema 11, 2026-11-20, HANDOFF 0d): the same `signal_generate` program keeps,
  per target tgid (LRU map `killers`, 4096), the last sender of each signal whose default action
  ends a process (`FATAL_MASK` 1-31 Term/Core, and 32-64), delivered or LOSE_INFO only (an
  already pending one keeps the first sender); sender = the current task for SEND_SIG_NOINFO and
  si_code SI_USER/SI_QUEUE/SI_TKILL (si_code read at offset 8: x86_64 and arm64), else the kernel
  (pid 0). A self-sent re-raise of the same signal keeps the earlier sender. At the exit, when the
  wait status is that signal and the target's start time matches, the exit event carries it
  (`FLAG_KILLER`, `FLAG_KILLER_KERNEL`) -> `store.Killer` -> `processes.killer_pid|uid|comm`
  (NULL: unknown). Attached whenever fork/exec/exit use tp_btf (`Source.Killers`); none with
  classic tracepoints or the proc connector (Rocky 8.10's 4.18 has tp_btf: senders there too). `query.LifeRow.SentBy`, life's SENT BY
  column, events' "SIGTERM from PID (COMM, USER) [command]".
- `tcp:tcp_send_reset` also fires for active resets since Linux 6.10 (no skb): not counted
  there, `EV_ACTIVE_RESET` reports them. A reset or retransmit counted on a socket already in
  TCP_CLOSE (e.g. an RST to a segment in flight after an abort) is an `EV_LATE_COUNT` event,
  added to the connection just closed at that pointer (in the counters map it would go to the
  next connection there); a state change from TCP_CLOSE clears the pointer's counters.
- connect(): the kernel sets SYN_SENT before it picks the local port, so that event has
  port 0 and the connection no addresses yet (`setTuple` waits for a port). `EV_LOCAL_PORT`
  reports the addresses when tcp_v4_connect / tcp_v6_connect return (fexit or kretprobe;
  optional, else at the connect syscall's exit: late for a blocking connect). Without it a
  connection stuck in SYN_SENT was missing from `ss` until a keyframe adopted it.
- Keyframes: a TCP row of a later keyframe that no event explains waits one sample
  (`resolveDeferred`): an event that fired just before the dump may not be applied yet. A socket
  adopted from a keyframe takes its first event by its addresses, a listener's own close too.
  `tcp_missed_runs` guard events name the programs the kernel skipped.
  Lost TCP events (ring/perf buffer full, `recorder_stats` dropped; queue overflow `events_lost`; not
  missed runs or budget shedding) bring the next keyframe forward to the first sample a minute
  after the previous one (`keyframeAfterLoss`, 2026-11-21): a lost close keeps a connection open
  until a keyframe or an address reuse finds it gone (11-19 benchmark: four load processes exited
  at once, 57,000 state changes dropped, 14,000 connections open for four minutes).
  `query.TCPLossNote`: an "incomplete:" header on ss, netstat and lsof -i from the sample before
  the losses to the keyframe after them (keyframe times from `reconcile`, loaded whole).
- Open files (`meta fds`): "held" (v2, `fds_held`): an fd is stored at the second consecutive
  walk of its process that sees it (first_seen = the first), deleted files at once; inet
  socket fds only when they add a holder beyond tcp_conns' owner. A process is not re-read
  when its fd count (size of /proc/<pid>/fd, Linux 6.2+) is unchanged and it had no TCP
  activity, except every `--fd-full-every` walks. "all" = v1 `open_files` (with `--tcp sample`).
  A process holding more than `--max-files-per-process` (131072) fds is not tracked (`noFiles`,
  guard event `files_capped`; known from the fd count on 6.2+, else after one read) and, with
  TCP events, not read again; the memory guard also runs inside the walk (every
  `walkCheckFDs` fds read or presumed, on the current heap `heapObjects`) and returns freed
  memory (`debug.FreeOSMemory`); it untracks only processes with more than `shedMinFiles`
  (1000) files, reports memory_ok only a budget window after the last shed, and at most
  `maxNewHeldPerWalk` (200,000) new held files are stored per walk (`fd_walk_held_deferred`).
  `cmd/clifrd/gc.go` `setSoftLimit`: Go's memory limit = 80% of the cgroup's memory.max.
- Event budget (2026-11-11, `recorder/budget.go`, README "Event budget"): an unprivileged flood
  (11,600 fork+exec/s, 30,700 connections/s in a 4-CPU VM) OOM-killed clifrd in 20 s (unbounded
  queues, a /proc read and a command line per event). Per 10 s window: process events (fork, exec)
  full up to `--event-budget-processes` (4000/s) and `--event-budget-cmdline` (1M/s of argument
  bytes), "lite" up to `-max` (10000/s: no /proc reads, command line cut to `liteCmdline` 256, the
  proc connector stat+status only), then only counted; decided in the readers (`fromBPF`,
  `enrichBudget`); a process is kept or dropped whole (`budget.shedBorn`: its exec and exit are
  dropped for `shedMemory` 1 h; an exec of a process recorded at its fork is at worst lite).
  TCP (`tcpBudgetFilter`, reader goroutine): births (CLOSE->SYN_SENT, LISTEN->SYN_RECV) above
  `--event-budget-connections` (5000/s) only counted, later events by sock pointer dropped until
  its close; listeners always kept. One `events_shed` guard event per sample per kind (detail
  "processes: ..." / "tcp: ...", counts, budget, top 5 keys), recorder_stats
  `process_events_lite|_shed|_dropped`, `tcp_conns_shed|_dropped`; `query.BudgetNote` puts an
  "incomplete:" header on events, life, ps range, ss --list, TCP range views. Backstops: queue
  caps `queueCap`/`tcpQueueCap` 500,000 (`events_lost`), the process queue in `queueChunk` (4096)
  chunks (a growing slice copied itself: 1.2 GB heap, 300 MB live), store `--flush-bytes` 16M
  (cmdline, exe, cgroup, label, held fd names; a flush needs ~3x its data). The bound is memory, not
  the rates: while `heapNow` > `--memory-guard`, new processes and connections are only counted
  (`budget.pressure`, checked every `pressureEvery` 100 ms; rates alone let unique 4 KB arguments
  reach MemoryMax, where clifrd livelocked in reclaim without an OOM kill). `cutCmdline` copies
  (`strings.Clone`): a substring kept the 1 KiB original alive (214 MB). `drainEvents` applies
  process events every `tcpDrainEvery` (5 s) between samples into `r.pending` and writes only
  exited event-only processes then (`flushEvProcs` exitedOnly: a live one may be adopted by the
  sample); `afterFlood` returns memory (`freeOSMemory`) at the first sample with neither kind
  above its budget after a flood. Parquet row groups end at `rowGroupBytes` (32 MiB, estimated by
  `rowBytes`: struct size + string lengths; `pqstore/rowgroup.go`) in flushes, compaction and the
  open-file rewrite: parquet-go buffers a whole row group, and a flood hour compacted as one OOM-killed
  clifrd at every start. `pqstore.Options.Busy` (`Recorder.storeBusy`: flooding, or heap > half the
  memory guard) puts compaction off to the next flush.
- Mounts: `mounts` table (present/mount/unmount/remount; the whole table as `present` rows at start and
  hourly, each snapshot replacing the table, so retention never removes a running run's base) from POLLPRI on mountinfo, opened
  with raw open(2): Go's own epoll would consume the kernel's change notification. Since
  schema 2 also `super_options`, `dev`, `root`, `seq` (position in mountinfo: `mount` and `df`
  list in that order; later mounts are appended), `loop_file`, `user_options` (utab).
- `fs_samples`: statfs per mount per sample (frsize, blocks, bfree, bavail, files, ffree), written
  when changed and hourly, in a goroutine that skips rounds while one is still running (hung NFS);
  each mount's statfs is waited for `statfsWait` (1 s), then that mount is stuck (guard event
  `statfs_stuck`, detail "POINT: statfs ...") and skipped until the call returns (`statfs_ok`, its
  row then); `query.statfsStalls` marks it in `clifr df` (`DFRow.StatfsStuck`) until statfs_ok or
  a newer row.
- Per-sample values (`proc_samples`, `sock_samples`) are written when they change and hourly
  (`store.NetSnapshotMS`): retention would otherwise delete an idle process's only row.
  Every hourly rewrite (meta, mounts `present`, idle processes and sockets, `fs_samples`, cgroups,
  units, addresses and routes) comes at the first chance in each UTC hour (`store.OtherHour`), not
  an hour after the previous one: retention deletes whole UTC hours, and with run-phased rewrites
  the oldest hour kept had no mounts, idle values or meta for up to an hour (2026-11-12 VM run,
  `--retention 2h`). `query.MountsAt`: a mount an hourly snapshot repeats keeps its `since`
  (df/lsblk ignored a usage row written seconds before the snapshot); the hourly mount snapshot
  carries the sample's time, as the hourly usage rows do (the oldest hour kept has no earlier
  snapshot). `query.CompleteFrom`: the recording kept starts at the oldest mount snapshot when
  samples come before it (the deleted hour's last minutes, filed in the next hour's flush);
  `Covered`, `clifr info` and `clifr verify` leave those out.
- System-wide counters: every `--sys-interval` (10 s default; also at every sample) writes one `sys_samples` row, one `cpu_samples` row per CPU
  (cpu -1 = total) and one `disk_samples` row per device that has done I/O (`part` = 1: a partition,
  from /sys/block). Values are the kernel's raw cumulative counters, so a report is a difference:
  `--at` = since boot (`uptime_ms`; what the real tool prints without an interval, and what
  `clifr verify` compares, with a tolerance), a range = one report per sample interval. No rates
  are stored; resolution = `--sys-interval`. `uptime` (and `w`'s, `top`'s first line) at `--at T`: T's
  clock, the uptime extended to T (`UptimeRow.At`), the users at T (`query.UsersAt`), the sample's loads.
  Clock steps (2026-11-21, HANDOFF 0k): `uptime_ms` comes from CLOCK_BOOTTIME and `boot_ms` (schema 12) is
  the boot time on the clock at each system sample (now - CLOCK_BOOTTIME, read together); the run's
  boot time, measured once at start, stays in process start times and keys (joins). A move above 100
  ms is a `clock_step` guard event. Readers: `query.StartShiftAt` puts starts in moment views on the
  clock at T (`processesAt`, atop's exited processes and btime), `query.startShift` in history views
  (life, containers over a range) adds the steps between the run's start and the process's; ps's
  btime is cut from `BootClockAt`.
  Schema 12 (2026-11-21, for atop): `sys_samples` also holds meminfo's Committed_AS, CommitLimit,
  PageTables, HugePages_Total/Free, Hugepagesize, AnonHugePages, Zswap, Zswapped; vmstat's pgscan_*/
  pgsteal_* (kswapd, direct, khugepaged, proactive; per-zone lines of old kernels summed; not _anon/_file
  or pgscan_direct_throttle), allocstall (summed), compact_stall, pgmigrate_success,
  numa_pages_migrated, oom_kill, zswpin, zswpout; and PSI totals (µs: psi_cpu|mem|io_some|full;
  `psi` = 1 where /proc/pressure exists, NULL before schema 12), the PSI some lines' avg10/60/300
  (`psi_*_avg*`, hundredths: atop shows PSI only when one is not 0), `zswap_enabled`,
  `pgscan_direct_throttle` (atop counts it as a scan); `links.speed`/`duplex` (sysfs, -1 unknown);
  `proc_samples.run_delay_ns`: all threads' schedstat run delay (atop's RDELAY; `wait_ns` stays the
  main thread's, pidstat's). Also over all threads (2026-11-21, `procfs.ReadThreads`: each thread's
  schedstat, stat, status, ~20 µs a thread, for multi-threaded processes by the I/O rule; a
  single-threaded one takes its own values): `blkio_all_ticks`, `vol_ctx_all`, `nonvol_ctx_all`,
  `thr_run|sleep_i|sleep_u|idle` (atop's BDELAY, NVCSW/NIVCSW, TRUN/TSLPI/TSLPU/TIDLE, PRC #tidle);
  status's `vm_stk|swap|data|exe|lib|lck_kb` (atop -m); `processes.rgid` (-1: event-only).
  Schema 13 (2026-11-22, for iotop, `recorder/ioprio.go`): `proc_samples.ioprio`, the main thread's I/O
  priority as both iotops show it (class << 13 | data: the one set with ioprio_set, else derived
  from the policy and nice: FIFO/RR rt/((nice+20)/5), IDLE idle, else be/((nice+20)/5); the policy
  from sched_getscheduler for FIFO/RR/IDLE only, as SCHED_RESET_ON_FORK, absent from stat, makes
  iotop say be: rtkit's canary thread), -1 unknown (system calls: none with `--proc-root`
  fixtures), at every sample; `ioprio_dif` = 1 when the threads' names ("rt/N", "be/N", "idle")
  differ (iotop -P: "?dif"), from the per-thread walk (`procfs.Threads.Prio`: each thread's nice and
  policy). Checked against iotop 0.6 on the desktop: 521 of 521 processes the same, 7 "?dif".
  About 0.3 us per process per sample. Also `thr_read_bytes|thr_write_bytes|thr_cancelled_write_bytes`:
  the live threads' own counters summed (`task/*/io`: in the per-thread walk, or `task/PID/io` for a
  single-threaded one, by the I/O rule), what iotop adds up: /proc/PID/io also holds reaped children's
  I/O (wait_task_zombie adds it to the parent: a shell running dd shows the copy) and exited threads'.
  The I/O rule (2026-11-22): a process is also "fresh" when its main thread's run time in
  /proc/PID/schedstat (ns) changed: CPU time is charged in ticks to whoever runs at the tick, and
  jbd2 wrote megabytes without one (iotop verify: 8.8 MB/s real, 0 clifr); ~5 us a process whose
  ticks did not change (2.5 ms a sample for 520 processes). Multi-threaded processes whose workers
  run briefly while the main thread sleeps can still be late.
  `clifr iotop` (query/iotop.go, following iotop 0.6's Python code, packaging/notices/iotop.txt):
  iotop -b's output in the recorded build (`ToolStyle.Iotop`: "" 0.6-42, "0.6-24" ubuntu-22.04,
  "rhel" rhel-8/9: "Total DISK READ :", "Actual DISK READ:", lines as b'...'); processes only (a
  header says so without -P); at `--at` the interval between the two process samples at or before
  T, over a range iotop's first screen (zeros) then one per -d (snapped to samples with 10% slack);
  processes alive at both ends (new ones with zeros), ties in the order iotop first saw them (PID);
  sorted by IO % with delay accounting (`IotopDelayAcct`: kernel.task_delayacct = 1 or no such
  sysctl, RHEL 8) or by 0.6-24, else by DISK WRITE; SWAPIN not recorded ("?"). Verify: clifrd starts
  `iotop -b -P -n 2 -d INTERVAL` in the background at a checkpoint (`startIotop`, collected at a
  later sample; its PID is ignored in the other captures meanwhile), compared with clifr's interval
  from the checkpoint sample to the one nearest iotop's end (`compareIotop`; iotop-c not compared).
  Desktop and four VMs: every process matched, 99.4-100% exact. `verify.Run` sets time.Local to the host's zone
  per checkpoint (`query.HostZone`: meta timezone, else tz_offset_s; 2026-11-22): the tools printed in it. iotop captures (Python
  0.6-18/-24/-30/-42, iotop-c 1.21/1.26/1.31/1.33; desktop and four VMs):
  bench/results/iotop-captures-20261122.
  `clifr sar` (query/sar.go, following sysstat's code, GPL-2.0-or-later, packaging/notices/sysstat.txt;
  2026-11-22): sar -f's output over --since/--until (no --at), by `ToolStyle.Sar` ("" 12.7.7, "12.6"
  ubuntu-24.04, "12.5" rhel-9/ubuntu-22.04, "11.7" rhel-8): records = the first system sample at or
  after each multiple of -i SEC (default 600, local clock, as sa1's timer); a boot in the window is a
  LINUX RESTART and its segment's first record the next multiple (sa1 --boot writes only the mark);
  per segment each report in sysstat's activity order with its Average (rates over the segment, levels
  averaged; sysstat's integer divisions kept), the header again when 86400 lines are counted (-P ALL
  counts the 8200 bits of its CPU bitmap: every 11 records). Reports: -u [ALL] -P -B -b -d [-p] -w -W
  -r [ALL] -S -H -v (sysctl snapshot, minute) -q [CPU|IO|MEM|PSI|ALL] -I SUM (11.7, 12.5: /proc/stat intr;
  12.6+: the "interrupts" snapshot, minute, rates over the reads' own interval) -I ALL (12.6+ only) -m CPU
  -n DEV EDEV NFS NFSD SOCK IP EIP ICMP EICMP TCP ETCP UDP SOCK6 IP6 EIP6 ICMP6 EICMP6 UDP6 SOFT -F [MOUNT]
  (sar14.go: paging, io, disk, softnet, cpufreq, psiio/psimem, 12.6+ irq). -d: whole devices only (sa1's
  default -S DISK), in diskstats order (disk_samples.pos), -p names dm devices from blockdevs.dm_name;
  11.7 names devMAJ-MIN without -p and has svctm. -b leaves out virtual devices (disk_samples.virtual).
  Schema 14 (2026-11-22, for sar): sys_samples pgfree, pgsteal_anon/_file (sar's pgsteal = every
  pgsteal_ line), pgpromote, pgdemote, anon_pages, kernel_stack, vmalloc_used, hugepages_rsvd/_surp,
  psi_{mem,io}_full_avg{10,60,300}; cpu_samples mhz (sadc's /proc/cpuinfo hundredths, every system
  sample, 0.23 ms on 22 CPUs) and softnet_* (NULL: none); disk_samples pos and virtual (no
  /sys/block/NAME/device); snapshots source "interrupts" every minute (0.3 ms a read on 22 CPUs; at
  every sample its ~2,400 changing counters would multiply the data written). Interfaces by name (check_net_dev_reg: a counter going down = re-registered, from
  zero). Known: runq-sz reads high by clifrd's own running threads; interface values are read every
  --sys-interval, process samples' values up to that old. Checked: bench/sarcheck.sh (sadc -S ALL 60
  beside a 5 s clifrd), bench/sarcompare.sh, bench/sarcheck (internal/verify.ParseSar); clifr verify
  compares the sar REPORTS INTERVAL 1 clifrd runs in the background at checkpoints (recorder.sarReports,
  `bgCapture`, shared with iotop). bench/results/sar-captures-20261122.
  `clifr htop` (query/htop.go, following htop 3.2.1/3.3.0/3.4.1's C code, GPL-2.0-or-later,
  packaging/notices/htop.txt; 2026-11-22): htop's default screen as text at `--at` only, by
  `ToolStyle.Htop` ("" 3.4.1, "3.3" rhel-9/ubuntu-24.04, "3.2" rhel-8, "3.0" ubuntu-22.04); user
  threads hidden (not recorded; Tasks counts them from each process's thread count), kernel
  threads hidden (cmdline empty and pid 2 or ppid 2), every process (no screen height, no
  function bar), $COLUMNS / the terminal / 80 wide; %CPU over the process-sample interval as
  htop's period (all CPUs' ticks / CPU count). htop 3.0.5 is GPL-2.0-only (3.1.1 relicensed to
  GPLv2+): `query/htop30.go` is written from its output only (`testdata/htop/SPEC-3.0.5.md`);
  never read htop 3.1.0's or older code. Checked with `bench/htopcheck.sh` (captures in tmux
  with htop's own default htoprc + hide_userland_threads=1, beside a 5 s clifrd recording) and
  `bench/htopcompare.sh` (bench/htopcheck): desktop and four VMs, 35 screens, every header and
  process line laid out the same (bench/results/htop-captures-20261122).
  `clifr atop` (query/atop.go, atopfmt.go; following atop's code, packaging/notices/atop.txt): as
  root into a pipe; at `--at` the screen since boot, over a range `atop INTERVAL [COUNT]` (the
  increase between the samples at or before each bound; active processes, exited ones as <name>);
  the process views from atop's own column lists (`atopViews`, one catalog `atopColumns`, fitted
  to 80 columns by priority, `-m -d -s -v -c`). Versions by style (`AtopSys.SetStyle`): 2.12.1;
  2.7.1 (`Atop271`: rhel-8/9, ubuntu-22.04); 2.10.0 (`Atop210`, ubuntu-24.04: 2.12.1's lines and
  views, 2.7.1's header). Known limit: atop adds a CID column when a process has its own UTS
  namespace and host name (Ubuntu cloud images' udevd/timesyncd keep "ubuntu"), dropping
  RDELAY/BDELAY; clifrd cannot read those host names (setns needs CAP_SYS_ADMIN). Captures, all
  views as root on the desktop and four VMs: bench/results/atop-captures-20261121.
- `clifr vmstat` (query/vmstat.go, following procps' vmstat.c; 2026-11-23): `-a -w -t -n -y -S UNIT` on the
  default report and `-s -f -D` (--at), `-d -p -m` (counters at each report's sample), by `ToolStyle.Vmstat`
  ("" 4.0.4, "3.3.17" rhel-9/ubuntu-22.04: no gu, "3.3.15" rhel-8); the header again every 21 lines (a pipe;
  -d: 4.0.4 counts every /proc/diskstats device, partitions too); procps 4's since-boot line divides cs by
  the CPUs' ticks and takes guest time out of us. -d lists devices without I/O (not in disk_samples) from
  blockdevs with zeros, placed by device number. `clifr iostat` (query/iostat.go, sysstat's iostat.c):
  the first line (`SysstatFirstLine`, shared with sar), `-c -d -x -s -k -m -z -N -t -y`, a blank line after
  each report (two in sysstat 12), no time without -t; sysstat 11.7 lists devices in diskstats order (pos).
  Checked with bench/vmstatcheck.sh + bench/vmstatcompare.py: 28 commands on the desktop and four VMs, all
  laid out the same (-t prints the sample's time).
- `net_counters` (schema 4): every counter of /proc/net/snmp, netstat and snmp6 (nstat names,
  `section` = snmp/netstat section, "" in snmp6, `pos` = file order), at system samples, written when changed and all every
  `store.NetCountersFullMS` (5 min), so a moment needs only the rows of the 5 minutes before it
  (`internal/duck` loads that window).
- `links` (schema 5): each network interface from rtnetlink (`internal/rtnl`, RTM_GETLINK) at
  system samples: every attribute ip -s -d link prints (-1 / empty when the kernel does not send
  it), the raw per-type data (`info_data`, `slave_data`: not printed yet) and rtnl_link_stats64;
  a row when anything changed, all every 5 min, `gone` = 1 when it went away. Not with
  `--proc-root` fixtures.
- `addrs` (schema 5): interface addresses from rtnetlink (`recorder/netwatch.go`): `present` rows
  at start, every `store.NetSnapshotMS` (1 h) and after ENOBUFS (`seq` = dump order); `add`/`del`
  rows from RTM_NEWADDR/DELADDR notifications at receive time (`seq` orders one ms). A moment =
  the last snapshot before it plus the changes after (`query.AddrsAt`); lifetimes counted down.
- `routing` (schema 5): routes and rules as raw rtnetlink messages (`msg`, parsed when printed:
  `query/iproute.go`, `iprule.go`), `kind` route|rule, `key` (`rtnl.RouteKey`/`RuleKey`) for
  changes; same present/add/del scheme as `addrs`, plus a re-dump ~1 s after changes (at most
  every 10 s, not above 50,000 routes) so the kernel's order is recorded.
- `kmsg` (schema 6): /dev/kmsg records (`kind` msg: seq, prio, mono_us, caller, msg as the kernel
  escapes it, redacted; `boot_id`) read as written (`recorder/kmsg.go`; at start the whole buffer
  again: readers keep one row per boot and seq), and `ring` rows (oldest seq in the buffer,
  realtime-boottime and boottime-monotonic in µs for dmesg -T) at start and at most every 10 s
  while records arrive; `pstore` rows (2026-11-14, `recorder/pstore.go`): the previous boot's crash
  records from /sys/fs/pstore and /var/lib/systemd/pstore, at the first run of a boot, newer than the
  previous run's start, under that boot's id, with a `pstore` guard event (readers filter kind); `clifr pstore` prints them
  (`query.PstoreRecords`, `query.PanicReason`, shared with the guard event). Needs CAP_SYSLOG (in the unit; `ProtectKernelLogs=no`, and
  `DeviceAllow=/dev/kmsg r`: ProtectClock's device allow list excludes it otherwise).
- `units` (schema 7): systemd's loaded units (`internal/sdunits`, godbus/dbus over
  /run/systemd/private, else the system bus; `recorder/unitwatch.go`): `present` snapshot at
  start, hourly and after reconnecting (systemd closes the socket on daemon-reexec); `change`/
  `gone` rows from a ListUnits diff 200 ms after a signal, at most every second. Connected in the
  background (retried every 5 s) and every D-Bus call bounded by `sdunits.Timeout` (10 s): right
  after a restart systemd may not answer, and a call without a timeout once stopped the recorder
  from starting at all (2026-10-23, RHEL 8 and 9 VMs).
- `proc_samples` I/O columns (schema 2): rchar, wchar, read_bytes, write_bytes,
  cancelled_write_bytes from /proc/<pid>/io, re-read only when the process used CPU since its
  last sample and on fd-walk samples (cumulative: a skipped read only delays the update).
- Process fields (schema 8): `proc_samples` min_flt, maj_flt, priority (stat field 18: top's PR,
  -100 = "rt"), policy, rt_priority, processor, ps_flags (ps's F: (PF_* >> 6) & 7) (stat) and shr_kb (statm: top's SHR) at every
  sample; vol_ctx, nonvol_ctx (status) and wchan ("0" = running) by the same rule as the I/O
  columns. `processes.label` (attr/current) and `cgroup` (/proc/<pid>/cgroup, all lines) when
  first sampled, on fd walks, the label also at an exec; empty for event-only processes. NULL in
  older recordings (top then prints PR as 20 + NI and SHR as "-"). For pidstat: stime_ticks,
  guest_ticks, blkio_ticks, rss_stat_kb (stat's approximate RSS: pidstat's; rss_kb is statm's,
  ps's and top's) at every sample, wait_ns (schedstat run delay) by the I/O rule,
  `processes.ruid` (real uid: pidstat's UID). comm and ppid are updated whenever stat shows a
  change (renames), the rest of the process row on fd walks and execs. `processes.cmdline_pad`:
  NUL bytes after the command line (1 normally; more when a process rewrote its arguments:
  systemd-cgls counts them). `cgroups` table (path in systemd's hierarchy, `delegate`: systemd's
  trusted.delegate/user.delegate xattr, `cgroup_id` (the directory's inode: systemd 252 prints
  it), `xattrs` (user.*/trusted.* as name=value lines; under the unit, without CAP_SYS_ADMIN,
  no trusted.*: `query.deriveTrusted` adds systemd's mirrored trusted.invocation_id/delegate
  from the user.* copies when no recorded cgroup has a trusted.* name, except below a
  delegated cgroup)) written when a run first sees a path (a
  process's cgroup or an ancestor), when its inode changes (recreated) and hourly; loaded whole. Sibling cgroups are listed in kernfs order (the
  kernel's name hash, `query.kernfsHash`), so the directory tree itself is not recorded.
- `snapshots` (schema 9): files read whole at system samples, one row per line
  (`procfs.SnapSources`: swaps, modules, hostname; `key` = the line's first field, else "#n"):
  `whole` = 1 rows are the whole file, written at a run's first read, every
  `store.NetCountersFullMS` and whenever the keys or their order changed (an empty file: one row
  with pos -1); otherwise only changed lines. `query.FileAt` = the last whole copy plus the
  changes after it. The CLI parses the lines when printing. lsmod lists a module's users in
  kernfs order (`/sys/module/*/holders`), computed from the names; `hostname` and `uname -n`
  use the recorded host name (a change while clifrd runs), the run's meta before schema 9.
- `blockdevs` (schema 9): each device of /sys/block and its partitions (`parent`) as lsblk reads
  them: size, ro, removable, hidden, dm name/uuid, md level, SCSI type, holders, slaves, loop
  backing file, and FSTYPE/FSVER/LABEL/UUID from udev's database (/run/udev/data, as lsblk reads
  it first). Read at a system sample after a block uevent (`recorder/uevent.go`: kernel and udev
  groups of NETLINK_KOBJECT_UEVENT) and every minute (a full read is ~12 ms with 65 devices);
  written like `links` (changed rows, all every 5 min, `gone`). `query.LsblkAt` builds lsblk's
  tree (roots: devices without slaves; partitions, then holders; sorted by glibc's makedev as
  lsblk sorts by MAJ:MIN), mount points from `mounts`, FSAVAIL/FSUSE% from `fs_samples`;
  libsmartcols' widths (an absolute hint widens a column only when its data are as wide as the
  header) and continuation lines for several mount points. `mount -l` labels from it (by dev).
  `mounts.loop_file` is set only for loop devices with autoclear (mount shows those by their
  backing file, others as /dev/loopN; any loop device before 2026-10-23).
- `neighs` (schema 9): the ARP/NDISC table (`rtnl.DumpNeighs`, kernel order) at every system
  sample, written like `snapshots` (whole when the entries or their order change and every 5 min,
  else changed entries); cacheinfo ages stored as times (`*_ms`, ±20 ms is no change), so
  `ip -s neigh` counts them on to T. `snapshots` source "netns": /run/netns in directory order
  with each namespace's id (RTM_GETNSID; "name id", -1 none). `IPNeighOld` (ubuntu-22.04):
  iproute2 5.15 separates fields with a leading space.
- `snapshots` sources "sysvipc/msg|sem|shm" (keyed by id; `ipcs`, `ipcs -u` sums them) and
  "locks" (`recorder/locks.go`): each /proc/locks line plus what lslocks resolves at run time, as
  "line\tpath\tsize\tholder pid\tholder comm": the path and size through the holder's fds
  (lslocks' get_filename_sz: first fd but 0 on the inode; cached per pid and inode, then only
  the fd re-stat'ed) and an OFD lock's holder from every process's fdinfo "lock:" lines (util-linux
  2.41; scanned only when the OFD lock lines change, at most once a minute: until then a new OFD lock has no holder). lslocks lists /proc/locks in reverse;
  `LslocksOld` (before 2.41): OFD locks -1 "(undefined)" with the fallback path (mount point...).
- `snapshots` source "sysctl" (`recorder/sysctl.go`), read every minute (`snapReader.everyMS`; a read
  is 8-10 ms for ~1,600 files with raw syscalls): /proc/sys walked as procps' sysctl -a (3.3 and 4.0
  alike: directory order, deprecated names and unreadable files skipped, each line of a file as
  "name = line" with '.' and '/' swapped), keyed by name. Its whole copies come at the first read
  after 5 min, so `internal/duck` loads `snapshots` (and `blockdevs`) a minute further back.
- `snapshots` sources "slabinfo" (`procfs.SnapSource.EveryMS`: a minute) and "numa" (each node's
  numastat and meminfo lines and its huge pages per size, a minute): `slabtop -o` (procps 3.3's
  merge sort and USE formula with `Slabtop3`, 4.0's stable sort otherwise) and `numastat [-m] [-n]
  [-c] [-z]` (numactl 2.0.19's table code; without options the compatibility output; `NumastatOld`:
  before 2.0.15, fixed rows and "Token X not in hash table." lines). Values are
  as of that read: verify compares their numbers with a tolerance.
- `snapshots` sources (a minute) "conntrack" (`rtnl.ConntrackStats`: ctnetlink's per-CPU counters,
  asked only while nf_conntrack_netlink is loaded: the request would load it), "rpc/nfs" and
  "rpc/nfsd" (/proc/net/rpc), "mountstats" (the NFS sections of /proc/self/mountstats):
  `conntrack -S` (`ConntrackOld`: conntrack-tools before 1.4.7 stop at search_restart), `nfsstat`
  (nfs-utils' C code, the same in 2.3-2.6) and `mountstats [-n|-r|-x|-R]` (a clean-room
  reimplementation, 2026-11-21: mountstats.py is GPL-2.0-only, so the first port was replaced by code written
  from the real tool's output only, `query/testdata/mountstats/SPEC.md`, its golden cases from nfs-utils
  2.3.3 and 2.5.4/2.6.1; never read mountstats.py or the old port when changing it; `Mountstats233`: RHEL 8's 2.3.3).
- Logins (2026-11-20, `recorder/sessions.go`, `query/who.go`, `w.go`, `last.go`): `snapshots` sources
  "utmp" (every /run/utmp record as text, keyed "#slot"), "logind" (/run/systemd/sessions/ID, "ID=..."
  then `logindKeys` only: no DEVICES, CONTROLLER, fds) and "ttyatime" (each session terminal: atime,
  mode, tty_nr as /proc/PID/stat has it). Read at every system sample and 200 ms after an inotify
  event (`sessWatch`; reads under one mutex so their times stay in order). `who`: utmp when recorded
  (GNU coreutils 8.30/8.32), else logind as uutils 0.10.0 builds records (seat and tty lines, PID 0,
  uids: Ubuntu 26.04's AppArmor profile denies its who /etc/passwd, `StyleAt(..).UnameUnknown`).
  `w`/`uptime` by style: `Procps3` (rhel-8/9, ubuntu-22.04: utmp, pid order) or Debian/Ubuntu's
  patched procps 4.0.4 (logind's class user* sessions, start-time order, the tty via the leader's
  children); `WNoFrom`: RHEL 9's w has no FROM unless -f. `last`: util-linux 2.32/2.37 ported
  (`LastAt` = process_wtmp_file + list) over records derived from the utmp/logind history
  (`LoginRecords`: login on a new user record, logout at its DEAD record or when seen gone, none
  across a reboot; `BootRecords`: boot + a shutdown at each clean boot's last sample). One deviation,
  the user's (2026-11-20): a boot clifr knows crashed (`Boot.Crashed`) ends "- crash" at its last
  sample; util-linux runs it on to the next shutdown. Tools with `history: true` (last) open the
  whole recording (tables load lazily). Golden tests from the real tools: `query/testdata/who/`
  (containers, crafted utmp/wtmp, real ptys; captures from this desktop trimmed and the user renamed).
- `snapshots` source "passwd" (2026-11-08, a minute; `recorder/users.go`): the host's "uid name" pairs
  from /etc/passwd (nothing else of it), so a recording read on another machine (`--host`, a
  bundle) names users as the host did: `query.LoadUsers` at the queried moment, then
  `query.UserName`. Older recordings: this machine's names (a header says so when the machine-id
  differs). Never use `user.LookupId` for a recorded uid when the recording has names.
  Source "group" (schema 12, for atop -v): "gid name" pairs only (never members), `query.GroupName`;
  without it this machine's names only for a recording from this machine or one without names.
- `meta` (per run, latest wins in DuckDB; the store writes the run's whole meta again hourly, as
  retention deletes hours: `query.MetaAt` takes the copy of the run recording at T, else its first later one): `schema_version` (`store.SchemaVersion`, 13 since
  2026-11-22; no key = 1; clifr refuses newer ones), `clifrd_version`, `hostname`,
  `machine_id`, `boot_id`, `timezone` (IANA name), `tz_offset_s`, `uname_sysname|release|version|
  machine` (schema 3), `os_id`, `os_version_id`, `os_id_like`, `os_pretty_name` (2026-10-21),
  plus boot time, intervals and modes. Tool styles (`query/style.go`): clifr prints free, top,
  df, lsof, vmstat, iostat, systemd-cgls, swapon --summary and lsblk as the recorded distribution's tool versions do (rhel-8, rhel-9,
  ubuntu-22.04; current otherwise; `--style` overrides); each flag was confirmed in a VM. `UnameUnknown` (uutils coreutils, Ubuntu 25.10+:
  `uname -p`/`-i` print "unknown", left out of `-a`) is set by `StyleAt` from the distribution, not a style. Per-run values (hostname, uname,
  boots for `last`) are read from the meta files by `query.MetaAt` / `query.Boots`, not the
  latest-wins table. `sys_samples` also holds /proc/net/sockstat and sockstat6 (schema 3; NULL
  before) for `ss -s`. `processes.argv0_len`: length of argv[0] in `cmdline` (0/NULL unknown; netstat names).
- Redaction (`--redact`, clifrd.yml `redact`): `recorder.Redactor` masks command lines before
  they are stored; every /proc read goes through `r.readCmdline`, exec events through
  `r.redact.Cmdline`; argv[0] and the arguments are masked apart (argv0_len stays right).
  meta `redact_patterns` = their number (not the patterns).
- Times are Unix milliseconds (INTEGER). CLI times are local time `YYYY-MM-DD HH:MM:SS`.

## Commands
- Build: `CGO_ENABLED=0 go build -o clifrd ./cmd/clifrd` and `go build -o clifr ./cmd/clifr` (cgo, needs g++).
  go.mod pins toolchain go1.26.8 (downloaded automatically by an older `go`).
- eBPF self-test (root): `sudo ./clifrd --test-ebpf [--ebpf-force-perf --ebpf-classic-fork]`;
  `sudo ./clifrd doctor`: what the system supports (loads and closes the programs), the recording level.
- Test: `go test ./...` (eBPF tests skip without root; `go test -c` + sudo to run them); e2e: `sudo env PATH=$PATH HOME=$HOME go test -tags e2e -count=1 ./test/e2e`
- Ground truth (root; small ≈ 4 min, full ≈ 14 min with the recorder's defaults; results in `bench/results/truth-<scale>-<time>/`):
  `sudo env PATH=$PATH HOME=$HOME go test -tags truth -count=1 -timeout 40m -v ./test/truth -scale small|full`
- clifrd reads `/etc/clifr/clifrd.yml` (example: `deploy/clifrd.yml`; flags override it). The bench
  scripts and tests pass `--config /dev/null` so a machine's file cannot change results.
- Quick manual run: `sudo ./clifrd --data-dir /tmp/d --interval 2s --flush-interval 30s --duration 1m`,
  then `./clifr --data-dir /tmp/d --at "..." "ps aux"`
- Machine notes: v2 milestones 6–9 ran on the current machine (bare metal,
  Intel Core Ultra 7 155H): 22 logical CPUs, 61 GB RAM,
  Ubuntu 26.04, kernel 7.0, Go 1.27, PostgreSQL 18 (uutils coreutils: do not
  rely on GNU-only `date` etc.). Set up with `sudo bench/setup.sh` on 2026-10-10;
  unit tests, both `--test-ebpf` modes and the e2e test pass there. Earlier
  numbers are not comparable with it: v1 and v2 milestones 1–5 ran on the old
  8 vCPU VM (kernel 6.8, failing disk), the busy 20261008-0721 batch on a
  4 vCPU Ubuntu 26.04 VM. Calibrated pgbench rate here: `--rate 80000 --cpus 0-11`.
  Bench scripts abort below 1.5 GB free and validate every run
  (`bench/report -validate`). Close the browsers before a benchmark (`bench/run.sh` warns):
  clifrd records the whole desktop, and open browsers added 0.3-0.4 point of one core at the
  busy load (2026-11-19, `bench/results/cpu-ab-20261119`).
- The committed eBPF objects are in sync with the `.bpf.c` sources and load on
  any supported kernel unchanged (CO-RE): no regeneration per machine or kernel,
  only after editing a `.bpf.c` file (`go generate`; needs the apt packages
  clang-18, llvm-18 and libbpf-dev, installed on the current machine since M6).

## Milestone status
v1 (tag `v1-snapshot`): milestones 1–9 done; its report generator and
benchmark were finished as v2 milestone 1 (results: busy 20261008-0721 batch).

v2:
1. [x] Tag v1; fix the report bugs; validation step (no v1 rerun: the 0721 data were repaired)
2. [x] Storage interface, Parquet writer (rotation, compaction, retention), DuckDB CLI; parity via `clifr verify`
3. [x] eBPF process events (proc connector fallback), OOM events
4. [x] eBPF TCP events, keyframes, reconciliation; `ss` at/range
5. [x] Long-held fd snapshots, mount events
6. [x] Ground-truth tests (`test/truth`; full scale 41/41 checks, results: truth-full-20261010-1602)
7. [x] Benchmark: bpf_stats, new matrix, scaling, report (results: busy-20261012-1050,
   scaling-20261012-1050, report-20261012-1050). Rerun after the CPU plan on 2026-10-17
   (busy-, scaling-, report-20261017-1133): 2.14% of one core at the busy load, all 15
   scaling points within the 2% budget, no measurable pgbench impact. Then for memory
   (2026-10-17/18): pointer-free rows in memory and `--gc-heap-target` 256M (was 384M):
   single runs at the busy load 282 / 330 MiB avg / max with 256M, 326 / 379 with 384M
   (429 / 488 in batch 1133); 348 MiB max with 100,000 connections (561). Rerun after phase 3
   (2026-10-19, busy-, scaling-, report-20261019-1620): 1.84% of one core, 285 / 332 MiB at the
   busy load, all 15 scaling points within budget, no measurable pgbench impact. Rerun after
   phase 8 step 2 (2026-10-22, busy-, scaling-, report-20261021-2027): 1.86% of one core,
   285 / 323 MiB, all 15 scaling points within budget; pgbench latency +1 µs average, +2 µs
   p99 (1–2%), now measurable because the no-recorder runs were steadier (±0.000 ms against
   ±0.008): say "about 1 µs (1–2%) added latency", not "no measurable impact". Rerun after
   phase 8 step 3 (2026-10-23, busy-, scaling-, report-20261022-1900): 1.85% of one core,
   286 / 329 MiB, all 15 scaling points within budget; pgbench +1 µs average (within noise),
   +3 µs p99; fd-walk samples about 45 ms longer (283 against 238 ms p50: the new per-process
   reads), other samples about 2 ms. Rerun after phase 8 step 4 (2026-10-24, busy-, scaling-,
   report-20261023-2100): 1.90% of one core, 287 / 335 MiB, all 15 scaling points within budget,
   pgbench within noise; the once-a-minute reads (~15 ms: block devices, sysctl, slabinfo) make
   every other 30 s sample that much longer (71 against 57.5 ms p50 without an fd walk). Rerun after
   iotop/htop/sar/atop (2026-11-22, busy-, scaling-, report-20261122-2240, commit 0daec32): 2.17% of
   one core (2.03 on 11-19), 288 / 333 MiB, all 15 scaling points within budget, pgbench p99 +2 µs
   (1.4%); the process phase 76 against 53 ms p50 (main-thread schedstat, per-thread walk, ioprio).
8. [x] System-wide counters: /proc/stat, loadavg, meminfo, vmstat, diskstats per sample
   (raw cumulative counters; system, per-CPU and per-disk tables); `clifr uptime|vmstat|
   mpstat|iostat`; `clifr verify` compares them (`uptime`'s user count since 2026-11-20). About 0.2 ms of
   reads per sample (in the 1133 numbers, not in the 1050 ones).
9. [x] README (v2: build, recording, querying, tests, benchmark, results of M6–M8, limitations)
