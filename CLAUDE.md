# clifr — Linux flight recorder (working prototype)

`clifrd` continuously records which processes existed, which sockets and open
files each one held, short-lived process start/exit events and the system-wide
counters, as Parquet files (or, for v1 comparisons, one SQLite file).
`clifr` reconstructs the output of the real tools (`ps`, `lsof`, `ss`, `netstat`, `free`,
`uptime`, `vmstat`, `mpstat`, `iostat`; clifr-only `events`, `life`, `oom`, `mounts`) for a
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
1–9 done. v1 (snapshot-based, SQLite) is tagged `v1-snapshot` and stays
benchmarkable side by side. `HANDOFF.md` has the current results, the open
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
  encoding) behind a small interface; the v1 SQLite schema stays available as
  a backend for side-by-side comparison.
- Other dependencies only with the user's approval.
- Parse /proc ourselves. **Never read `/proc/*/environ`.**
- All /proc access goes through `procfs.FS` so `--proc-root` fixtures work.
- No network, encryption, obfuscation or web UI.

## Layout
- `cmd/clifrd/` — the recorder binary (static, no cgo).
- `cmd/clifr/` — the query CLI (DuckDB via cgo): `clifr [--at T | --since A --until B] [OPTIONS] "COMMAND [ARGS]"`;
  per-command option tables in `tools.go`, `tools2.go`, `systools.go` (unsupported options
  are rejected);
  `--data-dir` Parquet or hidden `--db` SQLite.
- `internal/procfs/` — /proc parsers (stat, status, cmdline, fd, net/*, meminfo; `system.go`: the
  system-wide stat, loadavg, meminfo, vmstat, diskstats).
- `internal/sockdiag/` — NETLINK_SOCK_DIAG (inet_diag) dumps.
- `internal/bpfproc/` — eBPF process events (fork/exec/exit, OOM): `procevents.bpf.c`
  (CO-RE, no vmlinux.h) and the committed bpf2go objects; `go generate ./internal/bpfproc`
  rebuilds them (clang-18, llvm-strip-18, libbpf-dev).
- `internal/bpftcp/` — eBPF TCP events: `tcpevents.bpf.c` (state changes with owners,
  accept fds, app close, time-wait start/end, retransmits/resets); objects for amd64 and arm64.
- `internal/cnproc/` — kernel proc connector (fork/exec/exit events), the fallback.
- `internal/store/` — `Backend` interface, v1 SQLite schema and batch writer, `Tee`.
- `internal/pqstore/` — Parquet backend: flush windows, open-entity files, compaction, retention.
- `internal/duck/` — loads a Parquet data directory into in-memory DuckDB with the v1 table names.
- `internal/recorder/` — sampling loop, interval trackers, self-metrics, guard rails.
- `internal/query/` — reconstruction and formatting of ps/lsof/ss/life/stats.
- `internal/verify/` — compare saved real tool output with reconstructions.
- `internal/bundle/` — `clifrd bundle` (pure Go): a window's data files as one tar with
  `bundle.json`; `Extract` for `clifr --data-dir FILE.tar`. `deploy/sos/clifr.py` — sos plugin.
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
  flush to `<table>/open/<run>.parquet` with last_seen = last sample. Readers keep one
  row per id (closed row first). Ids = run start (Unix s) × 1e9 + counter.
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
  reset/retransmit counters are still classic tracepoints.
- `tcp:tcp_send_reset` also fires for active resets since Linux 6.10 (no skb): not counted
  there, `EV_ACTIVE_RESET` reports them. A reset or retransmit counted on a socket already in
  TCP_CLOSE (e.g. an RST to a segment in flight after an abort) is an `EV_LATE_COUNT` event,
  added to the connection just closed at that pointer (in the counters map it would go to the
  next connection there); a state change from TCP_CLOSE clears the pointer's counters.
- Keyframes: a TCP row of a later keyframe that no event explains waits one sample
  (`resolveDeferred`): an event that fired just before the dump may not be applied yet. A socket
  adopted from a keyframe takes its first event by its addresses, a listener's own close too.
  `tcp_missed_runs` guard events name the programs the kernel skipped.
- Open files (`meta fds`): "held" (v2, `fds_held`): an fd is stored at the second consecutive
  walk of its process that sees it (first_seen = the first), deleted files at once; inet
  socket fds only when they add a holder beyond tcp_conns' owner. A process is not re-read
  when its fd count (size of /proc/<pid>/fd, Linux 6.2+) is unchanged and it had no TCP
  activity, except every `--fd-full-every` walks. "all" = v1 `open_files` (with `--tcp sample`).
- Mounts: `mounts` table (present/mount/unmount/remount) from POLLPRI on mountinfo, opened
  with raw open(2): Go's own epoll would consume the kernel's change notification. Since
  schema 2 also `super_options`, `dev`, `root`, `seq` (position in mountinfo: `mount` and `df`
  list in that order; later mounts are appended), `loop_file`, `user_options` (utab).
- `fs_samples`: statfs per mount per sample (frsize, blocks, bfree, bavail, files, ffree), written
  when changed, in a goroutine that skips rounds while one is still running (hung NFS).
- Per-sample values (`proc_samples`, `sock_samples`) are written only when they change.
- System-wide counters: every `--sys-interval` (10 s default; also at every sample) writes one `sys_samples` row, one `cpu_samples` row per CPU
  (cpu -1 = total) and one `disk_samples` row per device that has done I/O (`part` = 1: a partition,
  from /sys/block). Values are the kernel's raw cumulative counters, so a report is a difference:
  `--at` = since boot (`uptime_ms`; what the real tool prints without an interval, and what
  `clifr verify` compares, with a tolerance), a range = one report per sample interval. No rates
  are stored; resolution = `--sys-interval`. `uptime` has no user count.
- `proc_samples` I/O columns (schema 2): rchar, wchar, read_bytes, write_bytes,
  cancelled_write_bytes from /proc/<pid>/io, re-read only when the process used CPU since its
  last sample and on fd-walk samples (cumulative: a skipped read only delays the update).
- `meta` (per run, latest wins in DuckDB): `schema_version` (`store.SchemaVersion`, 2 since
  2026-10-19; no key = 1; clifr refuses newer ones), `clifrd_version`, `hostname`,
  `machine_id`, `boot_id`, `timezone` (IANA name), `tz_offset_s`, plus boot time, intervals and
  modes. `processes.argv0_len`: length of argv[0] in `cmdline` (0/NULL unknown; netstat names).
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
  (`bench/report -validate`).
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
   busy load, all 15 scaling points within budget, no measurable pgbench impact.
8. [x] System-wide counters: /proc/stat, loadavg, meminfo, vmstat, diskstats per sample
   (raw cumulative counters; system, per-CPU and per-disk tables); `clifr uptime|vmstat|
   mpstat|iostat`; `clifr verify` compares them. No user count for `uptime`. About 0.2 ms of
   reads per sample (in the 1133 numbers, not in the 1050 ones).
9. [x] README (v2: build, recording, querying, tests, benchmark, results of M6–M8, limitations)
