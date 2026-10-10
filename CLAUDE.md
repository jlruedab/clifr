# sosv — Linux flight recorder (proof of concept)

`sosv-record` continuously records which processes existed, which sockets and open
files each one held, and short-lived process start/exit events, as Parquet files
(or, for v1 comparisons, one SQLite file).
Query subcommands (`ps`, `lsof`, `ss`, `life`, `stats`, `verify`) reconstruct the
output of the real tools for a past moment or time range.

The PoC exists to prove two things with evidence: **accuracy** (reconstruction vs. the
real tools) and **cost** (CPU / memory / disk of recording and its impact on a busy
workload). The benchmark results under `bench/` are the main deliverable, not CLI polish.

**Current state:** v2 refactor in progress (event-based recorder, Parquet,
DuckDB CLI). v1 (snapshot-based, SQLite) is tagged `v1-snapshot` and stays
benchmarkable side by side. `HANDOFF.md` has the v1 benchmark history.
Build one v2 milestone at a time, run it, report results, and wait for the
user's go-ahead.

## Hard constraints (v2)
- Two binaries. `sosv-record`: pure Go, static, `CGO_ENABLED=0`, runs on the
  recorded server. `sosv`: the CLI, DuckDB (`github.com/duckdb/duckdb-go`,
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
- `cmd/sosv-record/` — the recorder binary (static, no cgo).
- `cmd/sosv/` — the query CLI (DuckDB via cgo; `--data-dir` Parquet or `--db` SQLite).
- `internal/procfs/` — /proc parsers (stat, status, cmdline, fd, net/*, meminfo).
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
  `--tcp sample` keeps v1 sampling. Kernel sock pointers are reused quickly: never key
  anything that must survive a close by the pointer alone.
- eBPF losses that leave no trace in the drop counters: the kernel does not run a tracing
  program on a CPU where it is already running (interrupted or preempted), and no classic
  tracepoint/kprobe program while another one runs. TCP state changes therefore use two
  `tp_btf` programs (the second reports what the first misses); the recorder closes a
  connection whose close was missed when its sock pointer is reused (`tcp_close_missed`
  guard event); `recorder_stats` has `tcp_missed_runs` / `ebpf_missed_runs` (dropped).
  exec/exit/OOM and the reset/retransmit counters are still classic tracepoints.
- `tcp:tcp_send_reset` also fires for active resets since Linux 6.10 (no skb): not counted
  there, `EV_ACTIVE_RESET` reports them.
- Open files (`meta fds`): "held" (v2, `fds_held`): an fd is stored at the second consecutive
  walk of its process that sees it (first_seen = the first), deleted files at once; inet
  socket fds only when they add a holder beyond tcp_conns' owner. A process is not re-read
  when its fd count (size of /proc/<pid>/fd, Linux 6.2+) is unchanged and it had no TCP
  activity, except every `--fd-full-every` walks. "all" = v1 `open_files` (with `--tcp sample`).
- Mounts: `mounts` table (present/mount/unmount/remount) from POLLPRI on mountinfo, opened
  with raw open(2): Go's own epoll would consume the kernel's change notification.
- Per-sample values (`proc_samples`, `sock_samples`) are written only when they change.
- Times are Unix milliseconds (INTEGER). CLI times are local time `YYYY-MM-DD HH:MM:SS`.

## Commands
- Build: `CGO_ENABLED=0 go build -o sosv-record ./cmd/sosv-record` and `go build -o sosv ./cmd/sosv` (cgo, needs g++).
  go.mod pins toolchain go1.26.8 (downloaded automatically by an older `go`).
- eBPF self-test (root): `sudo ./sosv-record --test-ebpf [--ebpf-force-perf --ebpf-classic-fork]`
- Test: `go test ./...` (eBPF tests skip without root; `go test -c` + sudo to run them); e2e: `sudo env PATH=$PATH HOME=$HOME go test -tags e2e -count=1 ./test/e2e`
- Ground truth (root; small ≈ 4 min, full ≈ 14 min with the recorder's defaults; results in `bench/results/truth-<scale>-<time>/`):
  `sudo env PATH=$PATH HOME=$HOME go test -tags truth -count=1 -timeout 40m -v ./test/truth -scale small|full`
- Quick manual run: `sudo ./sosv-record --data-dir /tmp/d --interval 2s --flush-interval 30s --duration 1m`,
  then `./sosv ps aux --data-dir /tmp/d --at "..."`
- Machine notes: v2 milestones 6–8 run on the current VM: 22 vCPU, 61 GB RAM,
  Ubuntu 26.04, kernel 7.0, Go 1.27, PostgreSQL 18 (uutils coreutils: do not
  rely on GNU-only `date` etc.). Set up with `sudo bench/setup.sh` on 2026-10-10;
  unit tests, both `--test-ebpf` modes and the e2e test pass there. Earlier
  numbers are not comparable with it: v1 and v2 milestones 1–5 ran on the old
  8 vCPU VM (kernel 6.8, failing disk), the busy 20261008-0721 batch on a
  4 vCPU Ubuntu 26.04 VM. The pgbench rate must be calibrated again here.
  Bench scripts abort below 1.5 GB free and validate every run
  (`bench/report -validate`).
- The committed eBPF objects are in sync with the `.bpf.c` sources and load on
  any supported kernel unchanged (CO-RE): no regeneration per machine or kernel,
  only after editing a `.bpf.c` file (`go generate`; needs the apt packages
  clang-18, llvm-18 and libbpf-dev, installed on the current VM since M6).

## Milestone status
v1 (tag `v1-snapshot`): milestones 1–9 done; its report generator and
benchmark were finished as v2 milestone 1 (results: busy 20261008-0721 batch).

v2:
1. [x] Tag v1; fix the report bugs; validation step (no v1 rerun: the 0721 data were repaired)
2. [x] Storage interface, Parquet writer (rotation, compaction, retention), DuckDB CLI; parity via `sosv verify`
3. [x] eBPF process events (proc connector fallback), OOM events
4. [x] eBPF TCP events, keyframes, reconciliation; `ss` at/range
5. [x] Long-held fd snapshots, mount events
6. [x] Ground-truth tests (`test/truth`; full scale 41/41 checks, results: truth-full-20261010-1531)
7. [ ] Benchmark: bpf_stats, new matrix, scaling, report
8. [ ] README
