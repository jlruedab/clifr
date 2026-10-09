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
- `internal/cnproc/` — kernel proc connector (fork/exec/exit events).
- `internal/store/` — `Backend` interface, v1 SQLite schema and batch writer, `Tee`.
- `internal/pqstore/` — Parquet backend: flush windows, open-entity files, compaction, retention.
- `internal/duck/` — loads a Parquet data directory into in-memory DuckDB with the v1 table names.
- `internal/recorder/` — sampling loop, interval trackers, self-metrics, guard rails.
- `internal/query/` — reconstruction and formatting of ps/lsof/ss/life/stats.
- `internal/verify/` — compare saved real tool output with reconstructions.
- `deploy/` — systemd unit. `bench/` — load generator, benchmark runner, report. `test/e2e/` — end-to-end test.

## Data model notes
- Entities are time ranges: `first_seen`, `last_seen`. While an entity is still open,
  `last_seen` is NULL in the DB and lives only in memory ("seen at every sample since
  first_seen"); it is written when the entity closes, on clean shutdown, or recovered
  from the last sample timestamp on the next start after a crash.
- Parquet: append-only. A closed entity is written once; open ones are rewritten each
  flush to `<table>/open/<run>.parquet` with last_seen = last sample. Readers keep one
  row per id (closed row first). Ids = run start (Unix s) × 1e9 + counter.
- Per-sample values (`proc_samples`, `sock_samples`) are written only when they change.
- Times are Unix milliseconds (INTEGER). CLI times are local time `YYYY-MM-DD HH:MM:SS`.

## Commands
- Build: `CGO_ENABLED=0 go build -o sosv-record ./cmd/sosv-record` and `go build -o sosv ./cmd/sosv` (cgo, needs g++).
  go.mod pins toolchain go1.26.8 (downloaded automatically by an older `go`).
- Test: `go test ./...`; e2e: `sudo env PATH=$PATH HOME=$HOME go test -tags e2e -count=1 ./test/e2e`
- Quick manual run: `sudo ./sosv-record --data-dir /tmp/d --interval 2s --flush-interval 30s --duration 1m`,
  then `./sosv ps aux --data-dir /tmp/d --at "..."`
- Machine notes: the old dev VM (8 vCPU, little free disk, failing disk) is
  for v2 milestones 1–2 only; eBPF work and benchmarks run on the 4 vCPU
  Ubuntu 26.04 VM (uutils coreutils: do not rely on GNU-only `date` etc.).
  Bench scripts abort below 1.5 GB free and validate every run
  (`bench/report -validate`).

## Milestone status
v1 (tag `v1-snapshot`): milestones 1–9 done; its report generator and
benchmark were finished as v2 milestone 1 (results: busy 20261008-0721 batch).

v2:
1. [x] Tag v1; fix the report bugs; validation step (no v1 rerun: the 0721 data were repaired)
2. [ ] Storage interface, Parquet writer (rotation, compaction, retention), DuckDB CLI; parity via `sosv verify`
3. [ ] eBPF process events (proc connector fallback), OOM events
4. [ ] eBPF TCP events, keyframes, reconciliation; `ss` at/range
5. [ ] Long-held fd snapshots, mount events
6. [ ] Ground-truth tests
7. [ ] Benchmark: bpf_stats, new matrix, scaling, report
8. [ ] README
