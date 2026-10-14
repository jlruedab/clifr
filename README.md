# sosv — a Linux flight recorder (proof of concept)

`sosv-record` continuously records which processes existed, which TCP
connections and open files each one held, when short-lived processes started
and exited, and the system-wide counters, as Parquet files. The `sosv` CLI
then reconstructs `ps aux`, `ss -tanp`, `lsof -n -P`, `uptime`, `vmstat`,
`mpstat` and `iostat` for a past moment or time range, and lists process
lifetimes, OOM kills and mount changes.

Tools like sar, atop and PCP record metrics and process statistics, but not
the *links* between a process and its sockets and files over time. This PoC
exists to answer two questions with evidence:

1. **Accuracy**: does the recording contain what really happened, and is the
   reconstructed output close to what the real commands showed?
2. **Cost**: how much CPU, memory and disk does recording take on a busy
   server, and does it measurably slow down the server's real workload?

The ground-truth test and the benchmark are the main deliverables; see
[Results](#results) and [Limitations](#limitations).

Version 1 (tag `v1-snapshot`) sampled everything every 30 s into one SQLite
file. Version 2, described here, takes process and TCP changes from eBPF
events and samples only what has no event. v1 stays buildable for
side-by-side benchmarks.

## Build

Two binaries, Go 1.25 or newer (go.mod pins toolchain go1.26.8, which an older
`go` downloads by itself):

    CGO_ENABLED=0 go build -o sosv-record ./cmd/sosv-record   # the recorder: static, pure Go
    go build -o sosv ./cmd/sosv                               # the CLI: DuckDB, needs cgo and g++

The recorder runs on the recorded server. The CLI may run anywhere the data
directory is readable or copied to.

Kernel: Linux with BTF at `/sys/kernel/btf/vmlinux` (RHEL 8.2+/9, Ubuntu
22.04+). The eBPF objects are committed and load unchanged on any such kernel
(CO-RE); clang is needed only after editing a `.bpf.c` file
(`go generate ./internal/bpfproc ./internal/bpftcp`; apt packages clang-18,
llvm-18, libbpf-dev).

Dependencies: `cilium/ebpf`, `parquet-go/parquet-go`, `duckdb/duckdb-go` (CLI
only), `modernc.org/sqlite` (v1 backend), `golang.org/x/sys`.

## Recording

    sudo ./sosv-record --data-dir /var/lib/sosv/data
    sudo ./sosv-record --test-ebpf        # load the programs, trigger every event type, report

| Flag | Default | Meaning |
|---|---|---|
| `--interval` | 30s | sample processes and the system-wide counters |
| `--fd-interval` | 120s | walk the processes' open files |
| `--keyframe-interval` | 5m | full socket dump: queues, UDP, check of the event stream |
| `--flush-interval` | 5m | write buffered rows to Parquet (a crash loses at most this much) |
| `--flush-rows` | 400000 | also write once this many rows are buffered |
| `--retention` / `--max-size` | 72h / none | delete old data; the oldest hours go first above the size cap |
| `--gc-heap-target` | 384M | heap size up to which garbage is collected at Go's default rate (GOGC 100); above it more often, down to GOGC 50; `0` = always 50; `GOGC` or `GOMEMLIMIT` in the environment turn the tuning off |
| `--cpu-budget` | 2% | of one core over `--budget-window` (5m); above it the fd interval doubles (up to 1h) if the fd walks are at least a quarter of the recorder's CPU, and either way a guard event is recorded |
| `--events` | auto | process events: eBPF, else the kernel proc connector, else none |
| `--tcp` | auto | TCP from eBPF events, else a socket dump every interval (v1) |
| `--fd-mode` | held | open files held across two walks and deleted files; `all` = every fd (v1) |
| `--db FILE` | off | also (or with `--data-dir ""` only) write the v1 SQLite schema |
| `--verify-every` | off | also save the real tools' output at checkpoints, for `sosv verify` |
| `--bpf-stats` | off | measure the eBPF programs' own run time (shown by `sosv stats`) |
| `--duration`, `--proc-root`, `--pprof-dir` | | stop after a time; fixture tree for tests; the recorder's own profiles |

What is recorded:

- **Processes**: pid and start time, ppid, uid, comm, command line, tty,
  executable; state, CPU time, RSS, VSZ and threads per sample, written only
  when they change. fork, exec and exit come from eBPF, so a process shorter
  than the interval is recorded with exact start and end, exit code and
  signal. OOM kills are recorded with the victim's RSS.
- **TCP connections**: every state change from eBPF, with the owning process
  and fd, the direction, the application's close, time-wait start and end,
  retransmits and resets. A full socket dump every 5 minutes (keyframe) adds
  queues and UDP sockets and checks the event stream against the kernel.
- **Open files**: an fd is stored when two consecutive walks of its process
  see it; deleted files at once. A process whose fd count did not change is
  not read again, except on every fifth walk.
- **Mounts**: mount, unmount and remount events of the recorder's namespace.
- **System-wide counters**, every sample: `/proc/stat` (per CPU),
  `loadavg`, `meminfo`, the paging counters of `/proc/vmstat` and
  `/proc/diskstats`, as the kernel's raw cumulative values.
- **The recorder itself**: per sample its CPU, RSS, data size, phase
  durations and rows written; events and drops per source; guard-rail events.

Entities are stored as time ranges (first seen, last seen), not snapshots.
`/proc/*/environ` is never read. Nothing is sent over the network.

Guard rails: a sample that overruns the interval makes the next one skip
(recorded); a process vanishing mid-read is handled; SIGINT/SIGTERM close
every open row; after a crash, open rows end at the last sample before the
last flush.

### As a service

`deploy/sosv.service` runs the recorder with Nice=10, the idle IO class,
CPUQuota=5%, MemoryMax=768M, a read-only filesystem except its state
directory and only the capabilities it needs (listed in the unit; kernels
before 5.8 need CAP_SYS_ADMIN for eBPF):

    sudo install -m 0755 sosv-record sosv /usr/local/sbin/
    sudo install -m 0644 deploy/sosv.service /etc/systemd/system/
    sudo systemctl daemon-reload && sudo systemctl enable --now sosv

MemoryMax is about 1.5 times the highest memory measured in the benchmark
(502 MiB with 100,000 connections). Read [Limitations](#limitations) before
relying on the CPU limit on a busy server: the measured CPU at the busy
benchmark load (5.2% of one core) is at CPUQuota, so the recorder would be
throttled there.

## Querying

Every query command takes `--at "YYYY-MM-DD HH:MM:SS"` (local time) or
`--start_from A --end_at B`, `--data-dir DIR` (or `--db FILE` for a v1
SQLite file) and `--json`. Informational headers go to stderr.

    sosv ps aux --at "2026-10-12 13:28:34"
    sosv ps aux --start_from "2026-10-12 13:00:00" --end_at "2026-10-12 14:00:00"
    sosv ss -tanp dport = :5432 and dst 10.0.0.0/24 --at "2026-10-12 13:28:34"
    sosv ss -tanp --start_from "2026-10-12 13:00:00" --end_at "2026-10-12 14:00:00"
    sosv lsof -p 4242 --at "2026-10-12 13:28:34"
    sosv life --name 'backup|rsync' --start_from "2026-10-12 00:00:00" --end_at "2026-10-12 06:00:00"
    sosv oom --start_from "2026-10-12 00:00:00"
    sosv mounts --at "2026-10-12 13:28:34"
    sosv vmstat --start_from "2026-10-12 13:00:00" --end_at "2026-10-12 13:10:00" --step 1m
    sosv mpstat -P ALL --at "2026-10-12 13:28:34"
    sosv iostat -x --start_from "2026-10-12 13:00:00" --end_at "2026-10-12 13:10:00"
    sosv uptime --at "2026-10-12 13:28:34"
    sosv stats
    sosv verify                 # needs a recording made with --verify-every
    sosv export tcp_conns       # one table as CSV

- `ps aux --at` prints the columns of `ps aux`; a range prints one row per
  command with first and last seen, runs, peak %CPU and RSS.
- `ss -tanp` filters: `dst IP[/len][:port]`, `src ...`, `dport = :N`,
  `sport = :N`, joined with `and`. With events, connections, states and
  owners at a moment are exact, not taken from the nearest sample (queues
  come from the last keyframe); a range lists the connections with duration,
  resets and retransmits.
- `life` lists start, end, duration, pid, ppid, command, exit code or signal.
- `uptime`, `vmstat`, `mpstat`, `iostat`: `--at` prints the averages since
  boot, which is what the real tool prints without an interval; a range
  prints one report per sample interval, or per `--step`. `mpstat -P ALL` or
  `-P 0,3`; `iostat -x` (extended), `-d` (devices only), `-p` (partitions).
- `stats` shows the recording range, samples and skips, rows per table, data
  size, recorder CPU and RSS, sample durations by phase, events and drops per
  source, guard-rail changes and estimated disk per day.

## Tests

    go test ./...                                                  # unit tests, /proc fixtures
    sudo env PATH=$PATH HOME=$HOME go test -tags e2e -count=1 ./test/e2e      # about 2.5 minutes
    sudo env PATH=$PATH HOME=$HOME go test -tags truth -count=1 -timeout 40m -v ./test/truth -scale small|full

The **ground-truth test** (`test/truth`; small about 4 minutes, full about 14)
runs the recorder with its defaults while a helper does things whose exact
outcome the test knows: 10,000 TCP connections of 50–200 ms, 5,000 processes
of under 100 ms with known arguments and exit codes, 500 connections aborted
by the server and 500 refused, an OOM kill in a cgroup, a tmpfs mounted,
remounted and unmounted, and a deleted file held open for 10 minutes. It then
asks the CLI and counts found against expected per check. Results go to
`bench/results/truth-<scale>-<time>/truth.md`.

## Benchmark

Everything runs unattended as root and writes CSV files plus machine
information under `bench/results/<name>/`. The scripts stop below 1.5 GB of
free disk and validate every run. Keep the machine otherwise idle.

1. **Setup** (once): installs PostgreSQL with pgbench and atop, and builds
   the tools (including the v1 recorder from its tag) into `bench/bin/`.
   `sosv verify` of the system-wide tools also needs the sysstat package.

       sudo bench/setup.sh

2. **Cost and impact matrix**: configurations A (workload only), B (sosv
   30s/120s, the default), C (10s/60s), D (60s/300s), V1 (the v1 recorder)
   and R1 (atop at 30 s), each 3 times in interleaved order, 2 minutes of
   warm-up and 15 minutes measured. About 5 hours.

       sudo bench/run.sh --profiles busy --rate 80000 --cpus 0-11

   The pgbench rate must be calibrated per machine: about a third of the
   read-only throughput measured with the busy load running. `--cpus` pins
   PostgreSQL and pgbench (here to the performance cores of a hybrid CPU).
   `bench/run.sh --smoke` is a 3-minute check of the harness.

3. **Scaling** (about 2 hours): no workload; processes, open fds, TCP
   connections, process spawns and connection churn varied one at a time,
   with the CPU guard rail off and the eBPF programs' run time measured.

       sudo bench/scaling.sh

4. **Report**: one self-contained HTML page and a Markdown summary.

       mkdir -p bench/results/report
       go run ./bench/report -out bench/results/report bench/results/<matrix> bench/results/<scaling>

5. **Accuracy against the real tools** (20 minutes): record under load with
   checkpoints, then `sosv verify`. `bench/accuracy.sh --profile busy`.
6. **Real server** (optional): `bench/passive.sh start|status|stop` records
   for 24 h with no generated load, under the shipped unit's limits.

How it measures:

- **Load generator** (`bench/load`), profile `busy`: 2,000 long-lived
  processes holding 50,000 files, 20,000 concurrent TCP connections, 500 new
  connections and 50 new processes per second.
- **Workload**: pgbench, read-only at a fixed rate with the database in
  memory. The recorder's impact shows as added latency or as a shortfall
  from the target rate.
- **Isolation**: load, recorder (or atop), pgbench and PostgreSQL each run in
  their own cgroup; a sampler records their CPU, memory, IO and pressure
  every 5 s. The recorder runs with nice 10 and the idle IO class like the
  shipped unit, but without its CPU and memory caps, so the true cost is
  measured. The 2% guard rail is on in the matrix and off in the scaling runs.
- **Statistics**: means over repeats with 95% confidence intervals
  (t-distribution); differences against the baseline with Welch's interval.

## Results

Machine: Intel Core Ultra 7 155H (22 logical CPUs, bare metal), 61 GB RAM,
NVMe, Ubuntu 26.04, kernel 7.0, PostgreSQL 18. The numbers are from one
machine and one synthetic load; the full reports are generated under
`bench/results/` (not committed).

### Accuracy

Ground truth at full scale (2026-10-10, `truth-full-20261010-1602`): **0 of
41 checks differ.**

| Scenario | Result |
|---|---|
| 10,000 TCP connections of 50–200 ms | both ends found with owner, peer and direction; durations within 20 ms (p99 error 1 ms); no connection recorded that did not exist |
| 5,000 processes of under 100 ms | all found with pid, full command line and exit code; durations within 20 ms (p99 error 10 ms); none recorded twice |
| 500 server aborts, 500 refused connects | every reset attributed to the right end |
| OOM kill | recorded with time, command and RSS at the kill |
| Mount, remount, unmount | 5 of 5 changes in order, within 1 ms |
| Deleted file held 10 minutes | listed at three moments, gone after release; first seen 110 s after it was deleted (open files are sampled) |
| Event stream | 0 of 186,988 events dropped; keyframe checks found no connection missed or kept too long |

System-wide tools (2026-10-12, a 25 s recording with 4 checkpoints on the
idle machine): `uptime`, `vmstat`, `mpstat -P ALL` (92 rows) and `iostat -dx`
(232 rows) all matched the real tools' output within 1% or 0.02.

Against the real tools at the busy load (2026-10-13,
`accuracy-busy-20261013-2044`): 20 minutes, the real commands captured at 10
checkpoints and compared with the reconstruction for the same moment.

| Tool | Rows in the real output | Matched | Only on one side, started or ended while the real command ran (missing / extra) | Only on one side, not explained (missing / extra) |
|---|---|---|---|---|
| `ps aux` | 25,158 | 99.92% | 20 / 26 | 0 / 0 |
| `ss -tanp` | 697,048 | 99.54% | 3,180 / 2,352 | 2 / 2 |
| `lsof -n -P` | 1,099,499 | 100.00% | 0 / 525 | 1 / 52 |

- The real `ss` finished about 1.3 s after the sample and the real `lsof`
  about 2.3 s after it, with 500 connections opening and closing per second.
  A row counts as explained when the recording shows the process, socket or
  fd starting or ending in that gap.
- `ss`, not explained: TIME-WAIT sockets that the real `ss` prints with a
  device suffix (`addr%wlp...`), which sosv does not have for them.
- `lsof`, not explained (not investigated further): mostly pidfds of the
  load generator and timerfds of desktop processes.
- Fields of matched rows that did not change in the gap: `ps` 99.40% exact
  (RSS, state and CPU time move between the sample and the command), `ss`
  99.99%, `lsof` 99.94%.
- System-wide tools at the same checkpoints: `vmstat` 10 of 10, `mpstat`
  230 of 230 and `iostat` 570 of 570 rows within tolerance; `uptime` 9 of 10
  (one load average off by more than 0.05).
- The recorder dropped no event. With the captures it used 387 MiB on
  average (510 MiB at most), against 327 MiB without them.

An earlier run the same day (`accuracy-busy-20261013-1833`) had 21 / 21
unexplained `ss` rows and 17 / 65 `lsof` rows. It led to three fixes: the
IPV6_V6ONLY flag is recorded (dual-stack listeners), `sosv verify` checks
the held-fd table for files that changed in the gap, and the real `lsof` is
captured without per-thread rows (1.2 million lines and 12 s per checkpoint
before, which also took the recorder to 947 MiB).

### Cost at the busy load

Three runs of 15 minutes each (2026-10-12, `report-20261012-1050`, before the
system-wide counters were added; those add about 0.2 ms of reads per sample).

| Metric | sosv, default (B) | sosv v1 | atop 30 s |
|---|---:|---:|---:|
| CPU, % of one core | 5.19 ± 0.55 | 11.6 ± 0.83 | 0.67 ± 0.04 |
| CPU, % of the machine | 0.24 | 0.53 | 0.03 |
| Memory (anonymous), average | 327 MiB | 153 MiB | 27 MiB |
| Memory (anonymous), max | 397 MiB | 183 MiB | 36 MiB |
| Data kept per day | 4.00 GiB | 18.05 GiB | 0.40 GiB |
| Written to disk per day | 12.3 GiB | 299 GiB | 0.86 GiB |

Impact on pgbench at 80,000 transactions per second, default configuration
against no recorder:

| Metric | No recorder | Difference | 95% interval |
|---|---:|---:|---|
| Transactions per second | 80,002 | −3 | −32 to +25, within noise |
| Latency average | 0.074 ms | +0.002 ms | +0.001 to +0.004, measurable |
| Latency p99 | 0.129 ms | +0.006 ms | −0.001 to +0.014, within noise |
| Latency p99.9 | 0.320 ms | +0.121 ms | +0.021 to +0.222, measurable |

v1 and atop showed no measurable latency change in the same batch.

### Scaling

One dimension varied at a time, no workload, guard rail off, 7 minutes per
point. The budget is 2% of one core.

| Point | Recorder CPU | eBPF programs | Memory max |
|---|---:|---:|---:|
| Baseline (2,000 processes, 50,000 fds, 20,000 connections, 50 spawns/s) | 2.4–2.5% | 0.08% | 175 MiB |
| 10,000 processes | 3.63% | 0.09% | 210 MiB |
| 200,000 open files | 3.10% | 0.09% | 273 MiB |
| 100,000 connections | 2.95% | 0.11% | 502 MiB |
| 10 spawns/s | 1.32% | 0.04% | 246 MiB |
| 200 spawns/s | 4.55% | 0.30% | 202 MiB |
| 100 new connections/s | 3.23% | 0.27% | 241 MiB |
| 500 new connections/s | 4.48% | 0.94% | 356 MiB |

Only 1 of 15 points fits the 2% budget. The eBPF programs run inside the
observed processes' own kernel paths, so their time is charged to those
processes and is not part of the recorder's CPU figure.

## Limitations

- **CPU is above the 2% budget** at almost every measured load, including the
  quiet baseline. The remaining cost is mostly system calls in the sampling
  loop and a `/proc` read for each new process.
- **The guard rail degraded open-file data in the matrix above.** In every
  matrix run it stretched the fd interval from 2 to 16 minutes (default
  configuration), although fd walks are a small part of the cost. Since
  2026-10-14 it lengthens that interval only when the fd walks are at least
  a quarter of the recorder's CPU; otherwise it records one
  `budget_exceeded` event and keeps the interval. In one busy-load run with
  that change the interval stayed at 2 minutes (fd walks: 7% of 5.13% of
  one core). The matrix has not been rerun with it.
- **Memory is about twice v1's**: 327 MiB on average at the busy load and up
  to 502 MiB with 100,000 connections. Rows are buffered until the 5-minute
  flush. The shipped unit allows 768 MiB; above that the recorder is killed
  and restarted, losing the rows since the last flush. (Matrix numbers.)
  Since 2026-10-14 the recorder trades some memory for CPU: garbage is
  collected at Go's default rate while the heap is small
  (`--gc-heap-target`). In single runs this cost about 85–90 MiB more
  anonymous memory (busy load 388 MiB average, 494 MiB max; 100,000
  connections 517 / 568 MiB) and saved about 0.5% of one core at the busy
  load. A fixed Go memory limit (`GOMEMLIMIT`) is not a safe alternative:
  at 384 MiB it took the recorder to 11% of one core with 100,000
  connections, mostly collecting.
- **The shipped unit's CPUQuota=5% is at the measured cost** at the busy load
  (5.2% of one core without the cap). The recorder has not been run under
  the unit at that load: throttled, it may fall behind on events.
- **Tail latency**: a small but measurable rise of pgbench's average and
  p99.9 latency in the last batch; the cause is not investigated.
- **Open files are sampled.** A file opened and closed between two walks is
  never seen, and one is stored only at its second walk. Memory-mapped files,
  DEVICE and SIZE/OFF and per-thread rows are not recorded.
- **eBPF losses without a drop count**: the kernel does not run a tracing
  program on a CPU where one is already running. Paired programs and the
  keyframe check cover TCP state changes, exec and exit; a few missed runs
  were counted (up to 5 per run), none of which lost a connection in the
  checks.
- **System-wide tools**: resolution is the sample interval, so `mpstat 1`
  cannot be reproduced. `uptime` has no user count. `vmstat`'s `r` and `b`
  are the values at the sample. On its since-boot line procps-ng 4.0.4
  prints a context-switch figure that is not per second; sosv prints the
  per-second rate. Interval output is not compared by `sosv verify`.
- **Dual-stack listeners in `ss`**: recordings made with a recorder older than
  2026-10-13 do not have the IPV6_V6ONLY flag, so a listener the real `ss` prints as `*:port`
  appears there as `[::]:port`. A listener's backlog (Send-Q) is 0 until
  the next keyframe, like the other queue values.
- **Namespaces**: only the host network namespace's sockets and the
  recorder's mount namespace are recorded.
- **Zombie processes** disappear from `sosv ps` at their exit event, while
  `ps` lists them until they are reaped.
- **Command lines** are read at exec and at fd walks; a process that
  rewrites its title can show an older one.
- **Benchmark scope**: one machine, a synthetic load, a read-only workload
  with the database in memory. The impact on a disk-bound workload is not
  measured. PCP is not compared.
- **No network, encryption or access control**: the data directory holds
  command lines and connection endpoints in plain Parquet files; the shipped
  unit creates it readable by root only (0700).
