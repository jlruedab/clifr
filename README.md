# clifr — a Linux flight recorder (working prototype)

*clifr was called sosv until 2026-10-19 (`sosv-record` → `clifrd`,
`sosv` → `clifr`, `/var/lib/sosv/data` → `/var/lib/clifr`). Recordings made
under the old name read unchanged; benchmark result directories keep their
old file names (`sosv-stats.json`, `sosv.db`).*

`clifrd` continuously records which processes existed, which TCP
connections and open files each one held, when short-lived processes started
and exited, and the system-wide counters, as Parquet files. The `clifr` CLI
then reconstructs `ps aux`, `ss -tanp`, `lsof -n -P`, `uptime`, `vmstat`,
`mpstat` and `iostat` for a past moment or time range, and lists process
lifetimes, OOM kills and mount changes.

Tools like sar, atop and PCP record metrics and process statistics, but not
the *links* between a process and its sockets and files over time. clifr
began as a proof of concept to answer two questions with evidence:

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

## Status

A working prototype: both questions above have answers backed by evidence,
and the recorder has what unattended use needs (systemd unit with limits,
CPU guard rail, retention and size caps, hourly compaction, crash recovery,
drop and missed-event counters, reconciliation with kernel dumps). It is
not yet shown to be viable for production:

1. **No long run.** The longest recordings are 15-minute benchmark runs
   and the 14-minute ground-truth test; days of memory use, retention,
   compaction and restarts have not been observed.
2. **One machine, one kernel** (Ubuntu 26.04, kernel 7.0, bare metal). The
   targets RHEL 8.2+/9 and Ubuntu 22.04+ and their fallback paths (perf
   buffer, classic tracepoints, proc connector) are untested there; the
   arm64 objects have never run.
3. **Synthetic load only**: pgbench and a load generator over loopback; no
   real server with many peers and containers.
4. **Known open issues**: see [Limitations](#limitations).
5. **Memory** (about 330–430 MiB at the busy load) may be too much for a
   fleet agent; that is a product decision.
6. **No packaging or delivery** (.deb/.rpm, the planned rename to clifr,
   the bundle and sos plugin of `docs/sos-vault-integration.md`).

To call it viable: a soak test of 3–7 days with a realistic mixed load
(memory, disk and data checked daily); `--test-ebpf`, the e2e test and the
small ground truth on RHEL 9, RHEL 8.x and Ubuntu 22.04 (VMs are enough);
and a short recording on a real server checked with `clifr verify`. About a
week, mostly unattended.

## Build

Two binaries, Go 1.25 or newer (go.mod pins toolchain go1.26.8, which an older
`go` downloads by itself):

    CGO_ENABLED=0 go build -o clifrd ./cmd/clifrd   # the recorder: static, pure Go
    go build -o clifr ./cmd/clifr                   # the CLI: DuckDB, needs cgo and g++

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

    sudo ./clifrd --data-dir /var/lib/clifr
    sudo ./clifrd --test-ebpf        # load the programs, trigger every event type, report

| Flag | Default | Meaning |
|---|---|---|
| `-C`, `--config` | /etc/clifr/clifrd.yml | settings file; a missing default file is not an error |
| `-D`, `--data-dir` | /var/lib/clifr | the Parquet data directory |
| `--interval` | 30s | sample processes and the system-wide counters |
| `--fd-interval` | 120s | walk the processes' open files |
| `--keyframe-interval` | 5m | full socket dump: queues, UDP, check of the event stream |
| `--flush-interval` | 5m | write buffered rows to Parquet (a crash loses at most this much) |
| `--flush-rows` | 400000 | also write once this many rows are buffered |
| `--retention` / `--max-size` | 72h / 2G | delete old data; the oldest hours go first above the size cap (`0` = none) |
| `--gc-heap-target` | 256M | heap size up to which garbage is collected at Go's default rate (GOGC 100); above it more often, down to GOGC 50; `0` = always 50; `GOGC` or `GOMEMLIMIT` in the environment turn the tuning off |
| `--cpu-budget` | 2% | of one core over `--budget-window` (5m); above it the fd interval doubles (up to 1h) if the fd walks are at least a quarter of the recorder's CPU, and either way a guard event is recorded |
| `--events` | auto | process events: eBPF, else the kernel proc connector, else none |
| `--tcp` | auto | TCP from eBPF events, else a socket dump every interval (v1) |
| `--fd-mode` | held | open files held across two walks and deleted files; `all` = every fd (v1) |
| `--db FILE` | off | also (or with `--data-dir ""` only) write the v1 SQLite schema |
| `--verify-every` | off | also save the real tools' output at checkpoints, for `clifr verify` |
| `--bpf-stats` | off | measure the eBPF programs' own run time (shown by `clifr info`) |
| `--log-level` | info | error, warn, info or debug |
| `-v`, `--version` | | print the version and exit |
| `--duration`, `--proc-root`, `--pprof-dir` | | stop after a time; fixture tree for tests; the recorder's own profiles |

Settings can also be given in the configuration file; `deploy/clifrd.yml`
lists them with their defaults (`data_dir`, `retention`, `max_size`,
`log_level`, `intervals: process, files, keyframe, flush`, `collectors:
process_events, tcp, files`, `cpu_budget`, `gc_heap_target`). A flag on the
command line overrides the file, and `CLIFR_DATA_DIR` its `data_dir`.
Unknown settings are rejected. `memory_limit` of the product spec is not
accepted: a Go memory limit makes the collector run continuously when the
live heap reaches it (11% of one core at 100,000 connections), so the soft
setting is `gc_heap_target` and the hard limit the unit's `MemoryMax`.

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
- **Mounts**: mount, unmount and remount events of the recorder's namespace,
  with mount and file-system options, device, root, position in mountinfo,
  loop backing file and libmount's userspace options.
- **File-system usage**: statfs of every mounted file system at each sample
  (in a goroutine of its own, so a hung network file system cannot stall the
  samples), written when it changed.
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

`deploy/clifrd.service` runs the recorder with Nice=10, the idle IO class,
CPUQuota=5%, MemoryMax=768M, a read-only filesystem except its state
directory and only the capabilities it needs (listed in the unit; kernels
before 5.8 need CAP_SYS_ADMIN for eBPF):

    sudo install -m 0755 clifrd clifr /usr/local/sbin/
    sudo install -D -m 0644 deploy/clifrd.yml /etc/clifr/clifrd.yml
    sudo install -m 0644 deploy/clifrd.service /etc/systemd/system/
    sudo systemctl daemon-reload && sudo systemctl enable --now clifrd

MemoryMax is about 1.5 times the highest memory measured in the benchmark
(502 MiB with 100,000 connections). Read [Limitations](#limitations) before
relying on the CPU limit on a busy server: at the busy benchmark load the
recorder averages about 2% of one core, but its 5-second peaks (p95 7.7%)
and the hourly compaction exceed CPUQuota=5%, and it has not been run
throttled at that load.

## Querying

`clifr` takes its own options and then the command to reconstruct, quoted,
in the real tool's syntax. `clifr help` lists the commands, `clifr help
COMMAND` the options each supports; any other option is rejected. The
resolved time and time zone and other informational lines go to stderr.

    clifr --at "02:45" "ps aux"
    clifr --at "02:45" "ps -ef"
    clifr --at "02:45" "ps -u postgres -o pid,rss,etime,args"
    clifr --since yesterday --until today "ps aux"
    clifr --at "2026-10-12 13:28:34" "ss -tanp dport = :5432 and dst 10.0.0.0/24"
    clifr --at "13:28" "ss -ltn"
    clifr --since "2026-10-12 13:00" --until "2026-10-12 14:00" "ss -tanp"
    clifr --at "13:28" "netstat -tulpn"
    clifr --at "13:28" "lsof -p 4242"
    clifr --at "13:28" "lsof -a -i -u postgres"
    clifr --at "13:28" "free -h"
    clifr --at "13:28" "df -h"
    clifr --at "13:28" "mount -t ext4,xfs"
    clifr --since "1 hour ago" events
    clifr --since "2026-10-12" --until "2026-10-12 06:00" "life --name 'backup|rsync'"
    clifr --since "2 hours ago" oom
    clifr --at "13:28" mounts
    clifr --since "13:00" --until "13:10" "vmstat 60"
    clifr --since "13:00" --until "13:10" --samples -e 1m "iostat -x"
    clifr --at "13:28" "mpstat -P ALL"
    clifr --at "13:28" uptime
    clifr info
    clifr verify                 # needs a recording made with --verify-every
    clifr export tcp_conns       # one table as CSV

Options: `-a/--at TIME`, or `-S/--since TIME` with `-U/--until TIME`
(default now); `-T/--tz ZONE`; `-D/--data-dir DIR` (default
`/var/lib/clifr`; hidden: `--db FILE` for a v1 SQLite file); `-j/--json`;
for ranges `--summary` (default), `--samples`, `-e/--every DUR`,
`-n/--number N`. TIME is `YYYY-MM-DD HH:MM[:SS]`, `YYYY-MM-DD`, `HH:MM`
(today), `today`, `yesterday`, `now`, or relative (`-30m`, `2 hours ago`).
`CLIFR_SINCE`, `CLIFR_UNTIL`, `CLIFR_TZ` and `CLIFR_DATA_DIR` set defaults.
A command can also be given unquoted after clifr's options
(`clifr --at 13:28 ps aux`).

- `ps aux`, or `-e`/`-p`/`-u`/`-C` with the default format, `-f` or
  `-o COLUMNS` (pid, ppid, uid, user, comm, args, cmd, rss, vsz, %cpu, %mem,
  c, ni, nlwp, s, stat, lstart, start, stime, etime, etimes, time, tty;
  `KEY:WIDTH`, `KEY=HEADING`), with procps's headings, widths and overflow.
  Over a range (aux or -e): one row per command with first and last seen,
  runs, peak %CPU and RSS.
- `ss` needs `-t` and/or `-u`; `-a` all, `-l` listening only, otherwise
  connected sockets only (as ss); `-p` owners, `-n` numeric ports (without
  it, names from `/etc/services` of the machine running clifr), `-4`/`-6`.
  Filters: `dst IP[/len][:port]`, `src ...`, `dport = :N`, `sport = :N`,
  joined with `and`. With events, connections, states and owners at a moment
  are exact (queues come from the last keyframe); a range lists TCP
  connections by process with duration, resets and retransmits.
- `netstat -n -t|-u [-a|-l] [-p] [-W] [-4|-6]`: the same data as `ss` in
  net-tools' layout (`-n` is required: past host names cannot be looked up).
  Program names come from the recorded argv[0], by net-tools' rule
  (recordings before schema 2 approximate it from the command line).
- `lsof [-p PIDS] [-u USERS] [-c NAME] [-i] [-a]`: selections ORed, or
  ANDed with `-a`, as lsof does (`-n`, `-P` accepted).
- `free [-b|-k|-m|-g|-h] [-w] [-t]` at a moment; over a range with
  `--samples` or `-s SECONDS` (`-c COUNT`), one report per sample.
- `events` (clifr only): a timeline of process starts and exits, OOM kills,
  mounts, recorder gaps, skipped samples and guard events (`--name REGEX`,
  `--type KINDS`); exits known only from samples are marked `~`.
- `mount [-t TYPES]`: the mount table as util-linux prints it (mount and
  file-system options, loop devices by their backing file, `/run/mount/utab`
  options), in mountinfo order; exact. Over a range: the changes.
- `df [-h] [-T] [-i] [PATH...]`: usage from the sample at or before T, as
  GNU df selects and prints it (dummy, empty, devtmpfs and squashfs file
  systems left out, a device mounted twice listed once, df's rounding and
  column widths). FUSE mounts without `allow_other` cannot be measured by
  root and are left out. Over a range with `--samples`.
- `life` (clifr only) lists start, end, duration, pid, ppid, command, exit
  code or signal; `oom` the OOM kills with the largest processes; `mounts`
  the mount table at a moment or its changes over a range.
- `uptime`, `vmstat`, `mpstat`, `iostat`: at a moment the averages since
  boot, which is what the real tool prints without an interval; over a
  range one report for the range, or one per interval with `--samples` or
  an interval argument (`"vmstat 60"`, `"iostat -x 60 10"`). `mpstat -P
  ALL` or `-P 0,3`; `iostat -x` (extended), `-d` (devices only), `-p`
  (partitions).
- `--json` writes JSON Lines, one object per row. Each starts with the times
  it describes, in Unix milliseconds: `ts_ms` (the moment, or the row's own
  time), `sample_ts_ms` (the sample its sampled values come from),
  `from_ms`/`to_ms` (the range, or a counter interval). Each ends with
  `sampled`, the names of its fields whose values come from a periodic
  sample (fd walk, keyframe, per-process or counter sample); the others are
  exact (events) or fixed for the object's life. `info` and `verify` write
  one object.

      {"ts_ms":1792380606000,"sample_ts_ms":1792380585319,"state":"ESTAB","recv_q":0,"send_q":0,
       "local":"192.168.1.12","lport":32800,"peer":"40.99.129.18","rport":443,"proto":"tcp",
       "inode":305975,"owners":[{"comm":"firefox","pid":12348,"fd":147}],"sampled":["recv_q","send_q"]}

- `info` shows the recording range, samples and skips, rows per table, data
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
   `clifr verify` of the system-wide tools also needs the sysstat package.

       sudo bench/setup.sh

2. **Cost and impact matrix**: configurations A (workload only), B (clifr
   30s/120s, the default), C (10s/60s), D (60s/300s), V1 (the v1 recorder)
   and R1 (atop at 30 s), each 3 times in interleaved order, 2 minutes of
   warm-up and 15 minutes measured. About 5 hours.

       sudo bench/run.sh --profiles busy --rate 80000 --cpus 0-11

   The pgbench rate must be calibrated per machine: about a third of the
   read-only throughput measured with the busy load running. `--cpus` pins
   PostgreSQL and pgbench (here to the performance cores of a hybrid CPU).
   `bench/run.sh --smoke` is a 3-minute check of the harness.
   `--configs N1` runs Prometheus Node Exporter instead, for comparison
   (package `prometheus-node-exporter`; scraped every 15 s from outside its
   cgroup).

3. **Scaling** (about 2 hours): no workload; processes, open fds, TCP
   connections, process spawns and connection churn varied one at a time,
   with the CPU guard rail off and the eBPF programs' run time measured.

       sudo bench/scaling.sh

4. **Report**: one self-contained HTML page and a Markdown summary.

       mkdir -p bench/results/report
       go run ./bench/report -out bench/results/report bench/results/<matrix> bench/results/<scaling>

5. **Accuracy against the real tools** (20 minutes): record under load with
   checkpoints, then `clifr verify`. `bench/accuracy.sh --profile busy`.
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

`free`, `ps -ef` and `netstat -tanp` (2026-10-19, a 150 s recording with 5
checkpoints on the test machine with a desktop session): `free` 10 of 10
rows within 2%, `ps -ef` 2,644 of 2,644 rows exact, `netstat -tanp` all 218
rows matched; 84 differed in PID/Program, all of Chrome processes, which
rewrite their whole command line, and 3 in State, as `ss` shows. Since
schema 2 the recording keeps where argv[0] ends: in a 70 s recording with 3
checkpoints `netstat -tanp` matched 154 of 154 rows, 99.35% exact (one
sampled Send-Q).

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
  device suffix (`addr%wlp...`), which clifr does not have for them.
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
IPV6_V6ONLY flag is recorded (dual-stack listeners), `clifr verify` checks
the held-fd table for files that changed in the gap, and the real `lsof` is
captured without per-thread rows (1.2 million lines and 12 s per checkpoint
before, which also took the recorder to 947 MiB).

### Cost at the busy load

Three runs of 15 minutes each (2026-10-17, `report-20261017-1133`, commit
`2c18c74`). The previous batch (2026-10-12, `report-20261012-1050`) is in
brackets.

| Metric | clifr, default (B) | v1 | atop 30 s |
|---|---:|---:|---:|
| CPU, % of one core | 2.14 ± 0.71 (5.19) | 11.3 ± 0.77 | 0.60 ± 0.05 |
| CPU, % of the machine | 0.10 (0.24) | 0.51 | 0.03 |
| Memory (anonymous), average | 429 MiB (327) | 152 MiB | 29 MiB |
| Memory (anonymous), max | 488 MiB (397) | 192 MiB | 35 MiB |
| Data kept per day | 3.99 GiB (4.00) | 18.03 GiB | 0.35 GiB |
| Written to disk per day | 12.6 GiB (12.3) | 298 GiB | 0.82 GiB |

The three B runs used 1.97%, 2.49% and 2.08% of one core; the second
included an hourly compaction. The aggressive configuration (10 s / 60 s)
used 2.62%, the conservative one (60 s / 300 s) 1.87%. The guard rail
recorded 2–3 `budget_exceeded` events per default run (2.02–2.15% over
5 minutes) and kept the fd interval at 2 minutes. Memory is higher than in
the previous batch because of the GC setting described under Limitations.

Impact on pgbench at 80,000 transactions per second, default configuration
against no recorder:

| Metric | No recorder | Difference | 95% interval |
|---|---:|---:|---|
| Transactions per second | 79,998 | −3 | −30 to +25, within noise |
| Latency average | 0.073 ms | +0.000 ms | −0.003 to +0.004, within noise |
| Latency p99 | 0.122 ms | +0.002 ms | −0.008 to +0.012, within noise |
| Latency p99.9 | 0.201 ms | +0.022 ms | −0.120 to +0.164, within noise |

No configuration (clifr at any interval, v1, atop) showed a measurable
latency change. In the previous batch the default configuration raised the
average by 0.002 ms and p99.9 by 0.121 ms, both measurable; the baseline's
p99.9 was also higher then (0.320 ms), so part of the difference may be the
machine.

### Scaling

One dimension varied at a time, no workload, guard rail off, 7 minutes per
point. The budget is 2% of one core.

2026-10-17 (`scaling-20261017-1133`); the recorder CPU of the previous
batch (`scaling-20261012-1050`) is in brackets.

| Point | Recorder CPU | eBPF programs | Memory max |
|---|---:|---:|---:|
| Baseline (2,000 processes, 50,000 fds, 20,000 connections, 50 spawns/s) | 0.48–0.51% (2.4–2.5%) | 0.04% | 221–257 MiB |
| 10,000 processes | 0.96% (3.63%) | 0.04% | 304 MiB |
| 200,000 open files | 0.78% (3.10%) | 0.04% | 395 MiB |
| 100,000 connections | 1.01% (2.95%) | 0.07% | 561 MiB |
| 10 spawns/s | 0.47% (1.32%) | 0.04% | 275 MiB |
| 200 spawns/s | 0.62% (4.55%) | 0.13% | 272 MiB |
| 100 new connections/s | 1.04% (3.23%) | 0.23% | 367 MiB |
| 500 new connections/s | 1.67% (4.48%) | 0.89% | 463 MiB |

All 15 points fit the 2% budget (1 of 15 in the previous batch).

The connection points were rerun on 2026-10-18 after the pointer-free rows
(see Limitations; `scaling-20261018-1157`, `report-20261018-1157`):

| Connections | Recorder CPU | Memory max |
|---:|---:|---:|
| 1,000 | 0.42% (0.42%) | 95 MiB (144) |
| 20,000 | 0.46% (0.49%) | 156 MiB (226) |
| 100,000 | 0.76% (1.01%) | 434 MiB (561) |

Brackets: the 2026-10-17 batch. Sample durations and disk use are
unchanged; the other points were not rerun. The eBPF programs run inside the
observed processes' own kernel paths, so their time is charged to those
processes and is not part of the recorder's CPU figure.

### Compared with Prometheus Node Exporter

At the busy load: clifr with the current code (pointer-free rows, default
heap target 256M; one run, `profile-busy-20261017-2037-compact3b-heap256`,
with the CPU profiler on) and from the matrix above (batch 1133, three
runs); Node Exporter 1.10.2 with the Debian package's default collectors,
scraped every 15 s (one run, `nodeexp-busy-20261016-1405`). Prometheus
itself was not run: its column is an estimate.

| | clifr now | clifr, batch 1133 | Node Exporter | Prometheus server (estimate) |
|---|---:|---:|---:|---:|
| CPU, % of one core | 1.84 | 2.14 | 1.36 | well under 1 |
| Memory (anonymous), average / max | 292 / 330 MiB | 429 / 488 MiB | 9.0 / 9.7 MiB | about 50–150 MiB |
| Data kept on the host | about 179 MB/h | about 178 MB/h | none | about 1–1.5 MB/h |
| Data kept at the default retention | about 13 GB (72 h) | the same | none | about 0.35–0.5 GB (15 days) |
| Written to disk | about 519 MB/h | about 565 MB/h | none | about 5–10 MB/h |
| Network | none | none | 274 KB per scrape (about 66 MB/h uncompressed) | receives the scrapes |

Node Exporter's CPU comes mostly from slow collectors on this laptop-class
machine (`systemd`, `hwmon`, `powersupplyclass`, `thermal_zone`: about
200 ms per scrape); on a server it would likely be well under 1%. Its data
is kept by a Prometheus server, usually on another machine: about 3,100
series, so about 18 million samples per day at 15 s, at the 1–2 bytes per
sample Prometheus documents; its disk writes (write-ahead log, head chunks,
compaction) are a few times that. Its memory is a few KB per series plus
the server's own base.

The two do different jobs. Node Exporter reports system counters at each
scrape and keeps nothing between scrapes. clifr records every process,
connection and open file so that `ps`, `ss` and `lsof` can be answered for
any past moment. At this load that is about 1,000 connection ends and
5,000 TCP state changes per second, 50 process starts per second, and in
memory 2,554 processes, 7,306 sockets, 57,000 open fds and about 30,000
connections in time-wait. For the part both do, the system counters, clifr
keeps about 0.3 MB per day and spends about 0.2 ms per sample.

Estimated floor for clifr at this load, if every reduction we know of were
made (not measured):

| | Now | Best case in Go | Best case in Rust | Node Exporter |
|---|---:|---:|---:|---:|
| Memory (anonymous) | 292 MiB | about 60–100 MiB | about 30–50 MiB | 9 MiB |
| Data kept | 179 MB/h | about 55–90 MB/h | the same | none (Prometheus: about 1–1.5 MB/h) |
| Written to disk | 519 MB/h | close to the data kept | the same | none (Prometheus: about 5–10 MB/h) |

The tracked state alone is some 20–30 MB in compact form, and each
connection needs some 15–25 bytes on disk even with a tight encoding
(about 48 now, transitions included). Only recording less closes the gap:
at this load all connections are loopback from the load generator, and
without them clifr is near its idle figures (about 22 MB/h and 171 MiB in batch 1133).
The fair comparison for clifr is atop with process accounting or a
continuous eBPF tracer, not a metrics exporter.

## Limitations

- **CPU is at the 2% budget at the busy load**: 2.14% of one core on
  average, with 2–3 `budget_exceeded` events per 15-minute run; an hourly
  compaction adds a burst of a few seconds. Every scaling point is within
  it. The guard rail lengthens the fd interval only when the fd walks are
  at least a quarter of the recorder's CPU (9–14% at the busy load), so it
  kept the interval at 2 minutes in every default run.
- **Memory is two to three times v1's**: 429 MiB on average at the busy
  load and up to 561 MiB with 100,000 connections in the 2026-10-17 batch.
  Rows held in memory have since been made pointer-free (fixed-size
  addresses, enums and interned names instead of strings and pointers), so
  the garbage collector does not scan them: in single runs 326 / 379 MiB
  average / max at the busy load and 434 MiB with 100,000 connections,
  with slightly less CPU. The full matrix has not been rerun with it. Rows are buffered until
  the 5-minute flush. The shipped unit allows 768 MiB; above that the
  recorder is killed and restarted, losing the rows since the last flush.
  Since 2026-10-14 the recorder trades some memory for CPU: garbage is
  collected at Go's default rate while the heap is small
  (`--gc-heap-target`). In single runs this cost about 85–90 MiB more
  anonymous memory and saved about 0.5% of one core at the busy
  load. With the pointer-free rows the default target was lowered from
  384M to 256M (2026-10-18): in single runs about 45 MiB less at the busy
  load and 86 MiB less with 100,000 connections (348 MiB max), for under
  0.1% of one core; below 256 MiB of heap it makes no difference. A fixed Go memory limit (`GOMEMLIMIT`) is not a safe alternative:
  at 384 MiB it took the recorder to 11% of one core with 100,000
  connections, mostly collecting.
- **The shipped unit's CPUQuota=5%** is above the average cost at the busy
  load (2.1% of one core) but below the bursts of compaction and of the
  busiest samples (p95 over 5 s: 8.6%). The recorder has not been run
  under the unit at that load: throttled, it may fall behind on events.
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
  prints a context-switch figure that is not per second; clifr prints the
  per-second rate. Interval output is not compared by `clifr verify`.
- **Dual-stack listeners in `ss`**: recordings made with a recorder older than
  2026-10-13 do not have the IPV6_V6ONLY flag, so a listener the real `ss` prints as `*:port`
  appears there as `[::]:port`. A listener's backlog (Send-Q) is 0 until
  the next keyframe, like the other queue values.
- **Namespaces**: only the host network namespace's sockets and the
  recorder's mount namespace are recorded.
- **Zombie processes** disappear from `clifr ps` at their exit event, while
  `ps` lists them until they are reaped.
- **Command lines** are read at exec and at fd walks; a process that
  rewrites its title can show an older one.
- **Benchmark scope**: one machine, a synthetic load, a read-only workload
  with the database in memory. The impact on a disk-bound workload is not
  measured. PCP is not compared.
- **No network, encryption or access control**: the data directory holds
  command lines and connection endpoints in plain Parquet files; the shipped
  unit creates it readable by root only (0700).
