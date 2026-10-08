# sosv — a Linux flight recorder (proof of concept)

`sosv record` continuously records which processes existed, which network
connections and open files each one held, and when short-lived processes
started and exited, into one SQLite file. Query commands then reconstruct
`ps aux`, `lsof -n -P`, `ss -tanp` and process lifetimes for any past moment
or time range.

Tools like sar, atop and PCP record metrics and process statistics, but not
the *links* between a process and its sockets and files over time. This PoC
exists to answer two questions with evidence:

1. **Accuracy**: is the reconstructed output for a past moment close to what
   the real commands showed at that moment?
2. **Cost**: how much CPU, memory and disk does recording take on a busy
   server, and does it measurably slow down the server's real workload?

The benchmark under `bench/` is the main deliverable. Results: see
[Results](#results).

## Build

Go 1.22 or newer; the result is one static binary.

    CGO_ENABLED=0 go build -o sosv ./cmd/sosv

Linux only, kernel 4.18+ (RHEL 8/9, Ubuntu 22.04/24.04). Dependencies: the
standard library, `modernc.org/sqlite` (pure Go) and `golang.org/x/sys`.

## Recording

    sudo ./sosv record --db /var/lib/sosv/sosv.db

| Flag | Default | Meaning |
|---|---|---|
| `--interval` | 30s | sample processes and sockets; find owners of new sockets |
| `--fd-interval` | 120s | full walk of every process's open files |
| `--cpu-budget` | 2% | of one core, averaged over `--budget-window` (5m); above it the fd interval is doubled (up to 1h) and the change is recorded |
| `--duration` | 0 (until signalled) | stop after this long |
| `--proc-root` | /proc | read a fixture tree instead (tests) |
| `--verify-every` | off | also save the real `ps aux`, `ss -tanp`, `lsof -n -P` output (for `sosv verify`) |

What is recorded:

- **Processes**: identity (pid, start time); ppid, uid, comm, cmdline, tty;
  per-sample state, CPU time, RSS, VSZ and threads (written only when they change).
- **Sockets**: TCP and UDP, IPv4 and IPv6, via NETLINK_SOCK_DIAG (what `ss`
  uses; falls back to /proc/net/*), with per-sample state and queues, and the
  owning process and fd.
- **Open files**: every fd of every process at each fd walk (target, type,
  mode, "(deleted)"), plus cwd, root and executable.
- **Process events**: fork/exec/exit from the kernel proc connector, so
  processes shorter than the interval are still seen with exact start and
  end times. Without CAP_NET_ADMIN the recorder warns and samples only.

Entities are stored as time ranges (first seen, last seen), not snapshots;
one SQLite transaction per sample, WAL mode. `/proc/*/environ` is never read.

Guard rails: a sample that overruns the interval makes the next one skip
(recorded); a process vanishing mid-read is handled; SIGINT/SIGTERM close
every open row cleanly; after a crash, open rows are closed at the last
sample on the next start.

### As a service

`deploy/sosv.service` runs the recorder with CPUQuota=5%, MemoryMax=256M,
Nice=10, IOSchedulingClass=idle, ProtectSystem=strict and only
CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH and CAP_NET_ADMIN:

    sudo install -m 0755 sosv /usr/local/sbin/sosv
    sudo install -m 0644 deploy/sosv.service /etc/systemd/system/
    sudo systemctl daemon-reload && sudo systemctl enable --now sosv

The database grows without bound in this PoC; watch `sosv stats`.

## Querying

All query commands take `--at "YYYY-MM-DD HH:MM:SS"` (local time) or
`--start_from A --end_at B`, plus `--db` and `--json`. Informational
headers go to stderr.

    sosv ps aux --at "2026-10-08 13:28:34"
    sosv ps aux --start_from "2026-10-08 13:00:00" --end_at "2026-10-08 14:00:00"
    sosv lsof -p 4242 --at "2026-10-08 13:28:34"
    sosv lsof -i --at "2026-10-08 13:28:34"
    sosv ss -tanp dport = :5432 and dst 10.0.0.0/24 --at "2026-10-08 13:28:34"
    sosv ss -tanp --start_from "2026-10-08 13:00:00" --end_at "2026-10-08 14:00:00"
    sosv life --name 'backup|rsync' --start_from "2026-10-08 00:00:00" --end_at "2026-10-08 06:00:00"
    sosv stats
    sosv verify            # needs a recording made with --verify-every

- `ps aux --at` prints the columns of `ps aux`; with a range, one row per
  command with first/last seen, runs, peak %CPU and RSS (`ev` marks
  processes only known from events).
- `ss -tanp` filters: `dst IP[/len][:port]`, `src ...`, `dport = :N`,
  `sport = :N`, joined with `and`. A range groups sockets by process: first
  and last seen, connections, peak concurrent, states.
- `life` lists start, end, duration, pid, ppid, command and source;
  durations are exact when both fork/exec and exit events were seen.
- `stats` shows the recording range, samples and skips, rows per table, DB
  size, recorder CPU and RSS, sample duration percentiles by phase,
  guard-rail adjustments and estimated disk per day.

## Tests

    go test ./...                                         # unit tests, fixtures via --proc-root
    sudo go test -tags e2e -v -count=1 ./test/e2e         # end to end, about 2 minutes

The end-to-end test starts the `light` load profile and `sosv record
--interval 2s`, then stages an incident: a client holding 150 connections
to a local server, a process holding a deleted file, and a burst of 20
processes of 0.3 s. It checks that `sosv ss`, `sosv lsof` and `sosv life`
find all three (150/150 connections on each side, the deleted file, and
20/20 processes with durations of about 300 ms).

## Benchmark

Everything runs unattended as root and writes CSV files plus machine
information under `bench/results/<name>/`. Each script checks for at least
1.5 GB of free disk before and during its runs (`--min-free-gb`).

1. **Setup** (once): installs PostgreSQL (with pgbench) and atop, disables
   atop's own logging services, creates the `sosvbench` database (pgbench
   scale 20) and builds the tools into `bench/bin/`.

       sudo bench/setup.sh

2. **Smoke test** (about 3 minutes): one configuration, one repeat, to
   prove the harness works.

       sudo bench/run.sh --smoke

3. **Cost and impact matrix**: for each load profile, configurations
   A (workload only), B (sosv 30s/120s, default), C (10s/60s), D (60s/300s)
   and R1 (atop at 30 s), each repeated 3 times in interleaved order, with
   2 minutes of warm-up (discarded) and 15 minutes measured. About 4.5 hours
   per profile.

       sudo bench/run.sh --profiles busy
       sudo bench/run.sh --profiles light,extreme --repeats 3

4. **Scaling** (about 2 hours): no workload; processes, open fds, TCP
   connections, process churn and connection churn varied one at a time.

       sudo bench/scaling.sh

5. **Accuracy** (20 minutes): record under load with a checkpoint every
   2 minutes, then `sosv verify`.

       sudo bench/accuracy.sh --profile busy

6. **Report**: one self-contained HTML page (inline SVG charts, no external
   resources) and a Markdown summary.

       go run ./bench/report -out bench/results/report bench/results/<matrix> bench/results/<scaling> bench/results/<accuracy>

7. **Real server** (optional): `bench/passive.sh start|status|stop` records
   for 24 h on a real server with no generated load, under the shipped
   unit's limits and sandbox, as a transient service that survives logout.
   The sampler stops the recorder if free disk runs low. Stop at any time
   with `sudo bench/passive.sh stop`. See the script's header for details.

### Machines with fewer CPUs (e.g. 4 vCPU)

The default pgbench target of 30,000 transactions per second was chosen
for an 8 vCPU machine: about a third of what it reached with the `busy`
load running (about 91,000). On a smaller machine that target can be
close to saturation, and a saturated workload hides the recorder's
effect. Calibrate the rate once, after `bench/setup.sh`:

1. Measure read-only throughput with the busy load running (about a minute):

       sudo bench/bin/load --profile busy --duration 90s >/tmp/load.out 2>&1 &
       until grep -q READY /tmp/load.out; do sleep 1; done
       sudo -u postgres psql -Atc "SELECT sum(pg_prewarm(c.oid::regclass,'read')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','i')" sosvbench
       sudo -u postgres pgbench -n -S -c 16 -j 4 -T 30 sosvbench | grep '^tps'
       wait

2. Use about a third of the reported TPS, rounded, as `--rate` for every
   matrix run, and give pgbench fewer threads on 4 CPUs:

       sudo bench/run.sh --profiles busy --rate 12000 --threads 2

   The rate is saved in `machine.env` and shown in the report.

Nothing else needs changing: the load profiles fit (the busy load itself
used about a third of one core), the recorder's 2% budget is per core, and
the report computes "% of the whole machine" from the CPU count in
`machine.env`. Expect results that are not comparable with an 8 vCPU run,
and a larger relative impact, since the recorder takes a bigger share of
the machine. The `extreme` profile and the largest scaling points
(10,000 processes, 100,000 connections, 500 new connections/s) are heavy on
4 CPUs: run `extreme` last and read it as where things stop fitting.

### How it measures

- **Load generator** (`bench/load`): long-lived processes holding open files,
  concurrent TCP connections between local clients and servers (over
  127.0.0.2–9) with connection churn, and short-lived processes per second.
  Profiles `light` (200 processes, 5,000 fds, 1,000 connections, 50 new
  connections/s, 5 spawns/s), `busy` (2,000 / 50,000 / 20,000 / 500 / 50) and
  `extreme` (5× busy); every knob can be overridden.
- **Workload**: pgbench. By default read-only (`-S`) at a fixed 30,000
  transactions per second (`--rate`; see above for smaller machines) with
  the database cached in memory; the
  recorder's impact then shows as added latency, mostly in the tail, and as
  a shortfall from the target rate. `--mode tpcb --rate 0` runs the
  read/write TPC-B-like script as fast as possible instead (see
  Limitations for why that is not the default).
- **Isolation**: the load generator, the recorder (or atop), pgbench and
  PostgreSQL each run in their own cgroup; a sampler records cpu.stat,
  memory.current, memory.peak, memory.stat, io.stat and pressure for each,
  plus /proc/stat, /proc/meminfo, /proc/pressure and /proc/diskstats,
  every 5 s. The recorder and atop run with nice 10 and the idle IO class
  like the shipped unit, but without its CPU and memory caps, so their true
  cost is measured.
- **Statistics**: means over repeats with 95% confidence intervals from the
  t-distribution; differences against the baseline with Welch's interval.
  The report says plainly when a difference is within noise.

## Results

The full benchmark runs are pending; this section will be filled in from
their report. Short test runs on the development VM (8 vCPU, 7.9 GB RAM,
VirtualBox, one repeat of 60 s, so no confidence intervals) indicate:

- **Accuracy** (light profile, 5 checkpoints): no genuine missing or extra
  rows; matched 100% of the rows that existed at the sample for `ps aux`,
  `ss -tanp` and `lsof -n -P` (99.6–99.8% with every compared field equal).
  Rows that started or ended between the sample and the real command are
  counted separately.
- **Cost at the busy profile is dominated by connection churn**: at 500 new
  connections per second each 30 s sample writes about 150,000 rows. The
  default configuration used about 8% of one core and wrote several GiB
  per hour to disk (SQLite WAL plus checkpoints for one transaction per
  sample), against atop's 0.4% and a few MiB per hour.
- **Workload impact**: pgbench held its 30,000 TPS target in every
  configuration; any effect shows in tail latency, which needs the repeated
  runs to separate from noise.

## Limitations

Stated plainly:

- **Sampling misses short-lived sockets and files.** A connection or file
  opened and closed between two samples is never seen; open files are only
  seen at fd walks (every 120 s by default). Processes are the exception
  (proc connector events).
- **Socket ownership can be inferred.** A socket first seen before any walk
  found its owner gets the owner from the first walk that does, backdated
  to when both the socket and the process existed.
- **Zombie processes** disappear from `sosv ps` once their exit event is
  seen, while `ps` still lists them until they are reaped.
- **lsof**: memory-mapped files (`mem`, `DEL`), DEVICE and SIZE/OFF and
  per-thread rows are not recorded; raw and packet sockets show as `sock`.
- **Network namespaces**: only the host namespace's sockets are recorded;
  container sockets are not visible.
- **Command lines** are re-read only at fd walks and on exec events;
  processes that rewrite their title (e.g. PostgreSQL backends) can show a
  title up to one fd interval old.
- **Lost events**: if the proc connector's buffer overflows, events are lost
  (counted as an `events_lost` guard event); those processes are only known
  from samples.
- **Disk use is an upper bound**: one SQLite transaction per sample, in WAL
  mode, writes far more than the database grows. There is no retention or
  compaction; the database grows without bound.
- **The CPU guard rail only lengthens the fd interval.** Process and socket
  sampling still run every interval, so with heavy connection churn the
  recorder can stay above its budget (it did at the busy profile).
- **CPUQuota throttling**: under the shipped unit's 5% quota a sample's
  burst of work is throttled and takes longer in wall time.
- **Verify**: rows that change between the sample and the moment the real
  command runs are reported separately as churn, not as errors; each
  checkpoint forces an fd walk.
- **Benchmark environment** (development VM): the virtual disk stalls for
  tens of seconds under sustained writes, even with the host I/O cache
  enabled (which also means fsync is not durable on the host), so the
  workload is read-only by default and **the impact on a disk-bound
  workload is not measured**. `bench/setup.sh` sets
  `synchronous_commit=off` and `max_wal_size=512MB` for the `--mode tpcb`
  option. The load generator's TIME-WAIT sockets are capped by
  `net.ipv4.tcp_max_tw_buckets`. PCP (configuration R2) was not installed
  and is not implemented.
