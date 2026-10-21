# clifr — a Linux flight recorder (working prototype)

*clifr was called sosv until 2026-10-19 (`sosv-record` → `clifrd`,
`sosv` → `clifr`, `/var/lib/sosv/data` → `/var/lib/clifr`). Recordings made
under the old name read unchanged; benchmark result directories keep their
old file names (`sosv-stats.json`, `sosv.db`).*

`clifrd` continuously records which processes existed, which TCP
connections and open files each one held, when short-lived processes started
and exited, and the system-wide counters, as Parquet files. The `clifr` CLI
then reconstructs `ps aux`, `top -b`, `ss -tanp`, `lsof -n -P`, `uptime`,
`vmstat`, `mpstat` and `iostat` (and more: `clifr help`) for a past moment or
time range, and lists process
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
events and samples only what has no event. v1 ran side by side in the
benchmarks until 2026-10-21, when it and the SQLite backend were removed;
its figures below come from the last batch that included it.

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
5. **Memory** (about 285 MiB on average at the busy load) may be too much for a
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

Packages (x86_64): `packaging/build.sh` (needs docker; `DOCKER="sudo docker"`
if only root may use it) writes `clifr` and `clifrd` as .deb and .rpm into
`dist/`. clifr is built in a Rocky Linux 8 container with gcc-toolset-13, so
it needs only glibc 2.28 (built here it would need this machine's 2.43);
clifrd is static. The packages carry the man pages (generated from the
help texts), bash completion, the unit, the sysusers file, `/etc/clifr/clifrd.yml`
and the sos plugin. `packaging/test.sh [BUNDLE]` installs them with sos in
Ubuntu 22.04 and 24.04 and Rocky Linux 8 and 9 containers and checks them
(versions, files, the clifr group, the sos plugin, `clifrd doctor` on this
kernel, a query of BUNDLE, removal); the service itself is not run there.
The .deb enables and starts clifrd on install (Debian's convention), the
.rpm does not (presets: `systemctl enable --now clifrd`); purging the .deb
deletes the recording. License field: to be decided.

Tested kernels (packages in KVM guests, 2026-10-20, `packaging/vm.sh`):
Rocky Linux 8.10 (4.18, SELinux enforcing), AlmaLinux 9.8 (5.14, enforcing),
Ubuntu 22.04.5 (5.15), and this machine's 7.0: `--test-ebpf` 21/21 in all
three attach modes, e2e and the small ground truth pass (43/43), the service records
with no SELinux denials (clifrd runs unconfined: no policy module is needed).

Kernel: Linux with BTF at `/sys/kernel/btf/vmlinux` (RHEL 8.2+/9, Ubuntu
22.04+). The eBPF objects are committed and load unchanged on any such kernel
(CO-RE); clang is needed only after editing a `.bpf.c` file
(`go generate ./internal/bpfproc ./internal/bpftcp`; apt packages clang-18,
llvm-18, libbpf-dev).

Dependencies: `cilium/ebpf`, `parquet-go/parquet-go`, `duckdb/duckdb-go` (CLI
only), `godbus/dbus/v5` (pure Go: systemd's units), `golang.org/x/sys`.

## Recording

    sudo ./clifrd --data-dir /var/lib/clifr
    sudo ./clifrd --test-ebpf        # load the programs, trigger every event type, report

| Flag | Default | Meaning |
|---|---|---|
| `-C`, `--config` | /etc/clifr/clifrd.yml | settings file; a missing default file is not an error |
| `-D`, `--data-dir` | /var/lib/clifr | the Parquet data directory |
| `--interval` | 30s | sample processes (and, at least that often, the system-wide counters) |
| `--sys-interval` | 10s | system-wide counters (uptime, vmstat, mpstat, iostat, free), at most `--interval` |
| `--proc-io` | true | per-process I/O counters (`/proc/<pid>/io`), read when the process used CPU since its last sample and at every fd walk |
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
| `--verify-every` | off | also save the real tools' output at checkpoints, for `clifr verify` |
| `--bpf-stats` | off | measure the eBPF programs' own run time (shown by `clifr info`) |
| `--redact` | none | regular expression masked (as `***`) in command lines before they are stored; repeatable; with capture groups only the groups are masked |
| `--log-level` | info | error, warn, info or debug |
| `-v`, `--version` | | print the version and exit |
| `--duration`, `--proc-root`, `--pprof-dir` | | stop after a time; fixture tree for tests; the recorder's own profiles |

Settings can also be given in the configuration file; `deploy/clifrd.yml`
lists them with their defaults (`data_dir`, `retention`, `max_size`,
`log_level`, `intervals: process, system, files, keyframe, flush`,
`collectors: process_events, tcp, files, process_io`, `cpu_budget`,
`gc_heap_target`, `redact`: a list of patterns; the example masks password
and token options, URL credentials and `key=value` secrets). A flag on the
command line overrides the file, and `CLIFR_DATA_DIR` its `data_dir`.
Unknown settings are rejected. `memory_limit` of the product spec is not
accepted: a Go memory limit makes the collector run continuously when the
live heap reaches it (11% of one core at 100,000 connections), so the soft
setting is `gc_heap_target` and the hard limit the unit's `MemoryMax`.

What is recorded:

- **Processes**: pid and start time, ppid, uid, comm, command line, tty,
  executable; state, CPU time, RSS, VSZ, threads and I/O counters per
  sample, written only when they change. fork, exec and exit come from eBPF, so a process shorter
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
- **System-wide counters**, every `--sys-interval` (10 s): `/proc/stat` (per CPU),
  `loadavg`, `meminfo`, the paging counters of `/proc/vmstat` and
  `/proc/diskstats`, as the kernel's raw cumulative values.
- **The recorder itself**: per sample its CPU, RSS, data size, phase
  durations and rows written; events and drops per source; guard-rail events.

Entities are stored as time ranges (first seen, last seen), not snapshots.
`/proc/*/environ` is never read. Nothing is sent over the network. Command
lines are masked with the `redact` patterns before they are stored (from
/proc, exec events and inherited ones alike; also the real tools' output
saved for `verify`); mount options and file names are not.

Guard rails: a sample that overruns the interval makes the next one skip
(recorded); a process vanishing mid-read is handled; SIGINT/SIGTERM close
every open row; after a crash, open rows end at the last sample before the
last flush.

### As a service

`deploy/clifrd.service` runs the recorder with Nice=10, the idle IO class,
CPUQuota=5%, MemoryMax=768M, a read-only filesystem except its state
directory and only the capabilities it needs (listed in the unit; kernels
before 5.8 need CAP_SYS_ADMIN for eBPF):

    # or install the clifrd and clifr packages (see Build), then only the last two lines
    sudo install -m 0755 clifrd /usr/sbin/ && sudo install -m 0755 clifr /usr/bin/
    sudo install -D -m 0644 deploy/clifrd.yml /etc/clifr/clifrd.yml
    sudo install -D -m 0644 deploy/clifr-sysusers.conf /usr/lib/sysusers.d/clifr.conf && sudo systemd-sysusers
    sudo install -m 0644 deploy/clifrd.service /etc/systemd/system/
    sudo clifrd doctor            # what this system supports: the recording level
    sudo systemctl daemon-reload && sudo systemctl enable --now clifrd

The recording holds every user's command lines: the unit keeps it readable
by root and the `clifr` group only (directories 0750, files 0640); add an
administrator with `usermod -aG clifr NAME` to use `clifr` without root.
`clifrd doctor` loads the eBPF programs and closes them again, reads each
source once and prints what works and the resulting recording level (full,
reduced or sampling only); it records nothing.

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
    clifr --at "02:45" "ps auxfwww"
    clifr --at "02:45" "pstree -lp"
    clifr --at "02:45" "top -b -n 1"
    clifr --at "02:45" "date --utc"
    clifr --at "02:45" findmnt
    clifr --at "02:45" "ss -s"
    clifr --at "02:45" "uname -a"
    clifr --at now "last -F reboot"
    clifr --at "02:45" "nstat -zas"
    clifr --at "02:45" "netstat -s"
    clifr --at "02:45" "ip -s -d link"
    clifr --at "02:45" "ip -o addr"
    clifr --at "02:45" "ip route show table all"
    clifr --at "02:45" "ip -6 rule list"
    clifr --at "02:45" "dmesg -T"
    clifr --at "02:45" "systemctl list-units --failed"
    clifr --since "02:00" --until "02:05" nstat
    clifr --at "02:45" "df -aliT -x autofs"
    clifr --since "02:00" --until "02:10" --samples "top -b -c -o %MEM"
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
    clifr diff --at "14:00" --at "14:20" "ss -ltnp"
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
`/var/lib/clifr`); `--style STYLE`; `-j/--json`;
for ranges `--summary` (default), `--changes`, `--samples`,
`-e/--every DUR`, `-n/--number N`. TIME is `YYYY-MM-DD HH:MM[:SS]`, `YYYY-MM-DD`, `HH:MM`
(today), `today`, `yesterday`, `now`, or relative (`-30m`, `2 hours ago`).
`CLIFR_SINCE`, `CLIFR_UNTIL`, `CLIFR_TZ` and `CLIFR_DATA_DIR` set defaults.
A command can also be given unquoted after clifr's options
(`clifr --at 13:28 ps aux`).

Tool versions differ between distributions, and some print the same data
differently. clifr prints as the recorded host's own tools do, so its output
agrees with them and with that host's sosreports: clifrd records the
distribution (`/etc/os-release`) and clifr picks the style of its tools.
Checked with `clifr verify` in VMs: RHEL 8 (`free`/`top` "used" as total -
free - buff/cache, `df` lists devtmpfs and squashfs, `lsof` without unix
socket state, `vmstat`'s since-boot rates per CPU-second, `iostat` in
sysstat 11's layout), RHEL 9 (`df` and `vmstat` as RHEL 8, the rest current)
and Ubuntu 22.04 (`free`/`top`, `lsof` and `vmstat` as RHEL 8). Other
distributions, and recordings made before 2026-10-21, get the current tools'
style. `--style rhel-8|rhel-9|ubuntu-22.04|current` (or `CLIFR_STYLE`)
chooses one; a line on stderr says when a style other than current is used.

- `ps aux`, or `-e`/`-p`/`-u`/`-C` with the default format, `-f` or
  `-o COLUMNS` (pid, ppid, uid, user, comm, args, cmd, rss, vsz, %cpu, %mem,
  c, ni, nlwp, s, stat, lstart, start, stime, etime, etimes, time, tty;
  `KEY:WIDTH`, `KEY=HEADING`), with procps's headings, widths and overflow.
  Over a range (aux or -e): one row per command with first and last seen,
  runs, peak %CPU and RSS. `ps auxf` draws the process tree in COMMAND as
  procps does (init's children at the top level, kthreadd's tree first).
- `pstree -p [-l] [-T] [-n] [-A|-U] [PID]`: psmisc's layout; threads are not
  recorded, so the tree is the one `-T` prints (`-p` is required: without it
  pstree merges identical subtrees). Over a range: one tree per sample with
  `--samples`.
- `date [-u|--utc] [-R]`: the moment asked for, in GNU date's C-locale
  format. `hostname [-s]`: the name when the clifrd run covering the moment
  started (later changes and `-f` are not recorded). `uname [-asnrvmpio]`:
  the kernel the run covering the moment recorded (since schema 3; `-p` and
  `-i` print the machine, as RHEL's and Debian's coreutils do). `last [-F]
  reboot`: the boots within the recording, newest "still running"; an
  earlier boot ends at its last recorded sample, where wtmp has the shutdown
  time or "crash"; boot times are the kernel's (wtmp's record is written a
  few seconds later, when systemd starts); logins are not recorded.
- `findmnt [-l]`: util-linux's tree (C locale: ASCII), TARGET SOURCE
  FSTYPE OPTIONS. The parent mount is not recorded: the tree uses the mount
  on the longest prefix of each path, which differs from findmnt only for a
  mount made under a path that was later mounted over.
- `top -b [-n 1] [-c] [-i] [-w COLUMNS] [-o FIELD] [-p PIDS] [-u USER]`:
  procps-ng 4's batch output. The summary comes from the system sample at or
  before T, the processes from the process sample at or before it, with
  %CPU over the interval since the sample before (top's own first screen
  covers a fraction of a second). Not recorded: the number of users (left
  out of the first line). Recordings before 2026-10-22 have no SHR (`-`)
  and no priority (PR is 20 + NI, never `rt`). Over a range: one report per sample with `--samples`
  (`-n` and `-d` as top's).
- `ss -s`: the counts of /proc/net/sockstat and sockstat6 at the system
  sample at or before T (recorded since schema 3), estab (ESTABLISHED and
  CLOSE-WAIT) from /proc/net/snmp (since schema 4; before, counted from the
  TCP records at T).
- `nstat -a [-z]` at a moment: every protocol counter of /proc/net/snmp,
  netstat and snmp6 since boot, as recorded at the system sample at or
  before T (clifrd writes a counter when it changes, and all of them every
  5 minutes; since schema 4). Over a range, `nstat [-z]` shows each
  counter's increase from the start to the end and its rate per second.
- `netstat -s [-t] [-u] [-w] [-6]`: the same counters in net-tools 2.10's
  sentences, sections and quirks (counters its tables miss print as
  "Name: value", only when not 0). Checked with `clifr verify` here and in
  the RHEL 8, RHEL 9 and Ubuntu 22.04 VMs: every line, 100%.
- `ip [-s [-s]] [-d] link [show] [[dev] NAME]`: the network interfaces at the
  system sample at or before T, in iproute2's layout (flags, state, MTU,
  qdisc, addresses, RX/TX counters, `-s -s` error counters, `-d`'s generic
  attributes, altnames). clifrd reads them over rtnetlink at each system
  sample (schema 5). Not reconstructed: the parameters of each interface
  type (`-d` prints "bridge", "bond", "vlan", ... without them), XDP
  programs, VF information. Checked: every interface 100% here (iproute2
  6.19) and in the VMs (6.2, 6.17, 5.15; only lo and one NIC there).
- `ip [-o] [-d] [-4|-6] address [show] [[dev] NAME]`: the interfaces as above
  (without what only `ip link` shows) and their addresses at T, lifetimes
  counted down to T. clifrd follows address changes as the kernel announces
  them (rtnetlink notifications) and writes all addresses at its start,
  every hour and after lost notifications, so a change is placed at the
  moment it happened, not at the next sample. With `-6` the interface lines
  are the kernel's IPv6 view, as iproute2 prints them.
- `ip [-4|-6] [-d] route [show] [table ID|all]` and `ip [-4|-6] rule
  [list]`: the routes and policy rules at T, in the kernel's order, as
  iproute2 prints them (types, gateways, tables, protocols, scopes, metrics,
  flags, route metrics, multipath nexthops; expiring routes counted down).
  clifrd keeps each route's and rule's netlink message as the kernel sent
  it, records every change as it is announced, and dumps the tables again
  about a second after changes (at most every 10 s; not above 50,000 routes)
  so the order is right within seconds. Table names other than local, main
  and default print as numbers (a host's /etc/iproute2/rt_tables is not
  recorded); MPLS and other encapsulations are recorded but not printed.
- `dmesg [-T] [-t] [-x]`: the kernel log. `--at T`: the records of the boot
  running at T that were still in the kernel's buffer, as dmesg would have
  printed them; a range: the records written in it. clifrd reads
  `/dev/kmsg` as the kernel writes it (CAP_SYSLOG; the unit no longer sets
  `ProtectKernelLogs`) and applies the `--redact` patterns to it. `-T`
  computes times from the boot time as the host's util-linux does (2.32,
  2.37 and 2.41 each differently). The buffer's oldest record is noted at
  most 10 s after records arrive, so right after a burst the oldest lines
  may still be listed although the kernel had dropped them.
- `systemctl [list-units] [-a] [--failed] [--state=S] [-t TYPE] [--plain]
  [--no-legend] [PATTERN...]`: systemd's loaded units at T. clifrd lists
  them over systemd's private socket (as systemctl does as root; else the
  system bus) at the start, hourly, and a fraction of a second after
  systemd signals a change (at most every second), so a unit that failed
  and was restarted within that second may be missed. Printed as the
  recorded host's systemd prints them (239 on RHEL 8, 249/252 on Ubuntu
  22.04 and RHEL 9, 258 and later), with `*` and `->` instead of `●` and
  `→` when clifr's locale is not UTF-8, as systemctl decides it.
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
- `df [-h] [-T] [-i] [-a] [-l] [-x TYPE] [-t TYPE] [PATH...]`: usage from
  the sample at or before T, as GNU df selects and prints it (dummy, empty,
  devtmpfs and squashfs file systems left out, a device mounted twice listed
  once, df's rounding and column widths; `-a` all of them, the dummies with
  zeros; `-l` no network file systems). FUSE mounts without `allow_other` cannot be measured by
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
- Range views: `--summary` (default) is one report for the range (ps, ss,
  netstat, lsof: one row per object with first/last seen and peaks; the
  counters: one report). `--samples` prints the full output at every sample
  (spacing `-e`, at most `-n`). `--changes` (ps, ss, netstat, lsof, df,
  mount) prints, between consecutive samples, the rows that appeared,
  disappeared or changed (ps: command, user, parent or terminal; sockets:
  state or owners; df: Use% or the file system), as tables in the command's
  own format; anything shorter than a sample interval is in `events`.
- On a terminal, output goes through a pager (`-I`; `--plain` prints, as
  when piped): one page per sample or comparison; PgDn/n and PgUp/p move
  between samples, Home/End to the first and last, `g` jumps to a time
  (`HH:MM` without a date: the one nearest the sample shown, so on its day),
  arrows, space and `b` scroll, `q` quits. One page that fits on the
  screen is just printed.
- `clifr diff --at A --at B "COMMAND"` (ps, ss, netstat, lsof, df, mount)
  compares the two moments the same way: appeared, gone, changed.
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

- Query cost: clifr loads only the tables a query names, and the TCP tables
  and processes only around the time asked for. On a 6-hour recording of
  the busy load (978 MB, about 23 million connections; 2026-10-20,
  `longrec-20261020-0945`): `vmstat` 0.05 s and 93 MB, `ps aux` about
  0.1 s and 150 MB, `ss -tanp` 0.7–1.2 s and 0.5 GB, `lsof` 1.0–1.5 s and
  0.6 GB at any moment in it; `info` 0.4 s and 1.4 GB. A range costs in
  proportion to its length: 30 minutes of `ss -tan` (1.8 million
  connections) 5.2 s and 2.3 GB.
- `info` shows the recording range, samples and skips, rows per table, data
  size, recorder CPU and RSS, sample durations by phase, events and drops per
  source, guard-rail changes and estimated disk per day.

### Bundles and sos report

`clifrd bundle` writes the recording, or what a window of it needs, as one
tar file to read on another machine; `clifr --data-dir FILE.tar` reads it
(unpacked into a temporary directory for the query):

    sudo clifrd bundle --last 6h -o /tmp/clifr.tar
    sudo clifrd bundle --since "2026-10-20 12:00" --until "2026-10-20 13:00" -o /tmp/clifr.tar
    clifr --data-dir /tmp/clifr.tar --at "2026-10-20 12:31" "ss -tanp"

- Data files are copied unchanged (the window's hours, whole), plus a
  lead-in for the state at the window's start (keyframe, samples), the
  values written only when they change, and `bundle.json` (the host's
  machine-id, boot id, time zone, versions, window, SHA-256 per file).
  Entity rows written after the window (processes and connections that
  closed later) are filtered to the ones that began by its end.
- Pure Go, safe while clifrd records. On the busy 6-hour recording: one
  hour in the middle 342 MB in 10 s (the filtering), the whole recording
  1.0 GB in 1 s; every output compared (44 moments, ranges, changes, diff)
  is identical to the same query on the recording.
- clifr refuses bundles of a newer layout, and damaged files.
- `deploy/sos/clifr.py` is a plugin for `sos report` (install it beside
  sos's plugins, `sos/report/plugins/`). It adds the bundle as
  `sos_commands/clifr/clifr-bundle.tar`, plus `clifrd --version`,
  `clifrd doctor` and `/etc/clifr`:

      sos report -o clifr                       # the last 6 hours
      sos report -o clifr -k clifr.window=24h   # or all
      sos report -o clifr -k clifr.start="2026-10-20 12:00" -k clifr.end="2026-10-20 13:00"

  Tested with sos 4.11.2 (Ubuntu's package, run from its files). xz
  hardly shrinks the Parquet files: plan the upload size (about 175 MB
  per hour at the busy load).

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
   the tools into `bench/bin/`.
   `clifr verify` of the system-wide tools also needs the sysstat package.

       sudo bench/setup.sh

2. **Cost and impact matrix**: configurations A (workload only), B (clifr
   30s/120s, the default), C (10s/60s), D (60s/300s) and R1 (atop at 30 s),
   each 3 times in interleaved order, 2 minutes of warm-up and 15 minutes
   measured. About 4.5 hours.

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
   for 24 h with no generated load, with the `[Service]` settings of
   `deploy/clifrd.service` (limits, capabilities, sandbox; read from the unit
   at start, `CAP_SYS_ADMIN` added before Linux 5.8). `start` prints the event
   sources the recorder got (eBPF or the fallbacks).

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

`top -b -n 1 -w 512` (2026-10-21, a 2-minute recording with 4 checkpoints
on the test machine): 2,102 of 2,102 process rows matched, 83.7% exact in
USER, PR, NI, VIRT, RES, S, TIME+ and COMMAND. PR differed in 304 rows, all
real-time or other non-default scheduling (`rt`, -51, -2: not recorded);
RES and TIME+ in about 25 each (top ran about 350 ms after the sample);
the task counts and memory lines matched. In a second such recording
`pstree -lpT` placed 836 of 836 processes under the right parent in the
right order, and `ps auxfwww` drew the same tree prefix for 2,094 of 2,094.
In a third (4 checkpoints), `findmnt` matched 376 of 376 lines exactly and
`df -al -x autofs` 372 of 372 rows; `pstree -lpT` had the right parent and
name for 863 of 866 processes (the 3: a Firefox process that renamed itself
after the sample; names are recorded at start and exec).

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

Three runs of 15 minutes each (2026-10-21, `report-20261021-2027`, commit
`85092b5`: after step 2 of phase 8, which added protocol counters,
interfaces, addresses, routes, the kernel log and systemd units). The
2026-10-19 batch (`report-20261019-1620`, commit `abc43af`) is in brackets;
v1 was last measured in that batch and has since been removed.

| Metric | clifr, default (B) | v1 (batch 1620) | atop 30 s |
|---|---:|---:|---:|
| CPU, % of one core | 1.86 ± 0.32 (1.84) | 10.9 ± 0.41 | 0.52 ± 0.01 |
| CPU, % of the machine | 0.08 (0.08) | 0.49 | 0.02 |
| Memory (anonymous), average | 285 MiB (285) | 151 MiB | 25 MiB |
| Memory (anonymous), max | 323 MiB (332) | 182 MiB | 28 MiB |
| Data kept per day | 4.01 GiB (3.98) | 18.03 GiB | 0.32 GiB |
| Written to disk per day | 12.1 GiB (12.0) | 301 GiB | 0.75 GiB |

The three B runs used about 1.8%, 1.8% and 2.0% of one core. The aggressive
configuration (10 s / 60 s) used 2.53% (2.23), the conservative one
(60 s / 300 s) 1.61% (1.55). The guard rail recorded 2 `budget_exceeded`
events over the three default runs and kept the fd interval at 2 minutes.
What step 2 added cost nothing measurable.
Memory is about a third lower than in the 2026-10-17 batch: rows held in
memory are pointer-free and the heap target is 256M (see Limitations). What
phase 3 added (three times as many system-counter samples, `/proc/<pid>/io`
reads, statfs per mount) did not change the CPU measurably: a single run on
2026-10-17 without it also used 1.84%.

Impact on pgbench at 80,000 transactions per second, default configuration
against no recorder:

| Metric | No recorder | Difference | 95% interval |
|---|---:|---:|---|
| Transactions per second | 80,003 | −1 | −23 to +21, within noise |
| Latency average | 0.070 ms | +0.001 ms | +0.001 to +0.001, measurable |
| Latency p99 | 0.116 ms | +0.002 ms | +0.000 to +0.003, measurable |
| Latency p99.9 | 0.164 ms | +0.007 ms | −0.018 to +0.031, within noise |

All three clifr configurations added about 1 µs to the average latency
(+1.4%) and about 2 µs to p99 (1.4–2.0%); atop added nothing measurable.
The machine's CPU use rose by 0.4–0.5 points, about 9% of one core, more
than the recorder's own 1.9%: most likely the eBPF programs, whose time is
charged to the processes they observe (not measured separately in these
runs). The 2026-10-19 and 2026-10-17 batches showed no measurable change,
but their no-recorder runs varied far more (average latency ±0.008 ms
against ±0.000 ms now), so a 1 µs effect was within their noise; clifr's
latency itself is lower than on 2026-10-19 (0.071 against 0.075 ms). In the
2026-10-12 batch the default configuration raised the average by 0.002 ms
and p99.9 by 0.121 ms, both measurable.

### Scaling

One dimension varied at a time, no workload, guard rail off, 7 minutes per
point. The budget is 2% of one core.

2026-10-21 (`scaling-20261021-2027`); the 2026-10-19 batch
(`scaling-20261019-1620`) is in brackets.

| Point | Recorder CPU | eBPF programs | Memory max |
|---|---:|---:|---:|
| Baseline (2,000 processes, 50,000 fds, 20,000 connections, 50 spawns/s) | 0.48–0.50% (0.47–0.50%) | 0.04% | 178–209 MiB (165–195) |
| 10,000 processes | 0.97% (0.95%) | 0.04% | 237 MiB (246) |
| 200,000 open files | 0.81% (0.79%) | 0.04% | 268 MiB (263) |
| 100,000 connections | 0.89% (0.92%) | 0.07% | 360 MiB (377) |
| 10 spawns/s | 0.47% (0.42%) | 0.04% | 237 MiB (213) |
| 200 spawns/s | 0.61% (0.60%) | 0.13% | 229 MiB (190) |
| 100 new connections/s | 1.01% (1.11%) | 0.23% | 246 MiB (258) |
| 500 new connections/s | 1.56% (1.62%) | 0.90% | 313 MiB (309) |

All 15 points fit the 2% budget, as in the 2026-10-19 and 2026-10-17
batches (1 of 15 on 2026-10-12). CPU and memory are the same within noise;
peak memory is 20–35% lower than on 2026-10-17.
The eBPF programs run inside the observed processes' own kernel paths, so
their time is charged to those processes and is not part of the recorder's
CPU figure.

### Compared with Prometheus Node Exporter

At the busy load: clifr from the matrix above (batch 1620, three runs) and
the 2026-10-17 batch (1133); Node Exporter 1.10.2 with the Debian package's default collectors,
scraped every 15 s (one run, `nodeexp-busy-20261016-1405`). Prometheus
itself was not run: its column is an estimate.

| | clifr, batch 1620 | clifr, batch 1133 | Node Exporter | Prometheus server (estimate) |
|---|---:|---:|---:|---:|
| CPU, % of one core | 1.84 | 2.14 | 1.36 | well under 1 |
| Memory (anonymous), average / max | 285 / 332 MiB | 429 / 488 MiB | 9.0 / 9.7 MiB | about 50–150 MiB |
| Data kept on the host | about 178 MB/h | about 178 MB/h | none | about 1–1.5 MB/h |
| Data kept at the default retention | about 2 GB (the 2G size cap; 72 h would be 13 GB) | about 13 GB (72 h) | none | about 0.35–0.5 GB (15 days) |
| Written to disk | about 538 MB/h | about 565 MB/h | none | about 5–10 MB/h |
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
| Memory (anonymous) | 285 MiB | about 60–100 MiB | about 30–50 MiB | 9 MiB |
| Data kept | 178 MB/h | about 55–90 MB/h | the same | none (Prometheus: about 1–1.5 MB/h) |
| Written to disk | 538 MB/h | close to the data kept | the same | none (Prometheus: about 5–10 MB/h) |

The tracked state alone is some 20–30 MB in compact form, and each
connection needs some 15–25 bytes on disk even with a tight encoding
(about 48 now, transitions included). Only recording less closes the gap:
at this load all connections are loopback from the load generator, and
without them clifr is near its idle figures (about 22 MB/h and 171 MiB in batch 1133).
The fair comparison for clifr is atop with process accounting or a
continuous eBPF tracer, not a metrics exporter.

## Limitations

- **The latest minutes cannot be queried**: clifrd keeps rows in memory
  and writes them every `--flush-interval` (5 minutes), so a moment after
  the last flush is refused ("after the end of the recording ... clifrd
  writes to disk every 5m0s"), like a moment in a gap of the recording.
- **OOM victim's RSS on RHEL 8 and 9** comes from the SIGKILL the OOM
  killer sends just before (their `oom:mark_victim` tracepoint has no RSS
  fields): within 0.5% of the kernel's "Killed process" line in the VM
  runs; with the classic fallback programs (no `tp_btf`) it is unknown (0).
- **RHEL 8 misses about one time-wait start in 1000 connections** in some
  ground-truth runs: its TCP hooks are kprobes, which the kernel skips while
  another BPF program runs on that CPU. The recorder infers it: a close from
  FIN_WAIT2 or CLOSING without a reset means the kernel made a time-wait
  socket (`recorder_stats` source `tcp_time_wait_inferred`; state
  TIME_WAIT, corrected by the next keyframe). If a reset in FIN_WAIT2 was
  missed too, `ss` shows a time-wait socket that did not exist for up to
  60 s.

- **CPU is just under the 2% budget at the busy load**: 1.84% of one core
  on average (runs of 1.7–2.1%), with a few `budget_exceeded` events; an hourly
  compaction adds a burst of a few seconds. Every scaling point is within
  it. The guard rail lengthens the fd interval only when the fd walks are
  at least a quarter of the recorder's CPU (9–14% at the busy load), so it
  kept the interval at 2 minutes in every default run.
- **Memory is about twice v1's**: 285 MiB on average (332 at most) at the
  busy load and up to 377 MiB with 100,000 connections (2026-10-19), down
  from 429 / 488 and 561 MiB: rows held in memory are pointer-free
  (fixed-size addresses, enums and interned names instead of strings and
  pointers), so the garbage collector does not scan them, and the heap
  target is 256M. Rows are buffered until
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
