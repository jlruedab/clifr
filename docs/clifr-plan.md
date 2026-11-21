# clifr / clifrd: from working prototype to viable product

Agreed with the user on 2026-10-19. Spec: `docs/clifr command line flight.txt` (the user's file). Phase 1 (rename) done 2026-10-19 (`0faa79f`); phase 2 (front end) 2026-10-19: grammar `1a7ef54`, new commands `034cfe6`, JSON Lines `9f680c7`, verify and ground truth `32eee75`; phase 3 (recorder) 2026-10-19 `03df9d3` .. `abc43af`, benchmark batch 20261019-1620; phase 4 (range views, diff, pager, loading) 2026-10-20 `438f503` .. `a9c619d`.

## Context

`docs/clifr command line flight.txt` (the user's spec) defines the product
interface: `clifr` (query CLI, today `sosv`) and `clifrd` (agent, today
`sosv-record`), new option names, new commands (netstat, free, df, mount,
diff, info, help, list), range views, JSON with provenance, an
interactive pager, a YAML config, redaction, push to sos-vault, remote query
and Prometheus metrics (the spec's encryption and licensing were dropped by the
user on 2026-11-09). The request: review it, say what is missing, and plan the
work to a viable product.

Decisions taken with the user (2026-10-19):
- **First viable release is local-only.** Network (push, `--host`, `/metrics`)
  and TLS are a later phase; the CLAUDE.md "no network" constraint is lifted
  only when that phase starts.
- **Remote query = serve files:** clifrd (or sos-vault) serves the Parquet
  files of a window; `clifr` reconstructs locally. clifrd stays pure Go, static,
  no query engine.
- **sos-vault delivery: both** — `clifrd bundle` + sos plugin first, `--push` later.
- **Dependencies approved:** `gopkg.in/yaml.v3` (clifrd.yml), `golang.org/x/term` (pager).

## Review of the spec

Strong points: one grammar for every command (`clifr --at T "ps aux"`) is
easier to learn than today's per-command flags; rejecting unsupported options
keeps the "exact reconstruction" promise honest; `--summary/--changes/--samples`,
`diff` and `info` cover the incident workflow; per-value "exact or sampled" in
JSON matches what the recording really knows; `doctor` answers the first
support question.

Problems to resolve in the spec:
1. **Encryption at rest with only a public key** makes the data unreadable to
   local `clifr` (free local use) unless the private key is on the host. Either
   encrypt only bundles/pushes, or say where the private key lives.
2. **`memory_limit: 256M` "soft memory limit"**: a Go memory limit was measured
   unsafe (11% of a core at 100,000 connections). Map it to today's
   `--gc-heap-target` and name it so (`gc_heap_target`), not "limit"; the
   busy load already sits around 290–330 MiB with it.
3. **`--host` remote clifrd** has no matching clifrd option: clifrd needs a
   `--serve ADDR` (file server for windows) in the network phase.
4. **`cpu_budget` "lengthens intervals"**: today only the fd interval is
   lengthened, and at the busy load the guard rail cannot act (fd walks are
   16% of the cost). Keep the wording to what it does.
5. **`--max-size` default 2G** is about 11 h at the busy load (4 GB/day),
   so the 72 h retention would rarely be reached there. Fine as a safety cap;
   `info` should show the effective coverage.
6. **`/metrics` "Node Exporter-compatible"** includes filesystems, network
   interfaces and pressure, which clifrd does not collect today (new collectors).
7. **"clifr list COMMAND"** is unclear (list of what?). Proposal: drop it and
   let `clifr help` list commands and `clifr help COMMAND` the options.

Missing from the spec:
- **The clifr-only views that are the product's edge:** process lifetimes
  (`life`: short-lived processes), OOM kills, mount changes, recorder gaps.
  Proposal: `clifr events` (starts/exits, OOM, mounts, gaps) with `--name`,
  `--since/--until`; keep `life`/`oom` as aliases.
- **Developer/support commands** today in `sosv`: `verify`, `stats`, `export`.
  Fold `stats` into `clifr info`; keep `verify` and `export` (hidden from the
  main help).
- **clifrd `bundle`** (pure Go, window of hourly files + `meta`) and the
  **sos plugin**, from `docs/sos-vault-integration.md`.
- **`meta`:** machine-id, boot ids, host time zone (needed by `--tz` default
  and sos-vault), bundle schema version.
- **Supported options per command:** the spec says "unsupported options are
  rejected" but not which are supported; a matrix is needed (below).
- **df** needs a new collector (statfs of each mount per sample); `free` and
  `netstat` can be built from existing data; `mount` from the mounts table.
- **Per-process I/O** ("process: CPU, memory and I/O samples"): not recorded
  today (`/proc/<pid>/io`); new column, costs reads.
- **Separate system interval (10 s) from process interval (30 s):** today
  one loop; split it.
- **Local access control:** the data holds every user's command lines; data
  dir root-only plus a `clifr` group for local readers.
- **Packaging:** .deb/.rpm, man pages, shell completion, SELinux policy for
  RHEL (eBPF and /proc access under enforcing), upgrade path for older
  recordings (schema version), arm64 actually run.
- **The viability evidence** (README "Status"): soak test, RHEL 9 / 8.x /
  Ubuntu 22.04 runs, a real server checked with `verify`.

## Supported options for the first release (proposal)

| Command | Options | Source |
|---|---|---|
| ps | `aux`, `-ef`, `-eo COLS` (pid,ppid,user,comm,args,rss,vsz,%cpu,stat,lstart,etime,tty), `-p PID`, `-u USER`, `-C NAME` | processes, proc_samples |
| lsof | `-p PID`, `-i`, `-u USER`, `-c NAME`, `-n`, `-P` | fds_held, tcp_conns |
| ss | `-t -u -a -n -p -l -4 -6`, filters `src/dst/sport/dport` with `and` | tcp_conns, keyframes |
| netstat | `-t -u -a -n -p -l` | same as ss |
| free | `-b -k -m -g -h`, `-w` | sys_samples |
| vmstat, mpstat (`-P`), iostat (`-x -d -p`), uptime | as today | sys/cpu/disk samples |
| df | `-h -T -i`, path | fs_samples (3c) |
| mount | (none), `-t TYPE` | mounts (3c: fs options, order, loop files, utab) |

## Plan (one step at a time; report and wait after each)

### Phase 1 — Rename (2–3 days)
- Go module `sosv` → `clifr`; `cmd/sosv-record` → `cmd/clifrd`, `cmd/sosv` →
  `cmd/clifr`; data dir `/var/lib/clifr`, config `/etc/clifr`; unit
  `deploy/clifrd.service`; bench scripts, tests, README/CLAUDE/HANDOFF.
- Readers keep accepting recordings written by sosv (meta unchanged).
- Verify: unit, e2e, `--test-ebpf`, small ground truth.

### Phase 2 — clifr front end (1–1.5 weeks)
- New entry point `cmd/clifr/main.go`: global options (spec names and short
  forms, env vars `CLIFR_*`), `"COMMAND [ARGS]"` split with shell-word
  rules, dispatch to per-command option parsers built on today's handlers
  (`cmdPS`, `cmdSS`, … in `cmd/sosv/main.go`).
- Time parser in `internal/query/common.go` (`ParseTime`): the spec's
  formats, relative times, `--tz`; resolved range and zone printed on stderr
  (`query.Header`).
- `clifr help`, `clifr help COMMAND` (generated from the option tables),
  rejection of unsupported options, `clifr info` (coverage, gaps, intervals,
  recording level, `ComputeStats`).
- Uniform `--json`: one object per row with timestamps and `exact|sampled`
  per field (`query.PrintJSON` everywhere, a provenance tag per column).
- New renderers from existing data: `free`, `netstat`; ps `-ef/-eo`,
  lsof/ps user and name filters; `events` (life/oom/mounts/gaps).
- Verify: unit tests per parser; extend `internal/verify` and `test/truth`
  to `free`, `netstat`, `mount`, `ps -ef`; e2e on the new grammar.

### Phase 3 — clifrd recorder features (1.5–2 weeks)
- Added during phase 2: `mount` needs the file-system (super block) options
  and the mountinfo order, which the mounts table does not keep; netstat's
  program name needs where argv[0] ends in the command line (processes that
  rewrite their whole command line, such as Chrome, differ today).
- `clifrd.yml` (yaml.v3): intervals (process, system, files, keyframe),
  collectors on/off, `cpu_budget`, `gc_heap_target`, `redact`, retention,
  max size; flags override the file.
- Split system interval from process interval in `internal/recorder`.
- New collectors: filesystem usage (statfs per mount → `fs_samples`, for df),
  per-process I/O (`/proc/<pid>/io`, via `procfs.FS`).
- `redact`: regex masking of command lines and exec arguments before they
  are stored.
- `meta`: machine-id, boot id, time zone, schema version.
- `clifrd doctor`: kernel, BTF, capabilities, eBPF features (reuse
  `--test-ebpf` code in `cmd/sosv-record/testebpf.go`), resulting recording
  level (eBPF full / proc connector / sampling only).
- `--max-size` default 2G, `--log-level`.
- Data dir permissions and a `clifr` group in the unit.
- Verify: unit, e2e, ground truth full; benchmark rerun (matrix + scaling,
  about 7 h) because the recorder changed.

### Phase 4 — Range views, diff, pager, query performance (1.5–2 weeks)
- `--summary` (default), `--changes`, `--samples` with `-e/--every`,
  `-n/--number` for every command, on top of the existing range queries
  (`PSRange`, `ConnsInRange`, `LsofRange`, `SysSpans`).
- `clifr diff --at A --at B`.
- Pager `-I` (x/term), `--plain` when piped.
- Window-only loading in `internal/duck` (today the whole data dir is loaded):
  measure 1 h / 6 h / 24 h busy recordings.
- Verify: tests on recorded fixtures; timing and memory of the CLI.

### Phase 5 — sos-vault without network (1 week) — done 2026-10-20
- `clifrd bundle --since/--until -o FILE` (whole hourly files + meta, pure Go).
- sos plugin (Python) running it; `clifr --data-dir` on an unpacked bundle.
- Verify: bundle of a busy hour opens and matches the source data.

### Phase 6 — Viability evidence and packaging (1–2 weeks, mostly unattended)
- .deb/.rpm, man pages from the help text, completion, SELinux module.
- RHEL 9, RHEL 8.x, Ubuntu 22.04 VMs: `doctor`, `--test-ebpf`, e2e, small
  ground truth; arm64 if a machine exists.
- 3–7 day soak test under the shipped unit (also settles `CPUQuota=5%`).
- A real server, checked with `clifr verify`.
- README Status updated to "viable" if all pass.

### Phase 7 — Network features (started 2026-11-07)
Agreed with the user on 2026-11-07 (the real-server test of phase 6 waits
for a busy server). Rules for the whole phase: every network feature is
opt-in and off by default (a default install has no listening port and no
outbound connection); the unit keeps `RestrictAddressFamilies=AF_NETLINK
AF_UNIX`, a packaged drop-in adds AF_INET/AF_INET6 for a feature that is
turned on; no phone-home or telemetry.
- **7.1 `/metrics`** (1–1.5 weeks): `clifrd --metrics 127.0.0.1:9100`
  (`metrics:` in clifrd.yml). Decisions (the user, 2026-11-07): the text
  exposition format written by hand (no Prometheus client library); loopback
  addresses only at first (TLS and auth later, as clifr's own small subset
  in clifrd.yml); Node Exporter's metric names, so its dashboards work.
  Served from the latest in-memory sample (a scrape reads no file).
  - 7.1a (done 2026-11-07): endpoint, text format; `/proc/stat`, meminfo,
    loadavg, vmstat (`node_cpu_seconds_total`, `node_memory_*_bytes`,
    `node_load*`, `node_context_switches_total`, …) and `clifr_*` (recorder
    CPU, memory, data size, events received and dropped per source).
  - 7.1b (done 2026-11-07): disks, network interfaces (rtnetlink stats64),
    filesystems (`fs_samples`), pressure (`/proc/pressure/*`, the one new
    collector, read only with `--metrics`). Not served (data not recorded):
    `node_disk_info` and the other `*_info` families, sysfs-only interface
    gauges (speed, carrier, dormant, assign types, device id).
  - 7.1c (done 2026-11-07): compared with the real Node Exporter here (in
    7.1a/b); the opt-in unit drop-in `deploy/clifrd-metrics.conf` (VMs:
    Ubuntu 22.04, Rocky 8); docs; benchmark with 15 s scrapes
    (`metrics-busy-20261107-1857`: no measurable cost). 7.1 is complete.
  - 7.1d (2026-11-08, the user: needed for clifrd to be an actual Node
    Exporter alternative): `--metrics-tls-config FILE` (`metrics_tls_config:`)
    in Node Exporter's web configuration format instead of clifr's own subset
    (an existing web-config.yml works): tls_server_config (admin-provided
    certificates, client certificates, versions, ciphers, curves),
    http_server_config.headers, basic_auth_users (bcrypt:
    golang.org/x/crypto, approved). With TLS any address; without it still
    loopback only. Reloaded when the files change.
  - 7.2d (2026-11-08, the user: one kind of certificate for both): `--serve-tls-config FILE`
    (`serve_tls_config:`), the same format and possibly the same file
    (`internal/webconfig`): the admin's certificate instead of the self-signed
    one, TLS 1.3 at least, on loopback too, client certificate settings and
    users ignored (tokens). `clifr --host` accepts a certificate valid for the
    host name against `--tls-ca FILE` (only that CA) or the system's CAs, and
    pins only when no CA vouches for it.
- **7.2 Remote query** (1.5–2 weeks): `clifrd --serve ADDR` serves the
  Parquet files of a window; `clifr --host URL` downloads and caches them and
  queries locally. Decisions (the user, 2026-11-07): tokens hashed in a
  root-only file (`clifrd token new` prints one once and stores its SHA-256
  in `/etc/clifr/serve-tokens`; constant-time compare); TLS with a
  self-signed certificate clifrd makes at first start, pinned by clifr on
  first use (`~/.config/clifr/known_hosts`, as SSH; `--tls-fingerprint` for
  non-interactive use; a changed certificate is an error); plain HTTP only on
  loopback; per-file transfer with a cache (`/v1/files` lists a window's
  files with SHA-256, as `bundle.Select`; clifr fetches the ones it lacks and
  queries exactly the listed set).
  - 7.2a (done 2026-11-07): clifrd side (`--serve`, `clifrd token`, the
    certificate, `/v1/info`, `/v1/files`, `/v1/file`).
  - 7.2b (done 2026-11-07): clifr side (`--host`, pinning, cache). On the
    way, two bugs of existing code fixed: bundles lost the rows of entities
    closed after the window (since 2026-11-01), and lsof lost most open
    files of a recording with several runs (fds_held ids, since M5).
  - 7.2c (done 2026-11-08): unit drop-in, sos plugin (never collects the
    token file), docs, VM end to end (Ubuntu 22.04, Rocky 8). It found that
    user names came from the reading machine's passwd: clifrd now records
    the host's (snapshots source "passwd", the user's choice). 7.2 is
    complete.
- **7.3 Licensing and 7.4 Encryption: dropped** (the user, 2026-11-09, after
  a business review): clifr is AGPL-3.0-only, with no commercial license and no
  licence check; bundles and pushes are not encrypted by clifr.
- **7.5 Push to sos-vault**: needs sos-vault's ingestion API; may not be
  needed if route A (a minimal `sos report` uploaded through sos-vault's
  existing API, `docs/sos-vault-integration.md`) is enough. Open (the user).

### Phase 8 — Command coverage
Agreed with the user on 2026-10-21; one step at a time, report and wait.
- **Step 1, from data already recorded** (no recorder or format change, ~1
  week): `top -b -n 1` (done 2026-10-21) (summary lines; PID USER PR NI VIRT RES S %CPU %MEM
  TIME+ COMMAND; PR and SHR recorded since step 3 (schema 8), %CPU over the sample
  interval), `date [--utc]`, `pstree -lp`, `ps` forest (`f`) (these three
  done 2026-10-21), `ss -s` (done 2026-10-21 with sockstat recorded: schema 3),
  `df -a -l -x`, `findmnt` (tree from mount paths), `hostname` (as recorded
  at start) (these three done 2026-10-21), `last -F reboot` (boots within
  the recording; done 2026-10-21 with uname recorded per run, which also
  gives `uname`, pulled forward from step 4).
- **Step 2, the CSV's priority items** (new tables, ~2–3 weeks): `netstat -s
  [-6]`, `nstat -zas` (/proc/net/snmp, snmp6, netstat per system sample;
  recording, nstat and netstat -s done 2026-10-21);
  `ip -s -d link` (rtnetlink; done 2026-10-21 without each interface type's
  own parameters, the user's choice; their raw attributes are recorded);
  `ip -o addr`, `ip -d address` (done 2026-10-21: address changes from
  rtnetlink notifications, hourly snapshots); `ip route show table all`
  (`-6`), `ip rule list` (`-4`/`-6`) (done 2026-10-21: raw messages, changes
  and a re-dump after them); `ip addr`, `ip route [-6]`,
  `ip rule` (netlink notifications, list at start then changes); `dmesg [-T]`
  (/dev/kmsg; the user decided 2026-10-21: record it, relax the unit's
  `ProtectKernelLogs`, apply the `--redact` patterns to the messages; done
  2026-10-21: schema 6 `kmsg`, CAP_SYSLOG in the unit);
  `systemctl list-units [--all|--failed]` (D-Bus unit signals; the user
  approved `github.com/godbus/dbus/v5` on 2026-10-21; done 2026-10-21: schema 7
  `units`, private socket, signals then a ListUnits diff). Step 2 is complete;
  benchmark batch 20261021-2027: cost unchanged (1.86% of one core, 285 / 323 MiB).
- **Step 3, process fields** (benchmark after): policy, real-time priority,
  faults, context switches (stat/status, already read), RssFile+RssShmem
  (top SHR), wchan, SELinux context, cgroup path → exact `top`, `ps alxwww`,
  `pidstat`, `ps auxZww`, `systemd-cgls`, container ids for docker/podman.
  Step 3 is complete (2026-10-22); benchmark batch 20261022-1900: cost unchanged
  (1.85% of one core, 286 / 329 MiB), fd-walk samples about 45 ms longer.
- **Step 4, change-only snapshots:** uname/hostname changes, /proc/swaps,
  modules, sysctl, locks, sysvipc, NUMA, slabinfo, nf_conntrack stats,
  mountstats, NFS counters, netns, neighbours, lsblk sizes and holders,
  file-system labels. Step 4 is complete (2026-10-23); benchmark batch
  20261023-2100: 1.90% of one core (+0.05), 287 / 335 MiB, pgbench within noise.
- Not possible: lsof's brief opens and mmaps, individual threads (ps -L/m).
- Every recorder addition bumps the schema version; steps 2–4 end with a
  benchmark rerun; every command gets a ground-truth or `clifr verify` check.

Rough total for phases 1–6: 7–10 weeks of work plus the unattended runs.

## Critical files
- `cmd/sosv/main.go` (→ `cmd/clifr`), `cmd/sosv-record/main.go` (→ `cmd/clifrd`)
- `internal/query/*` (renderers, `common.go` time parsing, JSON)
- `internal/recorder/*`, `internal/procfs/*`, `internal/store/batch.go`,
  `internal/pqstore/*` (new tables), `internal/duck/*` (window loading)
- `internal/verify/*`, `test/truth`, `test/e2e`, `deploy/sosv.service`
- `README.md`, `CLAUDE.md`, `HANDOFF.md`, `docs/sos-vault-integration.md`

## Verification (every phase)
`go test ./...`; e2e; `--test-ebpf`; ground truth small (full after recorder
changes); benchmark matrix + scaling after phase 3 and before phase 6; results
recorded in HANDOFF; commit only on the user's request.
