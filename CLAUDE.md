# sosv — Linux flight recorder (proof of concept)

`sosv record` continuously records which processes existed, which sockets and open
files each one held, and short-lived process start/exit events, into one SQLite file.
Query subcommands (`ps`, `lsof`, `ss`, `life`, `stats`, `verify`) reconstruct the
output of the real tools for a past moment or time range.

The PoC exists to prove two things with evidence: **accuracy** (reconstruction vs. the
real tools) and **cost** (CPU / memory / disk of recording and its impact on a busy
workload). The benchmark results under `bench/` are the main deliverable, not CLI polish.

## Hard constraints
- Go, one static binary (`CGO_ENABLED=0`), Linux only, kernel 4.18+ (RHEL 8/9, Ubuntu 22.04/24.04).
- Dependencies: standard library, `modernc.org/sqlite` (pinned v1.34.5 — newer versions need Go ≥1.26; this box has Go 1.22), `golang.org/x/sys`. Nothing else.
- Parse /proc ourselves. **Never read `/proc/*/environ`.**
- All /proc access goes through `procfs.FS` so `--proc-root` fixtures work.
- SQLite in WAL mode, one transaction per sample.
- No network, encryption, obfuscation, web UI or eBPF.

## Layout
- `cmd/sosv/` — subcommand dispatch and flag parsing.
- `internal/procfs/` — /proc parsers (stat, status, cmdline, fd, net/*, meminfo).
- `internal/sockdiag/` — NETLINK_SOCK_DIAG (inet_diag) dumps.
- `internal/cnproc/` — kernel proc connector (fork/exec/exit events).
- `internal/store/` — schema, batch writer.
- `internal/recorder/` — sampling loop, interval trackers, self-metrics, guard rails.
- `internal/query/` — reconstruction and formatting of ps/lsof/ss/life/stats.
- `internal/verify/` — compare saved real tool output with reconstructions.
- `deploy/` — systemd unit. `bench/` — load generator, benchmark runner, report. `test/e2e/` — end-to-end test.

## Data model notes
- Entities are time ranges: `first_seen`, `last_seen`. While an entity is still open,
  `last_seen` is NULL in the DB and lives only in memory ("seen at every sample since
  first_seen"); it is written when the entity closes, on clean shutdown, or recovered
  from the last sample timestamp on the next start after a crash.
- Per-sample values (`proc_samples`, `sock_samples`) are written only when they change.
- Times are Unix milliseconds (INTEGER). CLI times are local time `YYYY-MM-DD HH:MM:SS`.

## Commands
- Build: `CGO_ENABLED=0 go build -o sosv ./cmd/sosv`
- Test: `go test ./...`
- Quick manual run: `sudo ./sosv record --db /tmp/x.db --interval 2s --duration 1m`
- Machine notes: test VM has 8 vCPU, 7 GB RAM and little free disk; bench scripts abort below 1.5 GB free.

## Milestone status
1. [x] Process sampling, `ps aux --at`, `stats`
2. [x] Sockets (sock_diag), ownership, `ss`
3. [x] Open files, `lsof`
4. [x] Proc connector events, `life`, ps range mode
5. [x] Guard rails, systemd unit
6. [x] `--verify-every`, `verify`
7. [ ] Load generator + pgbench
8. [ ] Benchmark runner
9. [ ] Scaling tests, passive mode
10. [ ] Report generator, README
