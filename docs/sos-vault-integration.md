# clifr and sos-vault: integration draft

Draft 1, 2026-10-16. Status: proposal for discussion; nothing here is built.

clifr ("command line interface flight recorder") is the planned name of
sosv. This document uses **clifr** for the product, `clifr-record` for the
recorder (today `sosv-record`) and `clifr` for the query CLI (today `sosv`).
sos-vault is the sosreport analysis appliance
(<https://github.com/sos-vault/sos-vault-appliance>).

## 1. Goal

A system administrator runs clifr on a Linux fleet and uploads a sosreport
from each server to sos-vault. Days later, for any selected server, they
retrieve the server's recent clifr data and **play it** in sos-vault:

- pick a moment and see `ps`, `ss`, `lsof`, `vmstat`, `mpstat`, `iostat` and
  `uptime` as they were then, as tables or as the raw command output in the
  file viewer;
- step through time;
- give the data to the AI agent.

A sosreport is a snapshot at capture time. clifr supplies the history before
it: which processes ran (including short-lived ones), which connections
existed, which files were held, at any past moment within its retention.

## 2. Principles

- **Nothing leaves the server while it records.** clifr keeps its data
  locally (Parquet, bounded by `--retention` / `--max-size`) and needs no
  network code. Data is shipped on demand, for a case.
- **Reuse the sosreport path.** Capture, case id, encryption, upload and
  ingestion already exist in `sos report` and sos-vault; clifr data travels
  the same way.
- **Reuse clifr's reconstruction.** Rebuilding `ps`/`ss`/`lsof` for a moment
  from events, keyframes and open/closed entities is where clifr's accuracy
  work is (ground truth 41/41 checks; 99.5–100% of rows matched against the
  real tools). sos-vault calls the clifr CLI instead of re-implementing it.

## 3. Workflow

1. **Day 0, once per server:** install clifr (`clifr-record` as a systemd
   service) and upload a baseline sosreport to sos-vault. The sosreport
   registers the server (machine-id, hostname).
2. **Every day:** clifr records; old data is deleted past the retention.
3. **Day N, incident:** in sos-vault the admin selects a server and a time
   window. A minimal sosreport containing only the clifr plugin is captured
   on the server and uploaded (section 4). sos-vault links the bundle to the
   server and the case.
4. **Play:** the admin picks moments or ranges; sos-vault runs the clifr CLI
   on the bundle and shows tables, raw outputs and a timeline, and the agent
   can query it.

## 4. Retrieval

There is no single "latest Parquet file": the data is a directory of tables
(processes, TCP connections and transitions, keyframes, held fds, mounts,
system, CPU and disk counters, recorder stats, meta), with files per hour
plus the files of entities still open. The unit shipped is a **bundle**: every
table for a time window, plus `meta`.

| Route | How | For | Against |
|---|---|---|---|
| **A. Minimal sos report** (proposed) | `sos report --only-plugins clifr --case-id … -k clifr.window=6h`, run by the admin or by sos-vault over SSH; uploaded through the existing API | Reuses encryption, case tagging, upload and ingestion; no network code in clifr | Needs `sos` on each server (already true for this workflow) and someone or something to trigger it |
| B. Pull over SSH | sos-vault's sysadmin helpers rsync the window from the data directory | Fully started from sos-vault | SSH keys and sudo for the fleet in sos-vault; bypasses sos encryption and obfuscation |
| C. clifr listens | A port on each server | — | Against clifr's no-network rule; not proposed |

A and B combine: SSH only *triggers* route A, and the data still comes back
through the upload.

### Bundle

- Made by a new recorder subcommand (pure Go, no DuckDB, since the CLI may
  not be on the server), for example
  `clifr-record bundle --data-dir /var/lib/clifr --last 6h -o clifr.tar`.
- Copies whole hourly files that overlap the window, unchanged: almost no
  CPU. Cutting to an exact window would decode and re-encode, at about the
  CPU of hourly compaction.
- Contains `meta` with: hostname (stored today), **machine-id and boot ids**
  (new), **time zone** (new), **bundle schema version** (new), recorder
  version, window, and the recording settings already in `meta`.
- Files are renamed into place atomically by the recorder, so copying while
  it runs is safe.

### Sizes (measured on the test machine, one run each)

| Load | Data kept | 6 h bundle | 1 day | 7 days of retention |
|---|---:|---:|---:|---:|
| Busy (500 new connections/s, 50 new processes/s, 2,500 processes, 57,000 fds) | about 175 MB/h | about 1 GB | about 4 GB | about 28 GB |
| Quiet baseline | about 22 MB/h | about 130 MB | about 0.5 GB | about 3.7 GB |

Parquet is already compressed (zstd), so the sosreport archive barely
shrinks it. The default `--retention` is 72 h; "days later" needs it set per
fleet with a size cap.

### clifr sos plugin

A Python plugin for `sos report` (sos plugins are Python), shipped with
clifr. It runs `clifr-record bundle` with the window from its options and
adds the result and `clifr-record --version` to the archive. With no window
given it takes a default (for example 6 h), so a normal full sosreport also
carries recent history.

## 5. Linking in sos-vault

- **Server identity:** machine-id from the bundle matches the machine-id in
  the server's sosreports; hostname alone is not reliable (reuse, renames).
- **Case:** the minimal sosreport carries the case id like any other.
- **Time:** clifr stores UTC milliseconds; displays use the server's time
  zone from `meta`, whatever the appliance's zone.
- **Versions:** sos-vault's clifr CLI must read every bundle schema version
  in the fleet; the CLI refuses newer versions it does not know, with a
  clear message.

## 6. Playing it

### Query engine

sos-vault runs the `clifr` CLI (Go, DuckDB) as a subprocess from its queue
workers, the way it already runs privileged helpers, and reads its output.
Changes needed in the CLI:

- **JSON output for every subcommand** with a documented, versioned shape
  (today `--json` exists on some subcommands, CSV on others).
- **Window-only loading:** today the CLI loads the whole data directory into
  in-memory DuckDB. Fine for hours, too much for days of busy data on a
  shared appliance. Load only the window around the requested moment, or
  query the Parquet files in place; measure query time and memory on 1 h,
  6 h and 24 h busy bundles.
- **Snapshot at T:** one command that writes the reconstructed outputs at a
  moment as text files named like sosreport's (for example
  `sos_commands/process/ps_auxwww`, `sos_commands/networking/ss_-peaonmi`
  equivalents, `lsof`, `vmstat`, …). sos-vault's file viewer then shows a
  **virtual sosreport at T** without new viewer code.

### Views

- **Time picker / slider** per server and bundle.
- **Tables:** JSON from the CLI (`ps`, `ss`, `lsof`, `mounts`, `oom`,
  `life`, `vmstat`, `mpstat`, `iostat`, `uptime`).
- **Raw:** the virtual sosreport at T in the existing file viewer.
- **Timeline:** process starts and exits, connections, OOM kills, mounts,
  and recorder gaps.

Resolution, to be stated in the UI: process start/exit, connections, OOM
kills and mounts are exact (eBPF events, milliseconds); per-process values
(CPU, RSS) and system counters are per sample (30 s default); open files are
per fd walk (2 minutes default). Gaps (recorder stopped, skipped samples,
dropped events) are recorded and must be shown.

### Agent

Whole outputs are too large to send as text (`ps aux` about 2,500 rows and
`lsof` about 57,000 at the busy load). The agent gets **tools** backed by
the CLI instead:

- state at T (filtered: a process, a port, a user);
- processes started or ended between T1 and T2 (`life`);
- connections of a process, or to a port or peer, over a range;
- what changed between T1 and T2 (new: a diff command in the CLI);
- OOM kills, mounts and recorder gaps in a range.

Plus a page about clifr data and its resolution in the agent's knowledge
base (`agent/kb`).

## 7. Security and privacy

- **Obfuscation (the hardest open item):** `sos clean` masks hostnames,
  IPs, users and keywords in text files but cannot read Parquet. clifr data
  holds command lines (which may contain secrets in arguments), addresses,
  ports, paths and user ids. Options: (a) `clifr-record bundle --clean`
  applies the same rules with the same mapping as `sos clean`, so bundle
  and sosreport stay consistent; (b) obfuscated uploads leave clifr data
  out. Until one exists, clifr data must be treated as unobfuscated.
- **Encryption:** route A gets the sosreport archive's encryption. In
  sos-vault, bundles live in the vault like other archives (LUKS in the
  licensed tiers).
- **Command lines:** clifr reads `/proc/<pid>/cmdline` and the exec event's
  arguments; it never reads `/proc/<pid>/environ`.

## 8. Cost on the servers

Recording (measured 2026-10-16, busy load, one run): 2.07% of one core,
about 400 MiB anonymous memory, about 485 MB/h written, 175 MB/h kept. On a
quiet server: about 2% of one core (measured before the latest changes;
lower now), about 170 MiB, about 22 MB/h kept. Integration adds nothing
while recording; a bundle copies files once at capture.

## 9. Work items

| # | Item | Where | Rough effort |
|---|---|---|---|
| 1 | Rename to clifr (binaries, unit, paths, docs) | clifr | 1–2 days |
| 2 | `meta`: machine-id, boot ids, time zone, schema version | clifr | 1 day |
| 3 | `clifr-record bundle` | clifr | 2–3 days |
| 4 | sos plugin | clifr | 1–3 days |
| 5 | Uniform JSON output; snapshot at T; diff T1..T2 | clifr CLI | 3–5 days |
| 6 | Window-only loading, with measurements | clifr CLI | 2–4 days |
| 7 | Obfuscation consistent with `sos clean` | clifr | about 1 week plus review |
| 8 | Ingest bundles, link to servers and cases | sos-vault | unknown |
| 9 | Time picker, tables, virtual sosreport, timeline | sos-vault | unknown |
| 10 | Agent tools and knowledge base page | sos-vault | unknown |

The clifr items total roughly 3–4 weeks including tests against the
ground-truth data. The sos-vault items cannot be sized until its ingestion
and file-viewer code (`app/`, `routes/`) has been read; a first guess is
2–4 weeks.

## 10. Decisions needed

1. Retrieval route: A (proposed), B, or A triggered by B.
2. Obfuscation: required for the first release, or clifr data excluded
   from obfuscated uploads until then.
3. Retention and size cap per server (days of history against disk).
4. Default window of the sos plugin.
5. Timing of the rename to clifr.
6. Packaging: clifr viewer as a sos-vault module; licence compatibility
   with sos-vault's AGPL open core.

## 11. Open questions

- How sos-vault ingests and indexes archives today, and how its file
  viewer and agent take new data (not yet read).
- Whether the appliance can hold the DuckDB working set for the windows
  admins will ask for (to be measured, item 6).
- Whether the sos project would take the clifr plugin upstream or it ships
  with clifr.
- Fleet operations: who triggers captures for many servers at once, and how
  sos-vault reaches them.
