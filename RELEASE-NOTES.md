# Release notes

## clifr 0.2.0 (pre-release), 2026-11

Ten more tools, who killed a process, and the rest of vmstat's and iostat's options. clifr is still a **working prototype**: tested in virtual machines and on one desktop, not yet on a production server.

### Downloads

| File | What |
|---|---|
| [`clifrd_0.2.0_amd64.deb`](https://github.com/jlruedab/clifr/releases/download/v0.2.0/clifrd_0.2.0_amd64.deb), [`clifrd-0.2.0-1.x86_64.rpm`](https://github.com/jlruedab/clifr/releases/download/v0.2.0/clifrd-0.2.0-1.x86_64.rpm) | the recorder: a static Go binary, the systemd unit, the sos plugin |
| [`clifr_0.2.0_amd64.deb`](https://github.com/jlruedab/clifr/releases/download/v0.2.0/clifr_0.2.0_amd64.deb), [`clifr-0.2.0-1.x86_64.rpm`](https://github.com/jlruedab/clifr/releases/download/v0.2.0/clifr-0.2.0-1.x86_64.rpm) | the query tool (needs glibc 2.28 or later) |
| [`SHA256SUMS`](https://github.com/jlruedab/clifr/releases/download/v0.2.0/SHA256SUMS), [`SHA256SUMS.asc`](https://github.com/jlruedab/clifr/releases/download/v0.2.0/SHA256SUMS.asc) | checksums, and their signature |

Check the download before installing, with the same release key as 0.1.0 ([`KEYS`](https://raw.githubusercontent.com/jlruedab/clifr/v0.2.0/KEYS), fingerprint `2AD0 6804 EA2D 2396 1971  79AC 6336 C307 D721 2C5F`):

```sh
gpg --import KEYS                       # once: the release key, from the repository
gpg --verify SHA256SUMS.asc SHA256SUMS  # must say "Good signature"
sha256sum -c --ignore-missing SHA256SUMS
```

### Upgrading from 0.1.0

```sh
sudo apt install ./clifrd_0.2.0_amd64.deb ./clifr_0.2.0_amd64.deb       # Debian, Ubuntu
sudo dnf install ./clifrd-0.2.0-1.x86_64.rpm ./clifr-0.2.0-1.x86_64.rpm  # RHEL, Rocky, Alma
```

- **Upgrade clifr wherever you read recordings**, not only on the recorded hosts. 0.2.0 records schema 15 (0.1.0: schema 10), and clifr 0.1.0 refuses a newer recording ("recorded by a newer clifrd … update clifr"), a bundle or `--host` included.
- **The existing recording stays readable.** What 0.1.0 did not record (namespaces for `lsns`, CPU and memory topology for `lscpu` and `lsmem`, per-thread values for `atop`, I/O priorities for `iotop`, signal senders, logins) is missing for that part: the commands say from when it is recorded.

### What's new

**Ten more tools**, each following the real tool's code for the versions on the tested distributions:

| Tool | What it shows from the recording |
|---|---|
| `atop` | the screen since boot at a moment, or `atop INTERVAL` over a range; the process views `-m -d -s -v -c` |
| `htop` | the default screen at a moment, as text |
| `iotop` | `iotop -b`: I/O per process between two samples |
| `sar` | `sar -f`'s reports over a range: CPU, memory, paging, disks, network, sockets, PSI, interrupts and more |
| `who`, `w` | who was logged in, from utmp and logind |
| `lsipc` | System V IPC limits and objects |
| `lscpu` | CPUs, caches, topology, vulnerabilities, the hypervisor |
| `lsmem` | memory blocks, online and offline |
| `lsns` | the processes' namespaces |

That makes 45 tools, plus clifr's own 6 commands.

**Also new:**
- **Who killed a process**: the sender of a fatal signal (PID, command and user, or the kernel), in `clifr life` (SENT BY) and `clifr events`.
- **`last`** shows logins and logouts, not only reboots, and takes a range.
- **`vmstat`** gains `-a -w -t -n -y -S`, `-s -f -D`, `-d -p -m`; **`iostat`** gains `-c -d -x -s -k -m -z -N -t -y` and the first line.
- **`ps --container NAME`**: one container's processes.
- **`--json`** for `sar`, `htop`, `iotop` and `atop`: what the screen shows, one object per row.
- **`clifr verify`** also compares `atop`, `iotop` and `sar` with the real tools, in the recorded host's time zone.
- **Clock steps** (an NTP jump, a manual `date -s`) no longer move process start times or keys.
- **Lost TCP events**: the next full dump of the connection table comes a minute later instead of five, and `ss`, `netstat` and `lsof -i` print an "incomplete:" header for the time affected.

### Tested on

| Distribution | Kernel | How |
|---|---|---|
| Ubuntu 26.04 | 7.0 | the development desktop, bare metal: daily use, the benchmarks |
| Ubuntu 24.04 | 6.8 | KVM virtual machine (new in 0.2.0) |
| Ubuntu 22.04 | 5.15 | KVM virtual machine |
| Rocky Linux 8.10 | 4.18 (cgroup v1) | KVM virtual machine, SELinux enforcing |
| AlmaLinux 9.8 | 5.14 | KVM virtual machine, SELinux enforcing |

In each virtual machine the packages pass the installed-service checks, eBPF in all three program modes, the end-to-end test, the ground-truth test (43 of 43 checks), the network features (`--metrics`, `--serve`, TLS) and the sos plugin: 23 of 23 checks on Rocky 8 and Alma 9 (with SELinux), 21 of 21 on Ubuntu. The packages also install and remove cleanly in Ubuntu 22.04 and 24.04 and Rocky 8 and 9 containers. Each new tool was compared with the real one on the desktop and in the four virtual machines.

### What it costs

At the busy-server benchmark (80,000 PostgreSQL transactions a second, 2026-11-23): **2.2% of one core** (1.9% in 0.1.0), about 290 MiB of memory on average, 330 MiB at most. The increase is the per-thread values that `atop` and `iotop` need. Desktop and mixed-load figures were measured for 0.1.0 and are below.

### Known limitations

As in 0.1.0 (below), and:
- `lsns` lists only namespaces with a process in them: a namespace held only by an open file, a socket or a bind mount is not recorded.
- `htop` shows processes, not user threads; `iotop` shows processes only (as `iotop -P`).
- `lscpu` has no BIOS lines (the DMI table is root's only); `atop` cannot show the CID column for containers with their own host name.

## clifr 0.1.0 (pre-release), 2026-11

The first public release: packages for x86_64 Linux. clifr is a **working prototype**: tested for days in virtual machines and on one desktop, not yet on a production server. Please try it on machines where an incident would not hurt, and report what you find.

### What it is

clifr (**command line flight recorder**) is a flight recorder for Linux servers. **`clifrd`** records, all the time, which processes existed and which started and exited (even for a few milliseconds, through eBPF). It also records every TCP connection and who owned it, open files, mounts, routes, kernel messages and the system-wide counters. Everything goes into Parquet files in `/var/lib/clifr`, kept 72 hours by default.

**`clifr`** later rebuilds the output of 35 familiar tools (`ps`, `top`, `ss`, `lsof`, `df`, `free`, `vmstat`, `iostat`, `ip`, `dmesg`, …) as they would have looked at a past moment or over a range. It adds 6 commands of its own (`events`, `life`, `oom`, `mounts`, `containers`, `pstore`):

```sh
clifr --at "02:45" "ps aux"
clifr --since "2 hours ago" events
clifr diff --at "14:00" --at "14:20" "ss -ltnp"
```

It never runs the command: it reads the recording, on the recorded host or anywhere else from a bundle.

### Downloads

| File | What |
|---|---|
| [`clifrd_0.1.0_amd64.deb`](https://github.com/jlruedab/clifr/releases/download/v0.1.0/clifrd_0.1.0_amd64.deb), [`clifrd-0.1.0-1.x86_64.rpm`](https://github.com/jlruedab/clifr/releases/download/v0.1.0/clifrd-0.1.0-1.x86_64.rpm) | the recorder: a static Go binary, the systemd unit, the sos plugin |
| [`clifr_0.1.0_amd64.deb`](https://github.com/jlruedab/clifr/releases/download/v0.1.0/clifr_0.1.0_amd64.deb), [`clifr-0.1.0-1.x86_64.rpm`](https://github.com/jlruedab/clifr/releases/download/v0.1.0/clifr-0.1.0-1.x86_64.rpm) | the query tool (needs glibc 2.28 or later) |
| [`SHA256SUMS`](https://github.com/jlruedab/clifr/releases/download/v0.1.0/SHA256SUMS), [`SHA256SUMS.asc`](https://github.com/jlruedab/clifr/releases/download/v0.1.0/SHA256SUMS.asc) | checksums, and their signature |

Check the download before installing. The release key is [`KEYS`](https://raw.githubusercontent.com/jlruedab/clifr/v0.1.0/KEYS), in the repository:

```sh
gpg --import KEYS                       # once: the release key, from the repository
gpg --verify SHA256SUMS.asc SHA256SUMS  # must say "Good signature"
sha256sum -c --ignore-missing SHA256SUMS
```

The release key's fingerprint is `2AD0 6804 EA2D 2396 1971  79AC 6336 C307 D721 2C5F`.

### Install

```sh
sudo apt install ./clifrd_0.1.0_amd64.deb ./clifr_0.1.0_amd64.deb      # Debian, Ubuntu: starts the service
sudo dnf install ./clifrd-0.1.0-1.x86_64.rpm ./clifr-0.1.0-1.x86_64.rpm  # RHEL, Rocky, Alma
sudo systemctl enable --now clifrd                                       # RPM: not started by itself
sudo usermod -aG clifr "$USER"                                           # optional: query without sudo
```

Then `sudo clifrd doctor` tells what the machine supports, and `clifr info`, after the first 5 minutes, what was recorded. The [installation guide](https://github.com/jlruedab/clifr/blob/v0.1.0/install.md) covers requirements, RHEL 8's eBPF privileges, upgrades and removal. The [user guide](https://github.com/jlruedab/clifr/blob/v0.1.0/userguide.md) has 13 use cases (an OOM kill, a crash, who connected to a database, …), configuration and the architecture.

### Tested on

| Distribution | Kernel | How |
|---|---|---|
| Ubuntu 26.04 | 7.0 | the development desktop, bare metal: daily use, a 7-day soak, the benchmarks |
| Ubuntu 22.04 | 5.15 | KVM virtual machine |
| Rocky Linux 8.10 | 4.18 (cgroup v1) | KVM virtual machine, SELinux enforcing |
| AlmaLinux 9.8 | 5.14 | KVM virtual machine, SELinux enforcing |

In each virtual machine the packages pass the installed-service checks, eBPF in all three program modes, the end-to-end test, the ground-truth test (43 of 43 checks), the network features and the sos plugin. The kernel needs BTF (`/sys/kernel/btf/vmlinux`). Without it clifrd falls back to the process connector and to sampling TCP connections every 30 seconds.

### What it costs

| | Desktop (Ubuntu 26.04) | Mixed server load (3 VMs, 4 days) | Busy-server benchmark |
|---|---|---|---|
| CPU | 0.35% of one core | 0.53–0.64% of one core | 1.9% of one core |
| Memory (RSS) | about 88 MiB | 79–117 MiB on average, 137 MiB at most | about 290 MiB on average, 335 MiB at most |
| Disk | about 20 MiB a day | 101–106 MiB a day | capped at 2 GB |

The busy-server benchmark is 80,000 PostgreSQL transactions a second: there clifr added about 1 µs (1–2%) of latency. The service runs with limits: low CPU weight, at most half a core, at most 768 MiB, at most 2 GB of data.

The mixed-load soak (2026-11-13 to 17) ran PostgreSQL, nginx, cron-like bursts and memory spikes in Rocky 8, Alma 9 and Ubuntu 22.04. The host interrupted it once for about 6 hours, and clifrd recovered from that unclean stop by itself. Each VM recorded about 5.6 million processes and 7.2 million TCP connections:
- no restarts, skipped samples or dropped events;
- retention deleted the oldest hours on time;
- `clifr verify` passed all 68 checkpoints in each VM against the real tools' output.

### Highlights

- **41 commands** rebuilt for a moment or a range, with the options of the real tools. Output matches what the recorded distribution's tool versions print (procps, util-linux, iproute2, sysstat, …).
- **Events, not only samples**: process starts and exits, TCP state changes, OOM kills, mounts and kernel messages arrive through eBPF as they happen. An event budget and memory guards keep a flood from taking clifrd down.
- **Bundles and sos report**: `clifrd bundle` packs a window of the recording into one tar file. The sos plugin adds it to `sos report`, and `clifr --data-dir FILE.tar` reads it on another machine.
- **Integrity**:
  - every data file's SHA-256 is logged when written, and `clifr verify --integrity` checks the recording or a bundle;
  - writes are crash-safe, damaged files are skipped with a warning, and a full disk is handled;
  - a crash shows as `crash` in `clifr last reboot`.
- **Forward-secure sealing** (optional, `clifrd seal-setup`): an HMAC chain whose key evolves after every flush. Someone who becomes root later cannot change, remove or reorder what was sealed before without `clifr verify --integrity --seal-key KEY` reporting it. The verification key is printed once and never stored on the host. See [docs/sealing.md](https://github.com/jlruedab/clifr/blob/v0.1.0/docs/sealing.md).
- **Kernel crash records** (`clifr pstore`): after a panic, the kernel's own last messages, saved in UEFI variables or ramoops, are stored at the next boot. RHEL needs one or two boot options for this; see the user guide.
- **Opt-in network features**, off by default (a default install opens no port and makes no connection):
  - `--metrics`: Prometheus metrics in Node Exporter's format;
  - `--serve`: remote queries with `clifr --host`. Every request needs a token, and TLS is required except on loopback.
- **`--redact`** masks secrets in command lines before they are stored.

### Known limitations

- **The last minutes are not queryable** until the next flush, every 5 minutes. A crash or power loss loses up to that much.
- **Open files are sampled** (every 2 minutes) and kept from their second sighting: a briefly opened file is missed.
- **Events can be lost** when a user forks, execs or connects faster than clifrd drains its buffers. Losses are counted, and range queries say so.
- **One machine for the benchmarks**, synthetic loads, and no production server yet. arm64 builds but has never run.
- **Not a security audit system**: no file reads or writes are recorded, and root can stop clifrd. Sealing makes changes to what was already recorded detectable, not prevented.
- **The recording is sensitive**: it holds command lines (which can contain passwords) and connection endpoints. It is readable by root and the `clifr` group. Use `--redact`, and add only trusted administrators to the group.

The full list is in the README's [Limitations](https://github.com/jlruedab/clifr/blob/v0.1.0/README.md#limitations).

### License

AGPL-3.0-only. The eBPF programs are GPL-2.0-only OR BSD-2-Clause, and the sos plugin is GPL-2.0-only. Contributions are signed off under the DCO ([CONTRIBUTING.md](https://github.com/jlruedab/clifr/blob/v0.1.0/CONTRIBUTING.md)).
