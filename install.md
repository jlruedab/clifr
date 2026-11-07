# clifr installation guide

This guide installs the two parts of clifr on a Linux host:

| Package | Binary | What it does |
|---|---|---|
| `clifrd` | `/usr/sbin/clifrd` | The recorder. A systemd service that records processes, TCP connections, open files, mounts and system counters into `/var/lib/clifr`. |
| `clifr` | `/usr/bin/clifr` | The command-line tool that reads the recording and prints what `ps`, `ss`, `top`, `vmstat` and some 35 other tools would have printed at a past moment. |

You need both on the host you want to record. The `clifr` package alone can also be installed on an analysis machine that reads recordings copied from other hosts (see [Centralized analysis](userguide.md#centralized-analysis) in the user guide).

Once it is installed, continue with the [user guide](userguide.md).

> clifr is a working prototype. It has been tested on one bare-metal machine for weeks and in virtual machines of the distributions below, not yet in production fleets. See the README's [Status](README.md#status).

## Contents

1. [Requirements](#1-requirements)
2. [Getting the packages](#2-getting-the-packages)
3. [Debian and Ubuntu](#3-debian-and-ubuntu)
4. [RHEL, AlmaLinux and Rocky Linux](#4-rhel-almalinux-and-rocky-linux)
5. [Installing without packages](#5-installing-without-packages)
6. [After installing](#6-after-installing)
7. [Upgrading](#7-upgrading)
8. [Uninstalling](#8-uninstalling)
9. [Troubleshooting](#9-troubleshooting)

## 1. Requirements

| | Requirement |
|---|---|
| Architecture | x86_64 (the packages). arm64 builds from source but has never been run. |
| Kernel | Linux with BTF type information, i.e. the file `/sys/kernel/btf/vmlinux` exists. That is the case on RHEL 8.2 and later, RHEL 9, Ubuntu 22.04 and later, and current Debian. |
| Distributions tested | Ubuntu 26.04 (kernel 7.0, bare metal, weeks of use), and in VMs on 2026-10-20: Rocky Linux 8.10 (kernel 4.18, SELinux enforcing), AlmaLinux 9.8 (5.14, SELinux enforcing), Ubuntu 22.04.5 (5.15). |
| systemd | Required by the packages (the recorder runs as a service). |
| glibc | 2.28 or later for `clifr` (RHEL 8 has 2.28). `clifrd` is a static binary with no library dependency. |
| Disk | By default clifrd keeps 72 hours and never more than 2 GB in `/var/lib/clifr`. A typical desktop or quiet server uses 15–25 MB per day; a server with hundreds of new connections per second about 180 MB per hour, so it reaches the 2 GB cap in about 11 hours. Both limits can be changed (see [Configuration](userguide.md#6-configuration)). |
| Memory | About 50–100 MB on a quiet machine, about 300 MB on a very busy one. The service is hard-limited to 768 MB (`MemoryMax`). |
| CPU | About 0.4% of one core on a desktop, about 2% of one core on a very busy server. The service has a low CPU weight, so the real workload always comes first. |

Check the kernel before you start:

```sh
uname -r
ls -l /sys/kernel/btf/vmlinux
```

If `/sys/kernel/btf/vmlinux` is missing, clifrd still runs but without eBPF: it falls back to the kernel's process connector for process events and to sampling every 30 seconds for TCP connections. Short-lived connections are then missed.

## 2. Getting the packages

There is no public package repository yet. Packages are built from the source tree with `packaging/build.sh`, which needs Docker (the CLI is built in a Rocky Linux 8 container so it runs on glibc 2.28):

```sh
git clone <clifr repository> clifr && cd clifr
packaging/build.sh                         # or: DOCKER="sudo docker" packaging/build.sh
ls dist/
```

`dist/` then holds four files (the version is taken from the last git commit):

```
clifr_0.1.0~git20261105.6f30dcebea9e_amd64.deb
clifrd_0.1.0~git20261105.6f30dcebea9e_amd64.deb
clifr-0.1.0-0.git20261105.6f30dcebea9e.x86_64.rpm
clifrd-0.1.0-0.git20261105.6f30dcebea9e.x86_64.rpm
```

Copy the two files for your distribution to the host.

What the packages contain:

| File | Package |
|---|---|
| `/usr/sbin/clifrd` | clifrd |
| `/usr/lib/systemd/system/clifrd.service` | clifrd |
| `/etc/clifr/clifrd.yml` (configuration, kept on upgrade) | clifrd |
| `/usr/lib/sysusers.d/clifr.conf` (creates the `clifr` group) | clifrd |
| `/usr/share/clifr/sos/clifr.py` (plugin for `sos report`) | clifrd |
| `man clifrd`, bash completion | clifrd |
| `/usr/bin/clifr`, `man clifr`, bash completion | clifr |
| `/usr/share/doc/clifr*/`: `LICENSE` (AGPL-3.0), `LICENSING.md`, `THIRD_PARTY_NOTICES`; clifrd's eBPF sources in `ebpf/` | both |

## 3. Debian and Ubuntu

Install both packages with apt, which also installs their dependencies:

```sh
sudo apt install ./clifrd_*_amd64.deb ./clifr_*_amd64.deb
```

What the installation does:

1. Creates the system group `clifr` (members may read the recording).
2. Installs the service, **enables it and starts it** (Debian's convention for services). Recording begins immediately.
3. Creates `/var/lib/clifr` (mode 0750, group `clifr`) on the first start.

If you would rather review the configuration before the recorder starts, install the packages, then stop it, edit `/etc/clifr/clifrd.yml` and start it again:

```sh
sudo systemctl stop clifrd
sudoedit /etc/clifr/clifrd.yml
sudo systemctl start clifrd
```

If you use `sos report` (`sosreport` package), the clifr plugin is found automatically; see [section 6](#sos-report-plugin).

Now [check the installation](#check-the-installation).

## 4. RHEL, AlmaLinux and Rocky Linux

Install both packages with dnf:

```sh
sudo dnf install ./clifrd-*.x86_64.rpm ./clifr-*.x86_64.rpm
```

On RPM-based distributions a newly installed service is **not** started automatically (the distribution's presets decide). Enable and start it:

```sh
sudo systemctl enable --now clifrd
```

Notes for these distributions:

- **SELinux.** clifrd runs unconfined, like other services without a policy module of their own. In the tested VMs (Rocky 8.10 and AlmaLinux 9.8, SELinux enforcing) there were no denials. To check on your host:

  ```sh
  sudo ausearch -m AVC -c clifrd     # "<no matches>" is what you want
  ```

- **RHEL 8 and eBPF privileges.** clifrd loads its eBPF programs with the capabilities CAP_BPF and CAP_PERFMON. Kernels before 5.8 do not know these capabilities and need CAP_SYS_ADMIN instead. RHEL 8.10's kernel worked with the shipped unit in the tested VM. If on your RHEL 8 host the journal shows `process events: proc_connector` instead of `process events: ebpf` (see [Check the installation](#check-the-installation)), add CAP_SYS_ADMIN with a drop-in file:

  ```sh
  sudo systemctl edit clifrd
  ```

  and enter:

  ```ini
  [Service]
  CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_SYSLOG
  ```

  then `sudo systemctl restart clifrd`.

- **systemd 239 (RHEL 8)** logs that it does not know `ProtectKernelLogs`, `ProtectClock` and `ProtectHostname` when it loads the unit. These warnings are harmless: the settings are ignored.

- **cgroup v1 (RHEL 8's default).** Supported. `clifr ... systemd-cgls` and `containers` read the process's cgroup lines as RHEL 8 writes them.

Now [check the installation](#check-the-installation).

## 5. Installing without packages

On another architecture, or to try clifr without packages, build the binaries and install them by hand. You need Go 1.25 or later (the source pins its exact toolchain, which `go` downloads by itself) and, for `clifr`, a C++ compiler (`g++`):

```sh
CGO_ENABLED=0 go build -o clifrd ./cmd/clifrd   # static recorder
go build -o clifr ./cmd/clifr                   # CLI (DuckDB, needs cgo and g++)

sudo install -m 0755 clifrd /usr/sbin/
sudo install -m 0755 clifr /usr/bin/
sudo install -D -m 0644 deploy/clifrd.yml /etc/clifr/clifrd.yml
sudo install -D -m 0644 deploy/clifr-sysusers.conf /usr/lib/sysusers.d/clifr.conf
sudo systemd-sysusers
sudo install -m 0644 deploy/clifrd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now clifrd
```

A `clifr` binary built this way needs the glibc of the machine it was built on (or later). That is why the packages build it in a Rocky Linux 8 container.

To try the recorder for a few minutes without installing anything:

```sh
sudo ./clifrd --data-dir /tmp/clifr-test --interval 5s --flush-interval 1m --duration 10m
# in another terminal, after the first flush (1 minute here):
sudo ./clifr --data-dir /tmp/clifr-test info
sudo ./clifr --data-dir /tmp/clifr-test --at "-90s" "ps aux"
```

## 6. After installing

### Check the installation

**1. What the system supports.** `clifrd doctor` loads the eBPF programs, unloads them again, reads each data source once and prints the recording level. It records nothing:

```console
$ sudo clifrd doctor
clifrd doctor: what this system supports (nothing is recorded)
  kernel           ok 7.0.0-42-generic amd64
  BTF              ok /sys/kernel/btf/vmlinux present
  privileges       ok uid 0; CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_SYS_PTRACE CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_PERFMON CAP_BPF
  process events   ok eBPF (ringbuf, fork/exec/exit tp_btf, OOM kills)
  TCP events       ok eBPF (ringbuf, fentry, state tp_btf, time-wait end exact)
  socket dumps     ok sock_diag (75 sockets now)
  fd counts        ok the size of /proc/<pid>/fd (Linux 6.2+): unchanged processes are not re-read
  process I/O      ok /proc/<pid>/io readable
  mount events     ok mountinfo readable (changes via POLLPRI)
  configuration    ok /etc/clifr/clifrd.yml valid
  data directory   ok /var/lib/clifr mode 750, owner 0:968, 388.3 GiB free
Recording level: full: process and TCP events from eBPF, samples, fd walks, keyframes
```

The last line is what matters:

| Recording level | Meaning |
|---|---|
| `full` | Everything: process and TCP events from eBPF, so even a process or connection lasting milliseconds is recorded. |
| `reduced` | Process events from eBPF or the kernel's process connector, but TCP connections only sampled every 30 s (or the reverse). Short-lived connections or processes are missed. |
| `sampling only` | No events at all: processes, sockets and files only at each 30 s sample. |

**2. The service is running.**

```console
$ systemctl status clifrd
$ journalctl -u clifrd -b --no-pager -o cat | head -4
Started clifrd.service - clifr flight recorder (processes, sockets, open files, system counters).
clifrd: 2026/11/05 09:22:47 recording to /var/lib/clifr (Parquet, flushed every 5m0s) every 30s (fd walk every 2m0s)
clifrd: 2026/11/05 09:22:47 process events: ebpf (ringbuf, fork/exec/exit tp_btf, oom)
clifrd: 2026/11/05 09:22:48 TCP: events (ringbuf, fentry, state tp_btf, time-wait end exact), keyframe every 5m0s
```

`process events: ebpf` and `TCP: events` mean full recording under the service. `doctor` runs with all of root's privileges; the journal shows what the service itself got.

**3. Data can be read.** clifrd keeps new data in memory and writes it to disk every 5 minutes, so **wait 5 minutes after the first start**, then:

```sh
sudo clifr info                      # the recording's range, size, rows
sudo clifr --at "-6m" "ps aux"       # processes 6 minutes ago
```

Until the first flush clifr answers `... is after the end of the recording (last sample ...): clifrd writes to disk every 5m0s, so the latest minutes may not be there yet`. That is expected; it is not an error. The same applies afterwards to the most recent minutes: they are on disk at the next flush.

### Let administrators use clifr without sudo

The recording contains every user's command lines, so it is readable only by root and the `clifr` group. Add trusted administrators to the group:

```sh
sudo usermod -aG clifr alice
```

The user must log in again (or run `newgrp clifr`) for the new group to apply. Then `clifr` works without `sudo`.

### sos report plugin

The clifrd package installs a plugin for `sos report` (sos 4.x). It adds a bundle of the recording to the report, so the support engineer who receives a sosreport can run clifr on it:

```sh
sudo sos report -o clifr                       # only the clifr plugin; the last 6 hours
sudo sos report                                # the full report includes it too
sudo sos report -k clifr.window=24h            # a longer window ("all": the whole recording)
sudo sos report -k clifr.start="2026-11-05 12:00" -k clifr.end="2026-11-05 13:00"
```

Inside the report the bundle is `sos_commands/clifr/clifr-bundle.tar`, beside `clifrd --version`, `clifrd doctor` and a copy of `/etc/clifr`. Plan for its size: about 175 MB per hour on a very busy server, a few MB per hour on a quiet one (Parquet files hardly compress further). With `sos report --clean` the bundle is left out, because sos's obfuscation cannot process it.

The plugin is installed as `/usr/share/clifr/sos/clifr.py` and linked into sos's plugin directory while sos is installed: clifrd and sos can be installed in either order, and removing sos removes the link (and nothing of sos's directory is left behind). Without sos, nothing is installed into sos's directory. The plugin belongs to sos's `system` profile, so a full `sos report` runs it. Unlike the rest of clifr it is licensed GPL-2.0-only, as sos is (see `LICENSING.md`).

### Configuration

Settings are in `/etc/clifr/clifrd.yml`. Every line of the shipped file shows the default, so the recorder behaves the same with an empty file. The most common changes are the retention and size cap, and the patterns that mask secrets in command lines. They are explained in the user guide's [Configuration](userguide.md#6-configuration) section. After editing:

```sh
sudo clifrd doctor | grep configuration    # checks the file
sudo systemctl restart clifrd
```

A restart starts a new *run*. Nothing is lost except what was not flushed yet; clifrd writes its buffers on a clean stop.

## 7. Upgrading

Install the newer packages the same way (`apt install ./...deb` or `dnf upgrade ./...rpm`). The service is restarted by the package. Recordings made by older versions stay readable by the newer `clifr`; a recording made by a *newer* clifrd than the `clifr` reading it is refused with a message to upgrade clifr. `/etc/clifr/clifrd.yml` is kept if you changed it (on Debian, dpkg asks when the packaged default changed too; on RPM, the new default is saved as `clifrd.yml.rpmnew`).

## 8. Uninstalling

| Command | Service | `/etc/clifr` | Recording in `/var/lib/clifr` |
|---|---|---|---|
| `sudo apt remove clifrd clifr` | stopped and disabled | kept | kept |
| `sudo apt purge clifrd clifr` | stopped and disabled | deleted | **deleted** |
| `sudo dnf remove clifrd clifr` | stopped and disabled | kept if changed (`.rpmsave`) | kept; delete by hand: `sudo rm -rf /var/lib/clifr` |

To keep a recording before purging, bundle it first:

```sh
sudo clifrd bundle -o /root/clifr-final.tar
```

The `clifr` group is left in place (systemd-sysusers groups are not removed on uninstall); remove it with `sudo groupdel clifr` if you want.

## 9. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `... is after the end of the recording (last sample ...): clifrd writes to disk every 5m0s` | The moment asked for is newer than the last flush. Wait up to 5 minutes, or ask for an earlier moment. `clifr info` prints the recording's range. |
| `nothing was recorded at ...: no samples from ... to ... (clifrd was not running)` | The moment falls in a gap: the machine was off or suspended, or the service was stopped. `clifr --since yesterday events` shows the gaps. |
| `/var/lib/clifr: permission denied (the recording is readable by root and the clifr group)` | Run with `sudo`, or add the user to the `clifr` group and log in again. |
| `ps: option --foo is not supported for recorded data (see: clifr help ps)` | clifr rebuilds each tool's output from recorded data and accepts only the options it can honour. `clifr help COMMAND` lists them. |
| `recorded by a newer clifrd (schema N) ...: update clifr` | The recording comes from a newer clifrd than this clifr. Install the matching clifr package. |
| `doctor` shows `reduced` or `sampling only` | No BTF (`/sys/kernel/btf/vmlinux`), a kernel too old for the eBPF programs, or missing privileges. On RHEL 8 see the [CAP_SYS_ADMIN drop-in](#4-rhel-almalinux-and-rocky-linux). |
| Journal: `warning: cpu budget exceeded ... fd-interval 2m0s -> 4m0s` | Normal under heavy load: the recorder spends more than its 2% budget and walks open files less often to stay within it. It goes back when the load drops. |
| Journal: `memory guard: recorder live heap ... exceeds the ... memory guard`, or the service restarted with `oom-kill` | The machine tracks far more processes, files or connections than measured so far. See the user guide on `memory_guard` and `MemoryMax`, and report it. |
| Disk fills faster than expected | `clifr info` prints the data kept per day. Lower `retention` or `max_size`. The 2 GB cap is always enforced, oldest hours first. |
| A range query prints `# events lost in this window`, or `clifr info` shows drops | The eBPF buffers overflowed under a burst of events (tens of thousands of connections per second). Short-lived processes or connections of that window may be missing; the periodic dumps correct long-lived ones. |

Logs: `journalctl -u clifrd`. Increase detail temporarily with `log_level: debug` in `/etc/clifr/clifrd.yml` and a restart. In a sosreport the same journal is under `sos_commands/logs/` and the service status under `sos_commands/systemd/`.
