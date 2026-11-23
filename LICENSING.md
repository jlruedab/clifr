# Licensing

Copyright © 2026 Jorge L. Rueda B. <jlrueda@gmail.com>

clifr is open-source software under the GNU AGPL-3.0, with the exceptions below for the eBPF programs and the sos plugin.

## Open source: GNU AGPL-3.0

clifr (the `clifrd` recorder, the `clifr` CLI, the packaging, the documentation) is free software: you can redistribute it and/or modify it under the terms of the **GNU Affero General Public License, version 3** (SPDX: `AGPL-3.0-only`), as published by the Free Software Foundation. The full text is in [LICENSE](LICENSE).

clifr is distributed in the hope that it will be useful, but **without any warranty**; without even the implied warranty of merchantability or fitness for a particular purpose. See the license for details.

What this means in practice (a summary, not a substitute for the license):

- You may run clifr on any number of machines, for any purpose, including in a company, at no cost.
- You may study, change and redistribute it. If you distribute clifr or a modified version, you must do so under the AGPL-3.0, with the corresponding source code.
- If you modify clifr and let people interact with the modified version over a network (for example, as part of a hosted service), you must offer those users the source code of your modified version (AGPL-3.0 section 13).

## eBPF programs

The two eBPF programs that clifrd loads into the kernel, `internal/bpfproc/procevents.bpf.c` and `internal/bpftcp/tcpevents.bpf.c`, and the objects compiled from them, are licensed under **GPL-2.0-only OR BSD-2-Clause**, at your option, as is common for eBPF programs: the kernel only gives some of its helper functions to programs that declare a GPL-compatible license. Each file says so in its header.

The GPL-2.0 text is at <https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt> (and in `/usr/share/common-licenses/GPL-2` on Debian and Ubuntu). The BSD-2-Clause license of these two files:

```
Copyright (c) 2026 Jorge L. Rueda B.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

## sos report plugin

The plugin for sos report, `deploy/sos/clifr.py` (installed into sos's plugin directory by the clifrd package), is licensed under **GPL-2.0-only**, the license of sos itself: it subclasses sos's plugin classes and runs inside sos, so it is licensed as sos is (and as sos requires of its plugins). Its header says so. The GPL-2.0 text is at <https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt> (and in `/usr/share/common-licenses/GPL-2` on Debian and Ubuntu).

## Third-party code

The binaries include third-party Go modules under their own permissive licenses (MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0), all compatible with the AGPL-3.0. Their copyright and license texts are shipped with the packages in `/usr/share/doc/clifr*/THIRD_PARTY_NOTICES`.

## net-tools text in `clifr netstat -s`

`clifr netstat -s` prints each counter in the same sentence as net-tools' `netstat -s` (for example "%d incoming packets delivered"), so that its output matches the real tool word for word. Those 188 sentences and the section headings are taken from net-tools 2.10's `statistics.c` ("Copyright 1997,1999,2000 Andi Kleen. Subject to the GPL."); the code that prints them, `internal/query/netstat_stats.go`, is clifr's own. As `statistics.c` names no GPL version, section 9 of the GPL lets any version be chosen: clifr uses the sentences under the GPLv3, which may be combined with AGPL-3.0 code (section 13 of both licenses). The attribution is in `/usr/share/doc/clifr/THIRD_PARTY_NOTICES` and `packaging/notices/net-tools.txt`.

## Code derived from other projects

clifr rebuilds the output of the real tools. Where matching them needed their exact rules, parts of clifr's Go code follow those tools' own code closely: written anew in Go, but derived from it. Each part is used under a license that may be combined with the AGPL-3.0:

| clifr code | Follows | Its license | Used under |
|---|---|---|---|
| `last`, `dmesg`, `swapon`, `lsblk`, `lslocks`, `lsipc`, `lscpu`, `lsmem`, `lsns` (libsmartcols' table layout); clifrd's lock file lookup and CPU and memory block reading | util-linux 2.32 / 2.37 / 2.39 / 2.41 | GPL-2.0-or-later; libsmartcols and `mbsalign.c` LGPL-2.1-or-later; `strutils.c` public domain | GPLv3 |
| `who`, `df` (column widths) | GNU coreutils 8.32 | GPL-3.0-or-later | GPLv3 |
| `w`, `slabtop` (3.3), `ps` (STIME, %CPU), `vmstat` (reports, options, layouts); clifrd's sysctl walk | procps-ng 3.3.15 / 3.3.17 / 4.0.4 | LGPL-2.1-or-later; `sysctl.c` GPL-2.0-or-later | GPLv3 |
| `numastat` | numactl 2.0.19 `numastat.c` | LGPL-2.1 (section 3 allows the GPL) | GPLv3 |
| `nfsstat` | nfs-utils `nfsstat.c` | GPL-2.0-or-later | GPLv3 |
| `systemctl list-units`, `systemd-cgls` (command lines) | systemd | LGPL-2.1-or-later | GPLv3 |
| `ip link`/`address`/`route`, `nstat` | iproute2 | GPL-2.0-or-later | GPLv3 |
| `conntrack -S` (counter names) | conntrack-tools | GPL-2.0-or-later | GPLv3 |
| `atop` (value formats, line layout) | atop 2.7.1 / 2.10.0 / 2.12.1 | GPL-2.0-or-later | GPLv3 |
| `iotop` (sizes, layout, sort, command); clifrd's I/O priorities | iotop 0.6 (Python) | GPL-2.0-or-later | GPLv3 |
| `sar` (report layouts, values, averages, header repeats), `iostat` (reports, options) | sysstat 11.7.3 / 12.5 / 12.6.1 / 12.7.7 | GPL-2.0-or-later | GPLv3 |
| `htop` (meters, layout, column formats, sort, tree); 3.0.5's screen is from its output only (GPL-2.0-only) | htop 3.2.1 / 3.3.0 / 3.4.1 | GPL-2.0-or-later | GPLv3 |
| `netstat -s` (sentences; section above) | net-tools 2.10 | GPL, no version named | GPLv3 |

Section 13 of the GPLv3 and of the AGPLv3 allows such code to be combined with AGPL-3.0 code; the LGPL-2.1's section 3 allows its code to be used under the GPL. The copyright notices and what was taken from each file are in `packaging/notices/` and in `/usr/share/doc/clifr*/THIRD_PARTY_NOTICES`; each Go file with such code says so at its top.

`clifr mountstats` is not derived from nfs-utils' `mountstats.py`, which is licensed GPL-2.0-only: an earlier port of it was replaced on 2026-11-21 by code written clean-room, from a specification of the real tool's observable behaviour and its output on known input only (`internal/query/testdata/mountstats/SPEC.md`). Its output sentences are the real tool's, as they must be to match it.

`kernfsHash` (`internal/query/cgls.go`, also used by `lsmod`) computes the Linux kernel's `kernfs_name_hash` (GPL-2.0), so that cgroups and module users are listed in the kernel's order: a short arithmetic formula, reimplemented for interoperability, with no other way to express it.

## Contributions

Contributions are welcome under the licenses above, each file under its own, with a Developer Certificate of Origin sign-off on every commit (`Signed-off-by:`, `git commit -s`). See [CONTRIBUTING.md](CONTRIBUTING.md).

## Trademark

The license does not grant permission to use the name "clifr" or its logo for a modified version or a different product in a way that suggests it is the original.
