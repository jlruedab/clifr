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

## Contributions

Contributions are welcome under the licenses above, each file under its own, with a Developer Certificate of Origin sign-off on every commit (`Signed-off-by:`, `git commit -s`). See [CONTRIBUTING.md](CONTRIBUTING.md).

## Trademark

The license does not grant permission to use the name "clifr" or its logo for a modified version or a different product in a way that suggests it is the original.
