# clifr mountstats: clean-room specification

Written 2026-11-21 for a clean-room reimplementation of `clifr mountstats`.

## Why

clifr's first `mountstats` was ported from nfs-utils' `mountstats.py`. That file is
licensed GPL-2.0-only, which cannot be combined with clifr's AGPL-3.0 code. The
replacement is written by someone who has not read `mountstats.py`. It is written from:

- this specification;
- the kernel's `/proc/self/mountstats` format;
- the real tool's output on known input (the golden files here).

## Rules for the implementer

Do not read any of these:

- `mountstats.py`, or any other nfs-utils source code, from any source (the web, a package,
  a pip cache, your memory of it);
- clifr's previous `internal/query/mountstats.go` and `internal/query/mountstats_test.go`,
  their git history (`git log -p`, `git show`, blame) and anything quoting them.

The previous files are removed from the working tree before you start.

Everything else in the repository may be read, for example `CLAUDE.md`, `internal/query/`'s
other tools, `internal/recorder/nfs.go`, `internal/store`, `internal/testrec`,
`cmd/clifr/tools3.go` and `internal/verify/tools.go`. Treat the golden output as a black box:
work every number out from the input and output pairs. Do not look up how the real tool
computes them.

## What clifr records (the input)

clifrd reads the host's `/proc/self/mountstats` every minute. It keeps only the sections of
NFS mounts, as `internal/recorder/nfs.go` does:

- A section starts at a line whose first word is `device` and that has at least 8 words. It is
  kept when the 8th word (the fstype) is `nfs` or `nfs4`.
- Every non-empty line of a kept section is stored with leading and trailing white space removed.
  The key is `MOUNTPOINT N`, where MOUNTPOINT is the 5th word of the device line and N counts
  from 0.

`query.FileAt(db, "mountstats", t)` returns these lines in file order. ok=false means the
source was not recorded by then.

Kernel lines in a section (whitespace-trimmed as stored). See the `input-*.txt` files for real
examples from kernels 4.18, 5.14 and 5.15:

```
device SERVER:/PATH mounted on MOUNTPOINT with fstype nfs|nfs4 statvers=1.1
opts:	OPTION,OPTION,...
age:	SECONDS since mount
impl_id:	...                      (some NFSv4.1+ mounts)
caps:	caps=0x..,wtmult=..,...
nfsv4:	bm0=0x..,...                  (NFSv4 only)
sec:	flavor=N,pseudoflavor=N
events:	27 counters
bytes:	8 counters
fsc:	...                          (only with fscache)
RPC iostats version: 1.1  p/v: PROG/VERS (nfs)
xprt:	PROTO counters...             (tcp, udp or rdma; the number of counters depends on the kernel)
per-op statistics
OPNAME: N N N N N N N N [N]       (one line per operation of that NFS version, in the kernel's order)
```

## The interface to implement

Write a new `internal/query/mountstats.go` with:

```go
// NFSMount is one recorded NFS mount; you design its fields. They are
// printed by clifr's --json (snake_case JSON tags).
type NFSMount struct { ... }

// MountstatsAt returns the NFS mounts as clifrd last read them at or before t,
// in file order. When the source was not recorded:
// fmt.Errorf("mountstats: not recorded at %s (recorded since schema 9)", FormatMS(t)).
func MountstatsAt(db *store.DB, t int64) ([]NFSMount, error)

type MountstatsOptions struct {
	NFS, RPC, Xprt, Raw bool     // -n, -r, -x, -R (at most one; clifr checks)
	MountPoints         []string // the MOUNTPOINT arguments
	V233                bool     // nfs-utils 2.3.3's layout (RHEL 8)
}

// PrintMountstats prints what the real tool prints to stdout; it returns
// false where the real tool exits with status 1.
func PrintMountstats(w io.Writer, mounts []NFSMount, o MountstatsOptions) bool
```

Change the two callers to these signatures:

- `cmd/clifr/tools3.go`: `mountstatsTool`. When the result is false, return an error that makes
  clifr exit with status 1 after printing. Check how other tools do this.
- `internal/verify/tools.go`: `compareNFS`.

`MountstatsAt` no longer takes the third argument; its callers pass the style only to
`PrintMountstats`.

## The golden files (authoritative)

Captured 2026-11-21 in the KVM test VMs by `capture.sh` (loopback NFS, NFSv3 and NFSv4.2 mounts,
some I/O) and `run.sh`:

- `input-rocky8.txt`, `input-alma9.txt`, `input-ubuntu2204.txt`: the whole real
  `/proc/self/mountstats` of each VM (kernels 4.18, 5.14, 5.15).
- `input-big1.txt`, `input-big2.txt`: copies of the real ones, transformed:
  - the age is set to multi-day values;
  - the events, bytes and per-op counters are multiplied (big1: ×7+3, big2: ×1000003).

  The real tool was run on these too.
- `input-nonfs.txt`: a file without NFS mounts.
- `golden-2.3.3.txt`: nfs-utils 2.3.3's `mountstats -f INPUT OPTS` (Rocky 8.10). This is the
  `V233` layout.
- `golden-2.5.4.txt`: nfs-utils 2.5.4's (Alma 9.8). nfs-utils 2.6.1's (Ubuntu 22.04) was byte
  for byte the same, so it is not kept separately. This is the default layout.

Each golden file is a list of cases:

```
=== INPUT <name without "input-"> | OPTS <options, may be empty>
--- rc <exit status>
--- stdout
<exact stdout>
--- stderr
<exact stderr: empty in every case>
```

The options are `""`, `-n`, `-r`, `-x`, `-R`, `/mnt/v3`, `-n /mnt/v42`, `-x /mnt/v3` and
`/mnt/none`.

## Acceptance

- A test (new `internal/query/mountstats_test.go`) reads both golden files. For each case it does
  three things:
  1. turns the input file into recorded rows exactly as the recorder would (section above);
  2. loads them with `testrec.Open` as `store.SnapshotRow{TS, Source: "mountstats", Key, Pos,
     Full: true, Line}` (see other tests in `internal/query` that use `testrec`);
  3. runs `MountstatsAt` and `PrintMountstats`, then compares stdout byte for byte and
     `rc == 0` with the return value.

  All 108 cases must pass.
- `gofmt`, `go vet ./...` and `go test ./...` pass. No new dependencies.
- Comments describe the output's rules as you found them in the goldens, not as any other
  program implements them.
