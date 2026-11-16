# Forward-secure sealing of the integrity log (proposal)

Status: approved 2026-11-16 (decisions D1-D7 below, all as recommended;
sealing ships in v0.1.0). Implementation in progress on the `integrity` branch.

## The problem

The integrity branch gives every data file a line `SHA256 SIZE PATH` in
`/var/lib/clifr/integrity/DAY.log`, and `clifr verify --integrity` checks the
files against it. That catches corruption (torn writes, bad disks, broken
copies), not tampering: the checksums carry no key, so anyone who can write
`/var/lib/clifr` (root; clifrd runs as root) can change a Parquet file and its
log line, or delete both, and verify still passes.

## Goal and threat model

An attacker who becomes root on the recorded host at time **C** must not be
able to change, remove or reorder what clifrd wrote and sealed **before C**
without `clifr verify --integrity --seal-key KEY` saying so. They can still:

- change or drop anything written after the last seal before C: at most one
  sealing period (**D2**, proposed: one flush, 5 minutes by default), the same
  amount a crash loses today;
- stop clifrd, or make it record lies from C on;
- delete the whole recording, or cut off its end (the newest seals). Cutting
  the end is visible only against an anchor kept elsewhere (see *Anchors*);
- delete it all, data and logs: then there is nothing to verify.

Sealing proves that records were not changed after they were sealed. It does
not prove they were true when written: a kernel rootkit installed before the
recording can hide processes from /proc and from eBPF alike.

It is not a signature either. The verification key can also create seals, so
whoever holds it must be trusted (the analysis side: the admin, sos-vault).
Non-repudiation would need forward-secure public-key signatures, which are not
in Go's standard library; out of scope.

## How it works

The scheme is a hash-chain key with MACs, the same idea as journald's Forward
Secure Sealing, built from Go's standard library only (`crypto/hmac`,
`crypto/sha256`, `crypto/rand`): no new dependency.

**Keys.** At setup clifrd draws a random 32-byte seed **k0**: that is the
verification key. Every epoch's key comes from the previous one through a
one-way step:

    k(i+1) = HMAC-SHA256(k(i), "clifr seal evolve")
    mac(i) = HMAC-SHA256(k(i), "clifr seal mac")

clifrd keeps only the current **k(i)** on the host. After it seals epoch i it
stores k(i+1) and erases k(i). From k(i) nobody can compute k(i-1), so an
attacker who reads the key at C cannot make valid seals for earlier epochs.
The verifier, holding k0, computes any k(i): a year of 5-minute epochs is
about 105,000 HMACs, a fraction of a second.

**Epochs (D2).** One epoch is one flush: clifrd seals right after each flush
makes its files and log lines durable. That needs no timer of its own, and
what a seal protects lines up with what is on disk. With the default
`flush: 5m`, an attacker can change at most the last 5 minutes. An early
flush (OOM, a kernel warning) seals too.

**Removal lines.** Today the log records only files written. A verifier with
a key must also tell a file deleted by clifrd from one deleted by an attacker.
So each removal the store makes gets a line too:

    del compacted PATH    # flush parts merged into the hour file
    del retention PATH    # older than --retention (also another run's old
                          # open file, and a day's integrity log)
    del size-cap PATH     # the --max-size cap
    del disk-full PATH    # the oldest hour, removed when the disk is full
    del closed PATH       # the run's open file, when nothing is open any more

**Seal lines.** At the end of each epoch clifrd appends:

    seal KEYID EPOCH TIME_MS RUN FLAG LINES PREVTAG TAG

    TAG = HMAC-SHA256(mac(EPOCH), KEYID | EPOCH | TIME_MS | RUN | FLAG | LINES |
                      PREVTAG | SHA-256 of every log line written since the last seal)

FLAG is `-` for a flush, `start` for a run's first seal, `end` for a clean
stop, `late` for lines a crash left unsealed, sealed when the next run starts
(before anything else), and `day` for the lines of a UTC day, sealed into
that day's log before the next day's log begins: each day's log then verifies
on its own, which retention and bundles need.

Each seal covers its epoch's lines and, through PREVTAG, the whole chain
before it. The lines are hashed in the order written across the day files (an
epoch can straddle midnight UTC). Both new line kinds start with a word, not a
64-digit hash, so readers built before them skip them: old clifr versions
still read new recordings.

**Key state on disk.** The key state is `integrity/seal.state` (0600, root):
the epoch, k(i), the last tag and the key id, in one of two fixed-size slots
with a checksum. A seal writes the new key into the other slot, fsyncs it,
then overwrites the old slot with blanks and fsyncs again: a torn write leaves
the old slot valid, and the old key is overwritten in place rather than left
behind in a renamed-away file. The seal line is made durable before the key
changes; a crash between the two is finished at the next start.

On flash storage and copy-on-write file systems (btrfs, ZFS), and with
journaling of data, an overwritten block may survive somewhere on the device.
Erasure is best effort, as it is for journald. The docs must say so.

**Backups and snapshots.** A copy of `seal.state` taken at time T holds that
moment's key: whoever has the backup or VM snapshot can forge seals from T on,
and restoring it brings the old key back (the chain then repeats epochs; an
anchor kept elsewhere shows it). Exclude `integrity/seal.state` from backups
and snapshots, or accept that their age bounds the protection. A reboot needs
nothing: clifrd keeps sealing with the key on disk; a clean stop ends with an
`end` seal, the next start begins with `start`, a crash with a `late` seal.

## Setup and the verification key (D1)

Sealing begins only when an admin runs:

    sudo clifrd seal-setup

That command:

1. writes `seal.state` with k1 = evolve(k0) and a key id (the first 8 hex digits of
   SHA-256(k0), so clifr can match keys and recordings);
2. prints the verification key once, with the host name, machine id and
   time, for the admin to store **off the host** (a password manager, the
   sos-vault host's key store);
3. never writes k0 anywhere else.

The running clifrd notices `seal.state` at its next flush and starts sealing.
No restart is needed.

A key printed once and lost cannot be shown again. `seal-setup --new` then
starts a new chain with a new key: the old chain stays verifiable with the
old key.

This is how journald does it (`journalctl --setup-keys`). The alternative,
generating the key at package install, would leave the verification key on
every host or in a package log, where root can read it, so sealing would prove
nothing.

**D1:** sealing opt-in through `seal-setup` (recommended), or on at install with
the key left in a file and a warning until it is moved off the host.

## Restarts and crashes

- **Clean stop.** clifrd seals the last epoch with flag `end`. The next run's
  first seal has flag `start`, so the chain goes on across restarts.
- **Crash.** Log lines written after the last seal are sealed at the next
  start, marked `late`. A torn last line is ended first, so the next line is
  not glued to it. The verifier reports them as written before a crash
  and sealed at the restart. Anyone with root between the crash and the
  restart could have changed them.
- **Lost or damaged `seal.state`** (disk, a restore). clifrd records
  `unsealed state-missing` (or `state-damaged`) in the log and warns in the journal and in `clifr
  info` until `seal-setup --new` runs. It never starts a new chain on its own.

## Verifying

    clifr verify --integrity --seal-key KEY [--seal-key KEY2 ...]

The key can be given as a string or `@FILE`. The command then:

1. **Walks the chain.** It recomputes every TAG with k(EPOCH) from the key
   whose id matches.
   - The first bad tag, or a missing epoch number, means log lines were
     changed, added or removed: it names the epoch and its time.
   - A chain that starts later than the recording's own retention would
     explain is flagged. The run's `retention` comes from meta, which is
     itself sealed.
2. **Checks each file against the last sealed line for it.**
   - A different SHA-256 means the file was modified.
   - A sealed file with no `del` line that is missing means it was deleted.
   - A file with no sealed line at all is unsealed: written before setup,
     after the last seal, or not by clifrd.
3. **Judges the removals.** An `expired retention` removal of a file younger
   than the retention is reported, and so is `compacted` into an hour file
   that does not exist.
4. **Reports the edges.** It gives the time of the first and last seal, the
   restarts, late seals, the lines after the last seal, and the unsealed
   stretches.

Without `--seal-key` it is today's corruption check, plus a line saying the
recording is sealed but was not verified.

`clifr info` shows the sealing state: off, or on since T, with the last seal,
the epoch and the key id.

## Bundles (D5)

`clifrd bundle` also packs the integrity logs: the days of the window plus the
next day, since an hour's file is compacted, and logged, after it ends.
`clifr --data-dir FILE.tar verify --integrity --seal-key KEY` then checks the
bundle's files the same way.

- Sealed files left out of the window are reported as **not in the bundle**,
  not as deleted.
- A chain segment can be verified from any seal on: each tag covers the tag
  before it, and k(EPOCH) comes from k0.
- sos reports carry the bundle, so sos-vault can verify a host's recording
  with the key stored for that host.

Signed bundles (proving which host made a bundle) remain a separate, deferred
item.

## Anchors against cutting off the end (D4)

A seal cannot show that later seals are missing. clifrd can write the newest
epoch and the first 16 hex digits of its tag to the journal:

    clifrd: seal anchor 4ccb1d4b/1234:9f2c1a7e5b3d0c11 (where the journal is copied ...)

(key id / epoch : the first 16 hex digits of the tag; the first seal of each
run, then at most hourly.)

**Proposal:** do this once an hour, at info level. Where the journal or syslog
is forwarded to another machine (common on managed servers), that copy is an
anchor the host's root cannot reach. clifr opens no connection, so the
network rule holds.

`clifr verify --seal-anchor KEYID/EPOCH:TAG` then checks that the recording still
reaches that seal.

## Cost

Per flush, the cost is one HMAC over a few KB of log lines, one 100-byte
in-place write and one fsync of `seal.state`. That fsync comes on top of the
log's own, which already happens once a flush. The CPU cost is not measurable
against the 5-minute flush.

The verifier hashes every file, as `--integrity` already does, plus the
chain: negligible.

Disk: one seal line (~200 B) per flush, plus one `del` line per removed file.
Roughly 60 KB a day.

## Decisions (taken 2026-11-16)

- **D1**: setup is opt-in via `clifrd seal-setup`, the key printed once and
  never stored. **Taken.**
- **D2**: epoch = one flush, i.e. 5 min by default. **Taken.**
- **D3**: when `seal.state` is lost, clifrd records `unsealed` and warns until
  a new setup. **Taken.**
- **D4**: hourly anchors to the journal. **Taken.**
- **D5**: bundles carry the integrity logs. **Taken.**
- **D6**: a MAC chain is authentication, not encryption, so it fits the "no
  encryption" rule. It is still a new security feature: add a line to the hard
  constraints in CLAUDE.md. **Taken.**
- **D7**: v0.1.0 ships with sealing (the release moves by about two days).
  **Taken.**

## Work and tests (after approval)

1. **`pqstore`:** `del` lines; `seal.state` (two slots); seals at flush, stop
   and start; `late` seals and the `unsealed` marker.
2. **`clifrd seal-setup [--new]`** and the hourly anchor.
3. **`clifr verify --integrity --seal-key/--seal-anchor`**; `clifr info`.
4. **Bundles:** pack the logs; verify a bundle.
5. **Tests:** one tamper scenario each, all of which must be found:
   - a file edited;
   - a log line edited;
   - a file deleted with its lines;
   - a seal removed;
   - epochs reordered;
   - `seal.state` replaced with an older copy;
   - the start cut beyond the retention;
   - the end cut against an anchor.

   Plus a clean run with retention and compaction that reports nothing, a
   crash with a late seal, and a restart.
6. **Docs:** README "Integrity", install.md (setup and keeping the key),
   userguide.md (verify), the man pages.
7. **VMs, after the soak:** a run with `--retention 2h`, a restart, a kernel
   panic, then verify with the key.
