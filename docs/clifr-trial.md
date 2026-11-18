# clifr production trial

[Español](clifr-trial-es.md)

`clifr-trial` collects the evidence that shows whether clifr can run on a real
production server: what it costs, whether it stays up, and whether what it
records is right. You install it once and leave it running for 2 to 4 weeks.
At the end it writes one anonymized `.tar.gz` report with a `SUMMARY.txt` that
ends in **PASSED**, **FAILED** or **INCOMPLETE**.

It is one file, `bench/clifr-trial` in this repository.

## Why a script that runs for weeks

clifrd keeps only the last 72 hours of data, so a check run at the end could
not see the first weeks. `clifr-trial` takes a small sample every hour (a
systemd timer) and writes the report from those samples at the end.

It only reads. The one exception is the drill, which you start yourself (see
below), and it is harmless.

## Requirements

- clifrd and clifr installed (the `clifrd` and `clifr` packages) and running.
- root, systemd.
- Python 3.6 or newer. On RHEL 8, the system's `/usr/libexec/platform-python`
  is enough: nothing to install.

## Steps

Run every command as root.

```sh
# 1. Download the script and start the trial
curl -O https://raw.githubusercontent.com/jlruedab/clifr/master/bench/clifr-trial
sudo sh clifr-trial start

# 2. Once, on a normal day: the drill
sudo clifr-trial drill

# 3. Now and then: how it is going
sudo clifr-trial status

# 4. After 2 to 4 weeks: the report to send back
sudo clifr-trial report
```

`start` copies the script to `/usr/local/sbin/clifr-trial`, so the downloaded
file can be deleted. It installs the `clifr-trial.timer` timer, records the
server's details and takes the first sample (a minute or two).

During the trial, please answer the questions in
`/var/lib/clifr-trial/QUESTIONS.txt` (workload, any effect you noticed, whether
clifr answered a real question, whether you would keep it). The file goes into
the report.

For the trial to be complete, the server should go through, while it runs:

- a reboot,
- a kernel or OS update,
- a clifrd upgrade (a newer package, if one is released).

Leave those to your normal maintenance. The report says which ones happened.

## What is collected

**Every hour** (the timer, at low priority: `Nice=19`, idle I/O, at most 2 GB
of memory):

- clifrd: CPU used, memory (current and peak), restarts, and whether it is
  running;
- the recording: size on disk and number of files, free space;
- the server: CPU use, load, available memory, pressure (PSI) where the kernel
  has it;
- the boot, the kernel and clifrd's version, to see reboots, updates and
  upgrades;
- clifrd's journal.

**Every 6 hours, an accuracy spot check:** the script saves what the real
`ps`, `ss` and `mount` show at that moment. Ten minutes or more later it asks
clifr to rebuild the same moment and compares the two: processes, listening
sockets, established TCP connections and mounts.

**Every day:** `clifr info` (cost, losses, guard events), `clifr verify
--integrity` (no damaged data files) and the guard events, gaps and skipped
samples.

Everything is kept in `/var/lib/clifr-trial` (root only).

## The drill

`sudo clifr-trial drill` makes a few planned events at a known time, so the
report can show that clifr recorded them. It runs in the background for about
11 minutes and does not touch any application:

- a short job (`sleep 2`, exit code 3);
- a TCP connection to itself on 127.0.0.1 (a listener and one connection);
- a file held open;
- a 1 MiB tmpfs mounted at `/run/clifr-trial-drill`, unmounted at the end.

If even that mount is not acceptable: `sudo clifr-trial drill --no-mount`.

A day later the hourly sample asks clifr about each event, as you would
during an incident, and records whether each was found. That check must happen
within the 72 hours clifrd keeps, which the timer does automatically.

There is no OOM kill and nothing that uses much CPU, memory or disk.

## The report

`sudo clifr-trial report` runs the checks once more and writes
`clifr-trial-YYYYMMDD-HHMM.tar.gz` in the current directory (`--out DIR` for
another one). It holds:

| File | Content |
|---|---|
| `SUMMARY.txt` | the verdicts, cost per day, the latest `clifr info`, guard events, journal summary, drills |
| `hourly.csv` | the hourly samples (numbers) |
| `accuracy.csv` | the spot checks (counts: matches, missing, extra) |
| `daily.jsonl` | the daily checks |
| `drills.jsonl` | the drills and their results (found / not found) |
| `baseline.json` | the server: distribution, kernel, CPUs, memory, other agents running, eBPF programs |
| `journal-summary.txt` | clifrd's journal, line kinds and counts only |
| `doctor.txt` | `clifrd doctor`: what the kernel supports |
| `QUESTIONS.txt` | your answers |

### Verdicts

| Verdict | Passes when |
|---|---|
| duration | 14 days or more |
| evidence coverage | at least 90% of the hours have a sample |
| no unplanned clifrd stop | no crash, OOM kill or failure in the journal |
| clifrd running at every sample | never found stopped |
| went through a reboot / a kernel or OS update / a clifrd upgrade | it happened during the trial |
| CPU within 2% of one core | on average and on every day |
| memory below the unit's limit | peak below 90% of `MemoryMax` (768 MiB) |
| disk within max_size | the recording stayed within `max_size` (2 GB) |
| retention | the recording holds the configured 72 hours, no more |
| no lost events | no events dropped by any source |
| gaps only at reboots and upgrades | no unexplained holes in the recording |
| integrity of the data files | no damaged files |
| accuracy spot checks | processes and mounts: at least 99.5% match; listeners: at most 1 (or 1%) differ; connections: at least 95% |
| drill reconstructed a day later | every drill event found |

**PASS** and **FAIL** are results. **NOT MET** means the trial did not
cover it (for example, no reboot happened), and **NO DATA** means nothing
was collected for it. The summary says **PASSED** only when every verdict
passes, **FAILED** when one fails, and **INCOMPLETE** otherwise.

## Privacy

The report holds numbers, verdicts and clifr's own words only. It has no host
name, IP or MAC address, machine or boot id, user name, command line, path,
port or time zone.

- Nothing that identifies the server is stored in the report's tables: the
  spot checks and drills keep counts and found / not found, never process
  names or addresses.
- Every file passes through a sanitizer. It replaces the host's names, every
  IP and MAC address, machine and boot ids, the user names of `/etc/passwd`,
  email addresses and `password=…`-style values. Times are in UTC.
- Free-text lines (the journal, error messages) keep only words that appear in
  clifr's own programs. Paths, quoted text, numbers and every other word
  (process, user and mount names) are replaced with `PATH`, `Q`, `N` or `X`.
- A last scan looks for all of the above again. If anything is still there,
  the report is **not written**, and the message names only the kind of data,
  not the data.

`QUESTIONS.txt` is your own text: it is sanitized too, but read it once more
before sending. You can always look inside the report first:

```sh
tar -xzf clifr-trial-*.tar.gz
```

The details of any accuracy mismatch (which process, which address) stay on
the server in `/var/lib/clifr-trial/accuracy-details.jsonl`, for you to look
at. Nothing is sent anywhere: you send the report yourself.

## Removing it

```sh
sudo clifr-trial stop              # removes the timer; the collected data stay
sudo rm -r /var/lib/clifr-trial    # when the report has been sent
sudo rm /usr/local/sbin/clifr-trial
```

`clifr-trial` does not change clifrd or its configuration: removing it leaves
clifr as it was.

## Known limits

- There is no baseline from before clifrd was installed. `QUESTIONS.txt` asks
  for your monitoring's numbers from the week before, if you have them.
- On RHEL 8, clifrd needs `CAP_SYS_ADMIN` for eBPF; without it, it records
  process events through the kernel's proc connector. The report shows which
  mode was used.
- The accuracy spot checks compare a moment, not the whole trial: about 4 a
  day, so about 100 in 4 weeks.
