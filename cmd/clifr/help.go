package main

import (
	"fmt"
	"os"
	"strings"
)

const mainHelp = `clifr shows what a Linux diagnostic command would have printed at a past
moment, using data recorded by clifrd. clifr never runs the command itself:
it rebuilds the output from the recording.

Usage:
  clifr --at TIME [OPTIONS] "COMMAND [ARGS]"
  clifr --since TIME [--until TIME] [OPTIONS] "COMMAND [ARGS]"
  clifr diff --at TIME_A --at TIME_B [OPTIONS] "COMMAND [ARGS]"
  clifr info [OPTIONS]
  clifr help COMMAND

Supported commands:
  ps, top, pstree, pidstat, lsof, ss, netstat, vmstat, mpstat, iostat, free,
  uptime, df, mount, findmnt, date, hostname, uname, last, nstat, ip, dmesg,
  systemctl, systemd-cgls, swapon, lsmod, lsblk, lslocks, ipcs, sysctl,
  slabtop, numastat, conntrack, nfsstat, mountstats
  events, life, oom, mounts, containers (clifr only: timeline, process
  lifetimes, OOM kills, mount table, containers by their cgroups)
  Run "clifr help COMMAND" to see which options are supported for recorded
  data. Unsupported options are rejected with an error.

Time:
  -a, --at TIME        a single moment
  -S, --since TIME     start of a range
  -U, --until TIME     end of a range (default: now)
  -T, --tz ZONE        time zone for TIME values and output (default: local time)

  TIME accepts "YYYY-MM-DD HH:MM:SS", "YYYY-MM-DD HH:MM", "YYYY-MM-DD",
  "HH:MM" (today), relative times ("2 hours ago", "-30m") and "yesterday",
  "today", "now". The resolved time and time zone are printed on stderr.

Range views (with --since):
  A range has no single moment, so clifr summarizes it by default.
      --summary        one report for the range; for ps and lsof one row per
                       object with first/last seen and peaks; for ss and
                       netstat one row per process (default)
      --list           ss, netstat: every TCP connection of the range, one row
                       each, with its open and close times
      --changes        ps, ss, netstat, lsof, df, mount: only what appeared,
                       disappeared or changed between consecutive samples
      --samples        full command output for every sample
  -e, --every DUR      spacing between samples for --samples
                       (rounded up to a multiple of the recording interval)
  -n, --number N       stop after N samples

Output:
  -j, --json           JSON Lines: one object per row, with its times (ts_ms,
                       sample_ts_ms, from_ms, to_ms) and "sampled", the
                       fields whose values come from a sample (others exact)
  -I, --interactive    page through samples (default when output is a terminal)
      --plain          never page, just print (default when output is piped)

Interactive keys:
  PgDn / n    next sample          PgUp / p    previous sample
  Home        first sample         End         last sample
  g           jump to a time       q           quit
  arrows, space, b: scroll within a sample
  (at g, HH:MM is on the day of the sample shown)

Sources:
  -D, --data-dir DIR   local recording directory (default /var/lib/clifr)
  -H, --host HOST      another host's recording, from its clifrd --serve
                       (HOST, HOST:PORT or https://HOST:PORT; port 8443): the
                       files the query needs are fetched (cached in
                       ~/.cache/clifr) and the query runs here
      --token TOKEN    access token for --host (or CLIFR_TOKEN; on the
                       server: clifrd token new)
      --tls-fingerprint SHA256:...  the certificate --host must have, to pin
                       it on first use without a terminal (clifrd logs it);
                       pins are kept in ~/.config/clifr/known_hosts
      --style STYLE    print free, top, df and lsof as these tools' versions do:
                       rhel-8, rhel-9, ubuntu-22.04 or current (default: the
                       recorded host's distribution; current if unknown)

Other:
  -v, --version        show version
  -h, --help           show this help

Other commands:
  clifr verify         compare real tool output saved by clifrd --verify-every
                       with the reconstruction
  clifr export TABLE   one recorded table as CSV

Environment variables:
  CLIFR_SINCE, CLIFR_UNTIL, CLIFR_TZ, CLIFR_DATA_DIR, CLIFR_STYLE,
  CLIFR_HOST, CLIFR_TOKEN, CLIFR_TLS_FINGERPRINT

Examples:
  # Processes at 02:45 this morning
  clifr --at "02:45" "ps aux"

  # Every process whose name matches cron yesterday, one row each
  clifr --since yesterday --until today "ps aux" | grep cron

  # Who talked to the database between 02:00 and 03:00
  clifr --since "2026-10-02 02:00" --until "2026-10-02 03:00" \
        "ss -tanp dst 10.0.4.21 and dport = :5432"

  # Compare listening ports before and after a deployment
  clifr diff --at "14:00" --at "14:20" "ss -ltnp"

  # Disk activity every minute between 02:00 and 02:30
  clifr --since "02:00" --until "02:30" --samples -e 1m "iostat -x"

  # What happened in the last hour: starts, exits, OOM kills, mounts, gaps
  clifr --since "1 hour ago" events

  # What the recording covers
  clifr info
`

func helpTool(name string) error {
	t, ok := tools[name]
	if !ok {
		if why := later[name]; why != "" {
			return fmt.Errorf("%s: %s", name, why)
		}
		return usageError{fmt.Errorf("%q is not a supported command (see: clifr help)", name)}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n\nUsage:\n  clifr --at TIME \"%s", t.name, t.about, t.name)
	if t.synopsis != "" {
		fmt.Fprintf(&b, " %s", t.synopsis)
	}
	fmt.Fprintf(&b, "\"\n  clifr --since TIME [--until TIME] \"%s ...\"\n", t.name)
	if len(t.opts) > 0 {
		b.WriteString("\nSupported options (any other is rejected):\n")
		for _, o := range t.opts {
			var names []string
			if o.short != 0 {
				names = append(names, "-"+string(o.short))
			}
			if o.long != "" {
				names = append(names, "--"+o.long)
			}
			n := strings.Join(names, ", ")
			switch {
			case o.optional:
				n += "[=" + o.arg + "]"
			case o.arg != "":
				n += " " + o.arg
			}
			fmt.Fprintf(&b, "  %-22s %s\n", n, o.help)
		}
	}
	if len(t.notes) > 0 {
		b.WriteString("\nNotes:\n")
		for _, n := range t.notes {
			fmt.Fprintf(&b, "  %s\n", n)
		}
	}
	if len(t.examples) > 0 {
		b.WriteString("\nExamples:\n")
		for _, e := range t.examples {
			fmt.Fprintf(&b, "  %s\n", e)
		}
	}
	_, err := os.Stdout.WriteString(b.String())
	return err
}
