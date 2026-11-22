#!/bin/bash
# bench/sarcheck.sh: record with clifrd while sysstat's own collector writes
# a daily-style file, for bench/sarcheck (run as root on the host to check).
#
#   bench/sarcheck.sh CLIFRD OUTDIR [MINUTES]
#
# Starts CLIFRD (--interval 5s) into OUTDIR/rec, then at the next full
# minute sadc -S ALL 60 into OUTDIR/sa (MINUTES + 1 records, default 13),
# with a little network and disk traffic meanwhile, then stops clifrd and
# writes OUTDIR/sar-ARGS.txt (sar ARGS -f OUTDIR/sa in the C locale) for
# each report list in OUTDIR/args (one per line), and OUTDIR/window (the
# first and last record, local time).
set -u
CLIFRD=${1:?clifrd binary}
OUT=${2:?outdir}
MIN=${3:-12}
mkdir -p "$OUT"
SADC=$(ls /usr/lib64/sa/sadc /usr/lib/sysstat/sadc 2>/dev/null | head -1)
[ -n "$SADC" ] || { echo "no sadc" >&2; exit 1; }
"$CLIFRD" --config /dev/null --data-dir "$OUT/rec" --interval 5s --sys-interval 5s --flush-interval 30s >"$OUT/clifrd.log" 2>&1 &
CPID=$!
sleep $((60 - $(date +%-S)))
date '+%Y-%m-%d %H:%M:%S' >"$OUT/window"
"$SADC" -S ALL 60 $((MIN + 1)) "$OUT/sa" &
SPID=$!
# Some traffic: a file written and read, loopback connections.
for i in $(seq 1 "$MIN"); do
	dd if=/dev/zero of="$OUT/tmpfile" bs=1M count=20 conv=fsync status=none
	cat "$OUT/tmpfile" >/dev/null
	for j in 1 2 3; do (exec 3<>/dev/tcp/127.0.0.1/22 && sleep 1) 2>/dev/null; done
	sleep 50
done
wait "$SPID"
date '+%Y-%m-%d %H:%M:%S' >>"$OUT/window"
rm -f "$OUT/tmpfile"
sleep 40 # clifrd's flush
kill "$CPID"
wait "$CPID"
sar -V >"$OUT/version.txt" 2>&1
n=0
while read -r args; do
	n=$((n + 1))
	{ echo "# sar $args"; LC_ALL=C sar $args -f "$OUT/sa"; } >"$OUT/sar-$n.txt" 2>&1
	echo "$args" >"$OUT/sar-$n.args"
done <"$OUT/args"
