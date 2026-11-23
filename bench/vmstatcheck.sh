#!/bin/bash
# bench/vmstatcheck.sh: capture vmstat's and iostat's reports beside a short
# clifrd recording, for bench/vmstatcompare.sh (run as root on the host).
#
#   bench/vmstatcheck.sh CLIFRD OUTDIR
#
# Records 90 s (--interval 5s --sys-interval 5s), and 45 s in runs each
# command in OUTDIR/cmds (one per line, default list below) into
# OUTDIR/out-N.txt, with the time just before in OUTDIR/at-N.txt
# (YYYY-MM-DD HH:MM:SS.mmm) and the command in OUTDIR/cmd-N.txt.
set -u
CLIFRD=${1:?clifrd binary}
OUT=${2:?outdir}
mkdir -p "$OUT"
[ -s "$OUT/cmds" ] || cat >"$OUT/cmds" <<'L'
vmstat
vmstat -a
vmstat -w
vmstat -a -w
vmstat -t
vmstat -S M
vmstat -S k
vmstat -s
vmstat -s -S M
vmstat -f
vmstat -d
vmstat -d -w
vmstat -D
vmstat -m
iostat
iostat -k
iostat -m
iostat -c
iostat -d
iostat -z
iostat -x
iostat -xz
iostat -N
iostat -dmN
iostat -t
iostat -s
iostat -xs
L
"$CLIFRD" --config /dev/null --data-dir "$OUT/rec" --interval 5s --sys-interval 5s --flush-interval 30s --duration 90s >"$OUT/clifrd.log" 2>&1 &
CPID=$!
sleep 45
# A partition with I/O for -p: the first one in diskstats with reads.
P=$(awk '$4 > 0 && $3 ~ /[0-9]$/ && $3 !~ /^(loop|ram|dm-|sr|md)/ {print $3; exit}' /proc/diskstats)
[ -n "$P" ] && grep -qx "vmstat -p $P" "$OUT/cmds" || { [ -n "$P" ] && echo "vmstat -p $P" >>"$OUT/cmds"; }
n=0
while read -r c; do
	n=$((n + 1))
	date '+%Y-%m-%d %H:%M:%S.%3N' >"$OUT/at-$n.txt"
	echo "$c" >"$OUT/cmd-$n.txt"
	LC_ALL=C $c >"$OUT/out-$n.txt" 2>&1
done <"$OUT/cmds"
wait "$CPID"
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT"
