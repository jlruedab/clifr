#!/bin/bash
# bench/lsipccheck.sh: capture lsipc's output beside a short clifrd
# recording, for bench/vmstatcompare.py (run as root on the host).
#
#   bench/lsipccheck.sh CLIFRD OUTDIR CMDS
#
# Creates a message queue, a shared memory segment and a semaphore set
# (ipcmk), records 90 s (--interval 5s), and 45 s in runs each line of
# CMDS (QID, MID, SID replaced by the new objects' ids) into OUTDIR/out-N.txt
# with OUTDIR/at-N.txt and OUTDIR/cmd-N.txt as bench/vmstatcheck.sh does;
# then removes the objects.
set -u
CLIFRD=${1:?clifrd binary}
OUT=${2:?outdir}
CMDS=${3:?command list}
mkdir -p "$OUT"
QID=$(ipcmk -Q | awk '{print $NF}')
MID=$(ipcmk -M 65536 | awk '{print $NF}')
SID=$(ipcmk -S 3 | awk '{print $NF}')
"$CLIFRD" --config /dev/null --data-dir "$OUT/rec" --interval 5s --sys-interval 5s --flush-interval 30s --duration 90s >"$OUT/clifrd.log" 2>&1 &
CPID=$!
sleep 75 # the sysctl limits are read once a minute
sed "s/QID/$QID/; s/MID/$MID/; s/SID/$SID/" "$CMDS" >"$OUT/cmds"
n=0
while read -r c; do
	n=$((n + 1))
	date '+%Y-%m-%d %H:%M:%S.%3N' >"$OUT/at-$n.txt"
	echo "$c" >"$OUT/cmd-$n.txt"
	LC_ALL=C $c >"$OUT/out-$n.txt" 2>&1
done <"$OUT/cmds"
wait "$CPID"
ipcrm -q "$QID" -m "$MID" -s "$SID"
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT"
