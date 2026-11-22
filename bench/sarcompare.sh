#!/bin/bash
# bench/sarcompare.sh: compare the sar outputs of bench/sarcheck.sh with
# clifr's sar over the same minutes: CLIFR OUTDIR [TZ].
set -u
CLIFR=${1:?clifr binary}
OUT=${2:?outdir}
[ -n "${3:-}" ] && export TZ=$3
CHECK=$(mktemp -d)
(cd "$(dirname "$0")/.." && go build -o "$CHECK/sarcheck" ./bench/sarcheck) || exit 2
from=$(sed -n 1p "$OUT/window" | cut -c1-16) # the minute: sadc may start a second late
until=$(date -d "$(sed -n 2p "$OUT/window") 30 seconds" "+%Y-%m-%d %H:%M:%S") # its sample is seconds after the minute
rc=0
for a in "$OUT"/sar-*.args; do
	n=$(basename "$a" .args)
	args=$(cat "$a")
	"$CLIFR" --data-dir "$OUT/rec" --since "$from" --until "$until" "sar $args -i 60" >"$OUT/$n.clifr" 2>"$OUT/$n.clifr.err" ||
		{ echo "$n: clifr failed: $(tail -1 "$OUT/$n.clifr.err")"; rc=1; continue; }
	echo "== sar $args"
	"$CHECK/sarcheck" "$OUT/$n.txt" "$OUT/$n.clifr" || rc=1
done
rm -rf "${CHECK:?}"
exit $rc
