#!/bin/bash
# bench/htopcompare.sh: compare the captures of bench/htopcheck.sh with
# clifr's htop: CLIFR OUTDIR [TZ]. Prints bench/htopcheck's report per capture.
set -u
CLIFR=${1:?clifr binary}
OUT=${2:?outdir}
CHECK=$(mktemp -d)
(cd "$(dirname "$0")/.." && go build -o "$CHECK/htopcheck" ./bench/htopcheck) || exit 2
rc=0
for t in "$OUT"/*.time; do
	name=$(basename "$t" .time)
	[ -n "${3:-}" ] && export TZ=$3
	COLUMNS=$(cat "$OUT/$name.cols") "$CLIFR" --data-dir "$OUT/rec" --at "$(cat "$t")" "htop $(cat "$OUT/$name.args")" \
		>"$OUT/$name.clifr" 2>"$OUT/$name.clifr.err" || { echo "$name: clifr failed: $(tail -1 "$OUT/$name.clifr.err")"; rc=1; continue; }
	echo "== $name (htop $(cat "$OUT/$name.args"))"
	"$CHECK/htopcheck" "$OUT/$name.txt" "$OUT/$name.clifr" || rc=1
done
rm -rf "${CHECK:?}"
exit $rc
