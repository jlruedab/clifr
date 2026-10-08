#!/usr/bin/env bash
# Runs the measured workload (pgbench) and writes its results.
#
#   bench/workload.sh OUTDIR SECONDS [CLIENTS] [THREADS]
#
# Environment:
#   PGB_MODE  select (default): read-only (pgbench -S), database cached in memory
#             tpcb: the TPC-B-like read/write default script
#   PGB_RATE  target transactions/s (pgbench -R); 0 = as fast as possible.
#             Default 30000. With a target rate, the recorder's impact shows as
#             latency (which includes schedule lag, so stalls are counted) and
#             as a shortfall from the target.
#
# Outputs in OUTDIR:
#   pgbench.out         pgbench's own output (progress every 5 s)
#   pgbench_log.*.gz    per-transaction latency log (sampled, ~100,000 lines)
#   (written to /dev/shm during the run, copied to OUTDIR afterwards)
#   workload.csv        tps,lat_avg_ms,lat_p50_ms,lat_p95_ms,lat_p99_ms,lat_p999_ms,transactions,failed,latency_samples
#
# pgbench runs as the postgres user; run this script as root. The caller
# decides which cgroup/scope it runs in.
set -euo pipefail
OUT=$1 SECS=$2 CLIENTS=${3:-16} THREADS=${4:-4}
PGB_MODE=${PGB_MODE:-select} PGB_RATE=${PGB_RATE:-30000}
BIN=$(cd "$(dirname "$0")" && pwd)/bin
case $PGB_MODE in
select) script=-S ;;
tpcb) script= ;;
*) echo "PGB_MODE must be select or tpcb" >&2; exit 2 ;;
esac
rate=()
((PGB_RATE > 0)) && rate=(-R "$PGB_RATE")
# Log about 100,000 transactions (enough for p99.9), at most 5% of them.
expected=$((PGB_RATE > 0 ? PGB_RATE * SECS : 100000 * SECS))
sampling=$(awk -v e="$expected" 'BEGIN { r = 100000 / e; printf "%.6f", (r > 0.05 ? 0.05 : r) }')
mkdir -p "$OUT"
# pgbench writes its progress and latency log to RAM during the run: a write
# to the test disk could block pgbench itself (e.g. behind the recorder's
# writes) and show up as workload latency that PostgreSQL never had.
TMP=$(mktemp -d /dev/shm/sosvbench.XXXXXX)
trap 'rm -rf "$TMP"' EXIT
chmod 777 "$TMP"
cd "$TMP"
# shellcheck disable=SC2086,SC2024 # $script may be empty; root writes the output
sudo -u postgres pgbench -n $script "${rate[@]}" -c "$CLIENTS" -j "$THREADS" -T "$SECS" -P 5 \
    -l --sampling-rate="$sampling" --log-prefix="$TMP/pgbench_log" sosvbench >"$TMP/pgbench.out" 2>&1 ||
    { echo "pgbench failed:" >&2; tail -5 "$TMP/pgbench.out" >&2; cp "$TMP/pgbench.out" "$OUT/"; exit 1; }
"$BIN/benchtool" pglat "$TMP/pgbench.out" "$TMP"/pgbench_log.* >"$TMP/workload.csv"
gzip -f "$TMP"/pgbench_log.* # raw latency sample, kept compressed
cp "$TMP"/* "$OUT/"
cat "$OUT/workload.csv"
