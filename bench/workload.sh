#!/usr/bin/env bash
# Runs the measured workload (pgbench, TPC-B-like) and writes its results.
#
#   bench/workload.sh OUTDIR SECONDS [CLIENTS] [THREADS]
#
# Outputs in OUTDIR:
#   pgbench.out         pgbench's own output (progress every 5 s)
#   pgbench_log.*.gz    per-transaction latency log (sampled, see RATE)
#   workload.csv        tps,lat_avg_ms,lat_p50_ms,lat_p95_ms,lat_p99_ms,transactions,failed
#
# pgbench runs as the postgres user; run this script as root. The caller
# decides which cgroup/scope it runs in.
set -euo pipefail
OUT=$1 SECS=$2 CLIENTS=${3:-16} THREADS=${4:-4}
RATE=${RATE:-0.05} # fraction of transactions logged with their latency
BIN=$(cd "$(dirname "$0")" && pwd)/bin
mkdir -p "$OUT"
chmod 777 "$OUT"
cd "$OUT"
sudo -u postgres pgbench -n -c "$CLIENTS" -j "$THREADS" -T "$SECS" -P 5 \
    -l --sampling-rate="$RATE" --log-prefix="$OUT/pgbench_log" sosvbench >"$OUT/pgbench.out" 2>&1 ||
    { echo "pgbench failed:" >&2; tail -5 "$OUT/pgbench.out" >&2; exit 1; }
"$BIN/benchtool" pglat "$OUT/pgbench.out" "$OUT"/pgbench_log.* >"$OUT/workload.csv"
gzip -f "$OUT"/pgbench_log.*  # raw latency sample, kept compressed
cat "$OUT/workload.csv"
