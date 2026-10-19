#!/usr/bin/env bash
# Accuracy run: record under a load profile with --verify-every, so the real
# ps aux / ss -tanp / lsof -n -P outputs are captured at checkpoints, then
# compare them with clifr's reconstructions (clifr verify). Run as root.
#
#   sudo bench/accuracy.sh [--profile busy] [--duration 20m] [--verify-every 2m]
#                          [--interval 30s] [--fd-interval 120s] [--out DIR] [--keep-db]
#
# Output (default bench/results/accuracy-<ts>/): verify.json and verify.txt
# (clifr verify), sosv-stats, samples.csv.gz, load.csv.gz, machine.env. The DB
# is deleted afterwards unless --keep-db. Not for cost measurement: each
# checkpoint forces an fd walk and runs the real tools.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

PROFILE=busy DURATION=20m VERIFY_EVERY=2m INTERVAL=30s FD_INTERVAL=120s OUT="" KEEP_DB=0 MIN_FREE_GB=1.5
while (($#)); do
    case $1 in
    --profile) PROFILE=$2; shift ;;
    --duration) DURATION=$2; shift ;;
    --verify-every) VERIFY_EVERY=$2; shift ;;
    --interval) INTERVAL=$2; shift ;;
    --fd-interval) FD_INTERVAL=$2; shift ;;
    --out) OUT=$2; shift ;;
    --keep-db) KEEP_DB=1 ;;
    --min-free-gb) MIN_FREE_GB=$2; shift ;;
    -h | --help) sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done
OUT=${OUT:-$ROOT/bench/results/accuracy-$(date +%Y%m%d-%H%M%S)}
OUT=$(realpath -m "$OUT") # workload.sh changes directory
. "$ROOT/bench/lib.sh"

check_common clifr clifrd load benchtool report
for t in ps ss lsof; do command -v $t >/dev/null || die "$t is needed for the real outputs"; done
mkdir -p "$OUT"
check_free "$OUT"
disk_devices "$OUT"
{
    machine_info "$OUT"
    echo "mode=accuracy"
    echo "profile=$PROFILE"
    echo "duration=$DURATION"
    echo "verify_every=$VERIFY_EVERY"
    echo "interval=$INTERVAL"
    echo "fd_interval=$FD_INTERVAL"
} >"$OUT/machine.env"

stop_all() { systemctl stop sosvbench.slice 2>/dev/null || true; }
trap 'stop_all; chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT" 2>/dev/null' EXIT
stop_all

log "start load ($PROFILE)"
systemd-run --quiet --scope --collect --slice=sosvbench.slice --unit=sosvbench-acc-load-$$ -- \
    "$BIN/load" --profile "$PROFILE" --stats "$OUT/load.csv" >"$OUT/load.out" 2>"$OUT/load.log" &
load_pid=$!
t=0
until grep -q READY "$OUT/load.out" 2>/dev/null; do
    kill -0 $load_pid 2>/dev/null || { tail -3 "$OUT/load.log"; die "load generator died"; }
    ((t++ < 900)) || die "load not READY after 900 s"
    sleep 1
done

log "record $DURATION, verify every $VERIFY_EVERY"
"$BIN/clifrd" --config /dev/null --data-dir "$OUT/data" --interval "$INTERVAL" --fd-interval "$FD_INTERVAL" \
    --verify-every "$VERIFY_EVERY" --duration "$DURATION" >"$OUT/recorder.log" 2>&1
stop_all
wait $load_pid 2>/dev/null || true

log "verify"
"$BIN/clifr" verify --data-dir "$OUT/data" --json >"$OUT/verify.json"
"$BIN/clifr" verify --data-dir "$OUT/data" >"$OUT/verify.txt"
collect_db "$OUT"
((KEEP_DB)) || rm -rf "$OUT/data"
gzip -f "$OUT"/*.csv
sed -n '1,40p' "$OUT/verify.txt"
validate "$OUT"
log "results in $OUT"
