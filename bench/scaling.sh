#!/usr/bin/env bash
# Scaling tests: how the recorder's cost grows with each load dimension.
# No workload (pgbench); one dimension varies at a time, the others stay at
# the baseline. Run as root.
#
#   sudo bench/scaling.sh [options]
#
#   --dims LIST       dimensions to vary (default: procs,fds,conns,spawn,churn)
#                       procs   long-lived processes      500, 2000*, 10000
#                       fds     open files held by them   10000, 50000*, 200000
#                       conns   concurrent TCP conns      1000, 20000*, 100000
#                       spawn   short-lived procs/s       10, 50*, 200
#                       churn   new TCP conns/s           0*, 100, 500
#                     (* = baseline used while another dimension varies)
#   --record SECS     recording time per point (default: 420, i.e. 14 samples
#                     and 4 full fd walks at the default intervals)
#   --interval D --fd-interval D   recorder intervals (default: 30s / 120s)
#   --out DIR         results directory (default: bench/results/scaling-<ts>)
#   --min-free-gb N   stop below this much free disk (default: 1.5)
#
# The baseline point appears once per dimension, so it is measured several
# times; its spread shows the noise. The recorder runs with --cpu-budget 100%
# (guard rail off) so the raw cost is measured; whether a point fits the
# default 2% budget is computed from the results by bench/report.
#
# Output: points.csv, machine.env, and per point points/<NN>-<dim>-<value>/
# with samples.csv.gz (per-sample phase durations, cumulative CPU, DB size),
# cgroup.csv.gz/system.csv.gz/disk.csv.gz (5 s), sosv-stats, db_bytes,
# load.csv.gz. The DB is deleted after its size and tables are saved.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

DIMS="procs fds conns spawn churn" RECORD=420 INTERVAL=30s FD_INTERVAL=120s OUT="" MIN_FREE_GB=1.5
while (($#)); do
    case $1 in
    --dims) DIMS=${2//,/ }; shift ;;
    --record) RECORD=$2; shift ;;
    --interval) INTERVAL=$2; shift ;;
    --fd-interval) FD_INTERVAL=$2; shift ;;
    --out) OUT=$2; shift ;;
    --min-free-gb) MIN_FREE_GB=$2; shift ;;
    -h | --help) sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done
OUT=${OUT:-$ROOT/bench/results/scaling-$(date +%Y%m%d-%H%M%S)}
OUT=$(realpath -m "$OUT") # workload.sh changes directory
. "$ROOT/bench/lib.sh"

declare -A BASE=([procs]=2000 [fds]=50000 [conns]=20000 [spawn]=50 [churn]=0)
declare -A VALUES=([procs]="500 2000 10000" [fds]="10000 50000 200000"
    [conns]="1000 20000 100000" [spawn]="10 50 200" [churn]="0 100 500")
for d in $DIMS; do [[ -n ${VALUES[$d]:-} ]] || die "unknown dimension $d"; done

check_common clifr clifrd load benchtool report
mkdir -p "$OUT/points"
check_free "$OUT"
disk_devices "$OUT"
{
    machine_info "$OUT"
    echo "dims=$DIMS"
    echo "record_s=$RECORD"
    echo "interval=$INTERVAL"
    echo "fd_interval=$FD_INTERVAL"
    echo "baseline=procs=${BASE[procs]} fds=${BASE[fds]} conns=${BASE[conns]} spawn=${BASE[spawn]} churn=${BASE[churn]}"
} >"$OUT/machine.env"
POINTS=$OUT/points.csv
[[ -f $POINTS ]] || echo "point_id,dim,value,procs,fds,conns,spawn,churn,start_ms,rec_start_ms,rec_end_ms,end_ms,status" >"$POINTS"

scope() {
    local name=$1
    shift
    systemd-run --quiet --scope --collect --slice=sosvbench.slice \
        --unit="sosvbench-$name-$PID_" \
        -p CPUAccounting=yes -p MemoryAccounting=yes -p IOAccounting=yes -- "$@"
}
cgpath() { echo "/sosvbench.slice/sosvbench-$1-$PID_.scope"; }
stop_all() { systemctl stop sosvbench.slice 2>/dev/null || true; }

# point DIM VALUE: one measurement; runs in a subshell, PID_ and DIR set by caller.
point() {
    local dim=$1 value=$2 start rec_start rec_end status=ok
    declare -A k
    local d
    for d in "${!BASE[@]}"; do k[$d]=${BASE[$d]}; done
    k[$dim]=$value
    mkdir -p "$DIR"
    samp_pid='' load_pid=''
    trap 'kill $samp_pid 2>/dev/null || true; stop_all' EXIT
    start=$(now_ms)
    check_free "$OUT"

    "$BIN/benchtool" cgsample --out "$DIR" --interval 5s --disk "$DISKS" --free-path "$OUT" \
        rec="$(cgpath rec)" load="$(cgpath load)" &
    samp_pid=$!

    log "$PID_: load procs=${k[procs]} fds=${k[fds]} conns=${k[conns]} spawn=${k[spawn]}/s churn=${k[churn]}/s"
    scope load "$BIN/load" --profile busy --procs "${k[procs]}" --fds "${k[fds]}" --conns "${k[conns]}" \
        --spawn "${k[spawn]}" --conn-churn "${k[churn]}" --stats "$DIR/load.csv" \
        >"$DIR/load.out" 2>"$DIR/load.log" &
    load_pid=$!
    local t=0
    until grep -q READY "$DIR/load.out" 2>/dev/null; do
        kill -0 $load_pid 2>/dev/null || { log "$PID_: load generator died"; tail -3 "$DIR/load.log"; exit 1; }
        ((t++ < 900)) || { log "$PID_: load not READY after 900 s"; exit 1; }
        sleep 1
    done

    rec_start=$(now_ms)
    log "$PID_: record ${RECORD}s"
    scope rec nice -n 10 ionice -c 3 "$BIN/clifrd" --data-dir "$DIR/data" --bpf-stats \
        --interval "$INTERVAL" --fd-interval "$FD_INTERVAL" --cpu-budget 100% \
        --duration "${RECORD}s" >"$DIR/recorder.log" 2>&1 || status=recorder_failed
    rec_end=$(now_ms)
    collect_db "$DIR"
    rm -rf "$DIR/data"
    sed -n '/^Sample duration/,/^  total/p' "$DIR/sosv-stats.txt" | sed 's/^/    /'

    stop_all
    wait $load_pid 2>/dev/null || true
    sleep 5
    kill $samp_pid 2>/dev/null || true
    wait $samp_pid 2>/dev/null || true
    gzip -f "$DIR"/*.csv
    echo "$PID_,$dim,$value,${k[procs]},${k[fds]},${k[conns]},${k[spawn]},${k[churn]},$start,$rec_start,$rec_end,$(now_ms),$status" >>"$POINTS"
}

trap 'stop_all; chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT" 2>/dev/null' EXIT
stop_all
n=0
for d in $DIMS; do n=$((n + $(wc -w <<<"${VALUES[$d]}"))); done
log "results: $OUT"
log "$n points, about $((n * (RECORD + 90) / 60)) min"
order=0 failed=0
for dim in $DIMS; do
    for value in ${VALUES[$dim]}; do
        order=$((order + 1))
        PID_=$(printf '%02d' "$order")-$dim-$value
        DIR=$OUT/points/$PID_
        set +e
        (set -e; point "$dim" "$value")
        rc=$?
        set -e
        if ((rc != 0)); then
            log "$PID_: FAILED"
            failed=$((failed + 1))
            grep -q "^$PID_," "$POINTS" || echo "$PID_,$dim,$value,,,,,,,,,$(now_ms),failed" >>"$POINTS"
            check_free "$OUT"
        else
            validate "$OUT"
        fi
    done
done
log "done: $order points, $failed failed; results in $OUT"
