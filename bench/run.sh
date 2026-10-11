#!/usr/bin/env bash
# Benchmark runner: measures the recorder's own cost and its impact on a busy
# workload. Run as root after bench/setup.sh.
#
#   sudo bench/run.sh [options]
#
#   --profiles LIST   load profiles, comma-separated (default: busy)
#   --configs LIST    configurations (default: A,B,C,D,V1,R1)
#                       A   workload only (baseline)
#                       B   sosv-record --interval 30s --fd-interval 120s (default)
#                       C   sosv-record --interval 10s --fd-interval 60s  (aggressive)
#                       D   sosv-record --interval 60s --fd-interval 300s (conservative)
#                       V1  the v1 recorder (tag v1-snapshot, SQLite) at 30s/120s
#                       R1  atop -w FILE 30                        (reference)
#   --bpf-stats       B, C, D: also measure the eBPF programs' run time
#                     (adds a little to every program run: not for latency figures)
#   --cpus LIST       pin PostgreSQL and pgbench to these CPUs (e.g. 0-11: the
#                     performance cores of a hybrid CPU), for steadier latency
#   --repeats N       repeats of each configuration (default: 3)
#   --warmup SECS     warm-up, discarded (default: 120)
#   --measure SECS    measured period (default: 900)
#   --mode M          pgbench workload: select (read-only, default) or tpcb
#   --rate N          pgbench target transactions/s, 0 = unthrottled (default: 30000;
#                     calibrate per machine, see README)
#   --clients N --threads N   pgbench clients/threads (default: 16/4)
#   --load-args "..." extra flags for bench/bin/load (e.g. "--conns 5000")
#   --rec-args "..."  extra flags for sosv-record in B, C and D; RUN in them is the
#                     run's directory (e.g. "--pprof-dir RUN/pprof")
#   --drop-caches     drop the page cache before each run
#   --keep-db         keep each run's sosv database (default: delete it after
#                     saving its size, stats and per-sample table)
#   --out DIR         results directory (default: bench/results/<timestamp>)
#   --smoke           harness check: profile light, config B, 1 repeat,
#                     30 s warm-up + 90 s measured
#
# Order is interleaved: for each profile, repeat 1 runs A B C D R1, then
# repeat 2, and so on, so slow drift affects every configuration alike.
#
# Each run (bench/results/<ts>/runs/<NN>-<profile>-<config>-r<k>/):
#   1. truncate pgbench_history, CHECKPOINT, restart PostgreSQL, load the
#      database files into the page cache (pg_prewarm)
#   2. start the 5 s sampler (cgroup.csv, system.csv, disk.csv)
#   3. start the load generator in its own scope, wait for READY
#   4. start the recorder (or atop) in its own scope
#   5. pgbench warm-up (discarded), then the measured pgbench run
#   6. stop the recorder with SIGTERM; save DB size, `sosv stats`, the
#      samples and guard_events tables; delete the DB
#   7. stop the load and the sampler; append a row to matrix.csv
#
# Workload: by default read-only pgbench at a fixed 30,000 transactions/s with
# the database cached, so the result does not depend on the disk (on the test
# VM, disk stalls of tens of seconds made write workloads unusable). The
# recorder's impact shows as added latency, mainly in the tail.
#
# Every process under test runs in a transient scope in sosvbench.slice with
# CPU, memory and IO accounting. The recorder and atop run with the same
# nice 10 / idle IO class as the shipped systemd unit, but without its
# CPUQuota/MemoryMax, so their true cost is measured instead of the cap.
# Free disk is checked before each run and every 15 s during it; below
# --min-free-gb (default 1.5) the benchmark stops.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

PROFILES=busy CONFIGS="A B C D V1 R1" REPEATS=3 BPF_STATS="" CPUS="" WARMUP=120 MEASURE=900
PGB_MODE=select PGB_RATE=30000 CLIENTS=16 THREADS=4 LOAD_ARGS="" REC_ARGS="" DROP_CACHES=0 KEEP_DB=0 OUT="" MIN_FREE_GB=1.5
while (($#)); do
    case $1 in
    --profiles) PROFILES=${2//,/ }; shift ;;
    --configs) CONFIGS=${2//,/ }; shift ;;
    --repeats) REPEATS=$2; shift ;;
    --warmup) WARMUP=$2; shift ;;
    --measure) MEASURE=$2; shift ;;
    --mode) PGB_MODE=$2; shift ;;
    --rate) PGB_RATE=$2; shift ;;
    --clients) CLIENTS=$2; shift ;;
    --threads) THREADS=$2; shift ;;
    --load-args) LOAD_ARGS=$2; shift ;;
    --rec-args) REC_ARGS=$2; shift ;;
    --drop-caches) DROP_CACHES=1 ;;
    --bpf-stats) BPF_STATS=--bpf-stats ;;
    --cpus) CPUS=$2; shift ;;
    --keep-db) KEEP_DB=1 ;;
    --out) OUT=$2; shift ;;
    --min-free-gb) MIN_FREE_GB=$2; shift ;;
    --smoke) PROFILES=light CONFIGS=B REPEATS=1 WARMUP=30 MEASURE=90 ;;
    -h | --help) sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done
OUT=${OUT:-$ROOT/bench/results/$(date +%Y%m%d-%H%M%S)}
export PGB_MODE PGB_RATE
OUT=$(realpath -m "$OUT") # workload.sh changes directory
. "$ROOT/bench/lib.sh"

# --- prerequisites ---------------------------------------------------------
check_common sosv sosv-record load benchtool report
for c in $CONFIGS; do
    case $c in
    A | B | C | D) ;;
    V1) [[ -x $BIN/sosv-v1 ]] || die "V1 needs $BIN/sosv-v1; run bench/setup.sh" ;;
    R1) command -v atop >/dev/null || die "R1 needs atop" ;;
    R2) die "R2 (PCP pmlogger) is not implemented: PCP is not installed on the test machine" ;;
    *) die "unknown configuration $c" ;;
    esac
done
PGUNIT=$(systemctl list-units --type=service --no-legend 'postgresql*' | awk '$1 ~ /@/ {print $1; exit}')
PGUNIT=${PGUNIT:-postgresql.service}
systemctl is-active -q "$PGUNIT" || die "$PGUNIT is not running"
sudo -u postgres psql -Atc 'select 1 from pgbench_branches limit 1' sosvbench >/dev/null 2>&1 ||
    die "database sosvbench is not ready; run bench/setup.sh"
mkdir -p "$OUT/runs"
check_free "$OUT"

# PostgreSQL is the workload; account its service too.
systemctl set-property --runtime "$PGUNIT" CPUAccounting=yes MemoryAccounting=yes IOAccounting=yes
[[ -z $CPUS ]] || systemctl set-property --runtime "$PGUNIT" AllowedCPUs="$CPUS"
systemctl daemon-reload
PGCG=$(systemctl show -p ControlGroup --value "$PGUNIT")
disk_devices "$OUT"

# --- machine info ------------------------------------------------------------
{
    machine_info "$OUT"
    echo "postgresql=$(sudo -u postgres psql -Atc 'show server_version')"
    echo "pg_settings=$(sudo -u postgres psql -Atc "select string_agg(name||'='||setting, ' ') from pg_settings where name in ('shared_buffers','max_wal_size','max_connections','synchronous_commit')" sosvbench)"
    echo "atop=$(atop -V 2>/dev/null | awk 'NR==1 {print $2}')"
    echo "profiles=$PROFILES"
    echo "configs=$CONFIGS"
    echo "repeats=$REPEATS"
    echo "warmup_s=$WARMUP"
    echo "measure_s=$MEASURE"
    echo "pgbench_mode=$PGB_MODE"
    echo "pgbench_rate=$PGB_RATE"
    echo "pgbench_clients=$CLIENTS"
    echo "pgbench_threads=$THREADS"
    echo "load_args=$LOAD_ARGS"
    echo "drop_caches=$DROP_CACHES"
    echo "bpf_stats=${BPF_STATS:+on}"
    echo "workload_cpus=$CPUS"
} >"$OUT/machine.env"
MATRIX=$OUT/matrix.csv
[[ -f $MATRIX ]] || echo "run_id,order,profile,config,repeat,start_ms,warm_start_ms,meas_start_ms,meas_end_ms,end_ms,status" >"$MATRIX"

# --- helpers -----------------------------------------------------------------
# scope NAME CMD...: run CMD in transient scope sosvbench-NAME-$RUNID.
scope() {
    local name=$1
    shift
    systemd-run --quiet --scope --collect --slice=sosvbench.slice \
        --unit="sosvbench-$name-$RUNID" \
        -p CPUAccounting=yes -p MemoryAccounting=yes -p IOAccounting=yes "${SCOPE_PROPS[@]}" -- "$@"
}
SCOPE_PROPS=()
# pinned NAME CMD...: scope, on the --cpus CPUs.
pinned() {
    [[ -n $CPUS ]] && SCOPE_PROPS=(-p AllowedCPUs="$CPUS")
    scope "$@"
    local rc=$?
    SCOPE_PROPS=()
    return $rc
}
cgpath() { echo "/sosvbench.slice/sosvbench-$1-$RUNID.scope"; }

recorder_cmd() {
    local s
    case $1 in
    A) return ;;
    B) s="--interval 30s --fd-interval 120s" ;;
    C) s="--interval 10s --fd-interval 60s" ;;
    D) s="--interval 60s --fd-interval 300s" ;;
    V1) echo "nice -n 10 ionice -c 3 $BIN/sosv-v1 record --db $RUN/sosv.db --interval 30s --fd-interval 120s"; return ;;
    R1) echo "nice -n 10 ionice -c 3 atop -w $RUN/atop.raw 30"; return ;;
    esac
    echo "nice -n 10 ionice -c 3 $BIN/sosv-record --data-dir $RUN/data $BPF_STATS ${REC_ARGS//RUN/$RUN} $s"
}

stop_all() {
    systemctl stop sosvbench.slice 2>/dev/null || true
}

# run_one ORDER PROFILE CONFIG REPEAT: one run, in a subshell (RUNID and RUN
# set by the caller); exits non-zero on failure.
run_one() {
    local order=$1 profile=$2 config=$3 rep=$4
    mkdir -p "$RUN"
    chmod 777 "$RUN"
    local start warm meas mend end status=ok cmd
    # Not local: the EXIT trap runs after the function has returned.
    samp_pid='' wd_pid='' load_pid='' rec_pid=''
    start=$(now_ms)
    trap 'kill $samp_pid $wd_pid 2>/dev/null || true; stop_all' EXIT

    (($(free_bytes "$OUT") >= $(min_free_bytes))) || { touch "$RUN/LOWDISK"; return 1; }

    log "$RUNID: reset PostgreSQL"
    # No manual VACUUM: on a slow disk it takes many minutes; autovacuum keeps
    # bloat bounded during the runs, the same way for every configuration.
    sudo -u postgres psql -q -c "TRUNCATE pgbench_history" -c "CHECKPOINT" sosvbench
    systemctl restart "$PGUNIT"
    if ((DROP_CACHES)); then sync && echo 3 >/proc/sys/vm/drop_caches; fi
    sudo -u postgres psql -q -c "SELECT pg_prewarm(c.oid::regclass, 'read') FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'i')" sosvbench >/dev/null

    "$BIN/benchtool" cgsample --out "$RUN" --interval 5s --disk "$DISKS" --free-path "$OUT" \
        rec="$(cgpath rec)" load="$(cgpath load)" pgb_warm="$(cgpath pgbw)" pgb="$(cgpath pgbm)" \
        postgres="$PGCG" &
    samp_pid=$!
    # Disk watchdog: stop everything if free space drops below the limit.
    (while sleep 15; do
        if (($(free_bytes "$OUT") < $(min_free_bytes))); then
            touch "$RUN/LOWDISK"
            echo "run.sh: free disk below ${MIN_FREE_GB} GB, stopping" >&2
            stop_all
            exit
        fi
    done) &
    wd_pid=$!

    log "$RUNID: start load ($profile)"
    # shellcheck disable=SC2086
    scope load "$BIN/load" --profile "$profile" --stats "$RUN/load.csv" $LOAD_ARGS >"$RUN/load.out" 2>"$RUN/load.log" &
    load_pid=$!
    local t=0
    until grep -q READY "$RUN/load.out" 2>/dev/null; do
        kill -0 $load_pid 2>/dev/null || { log "$RUNID: load generator died"; tail -3 "$RUN/load.log"; return 1; }
        ((t++ < 600)) || { log "$RUNID: load not READY after 600 s"; return 1; }
        sleep 1
    done

    cmd=$(recorder_cmd "$config")
    if [[ -n $cmd ]]; then
        log "$RUNID: start $cmd"
        # shellcheck disable=SC2086
        scope rec $cmd >"$RUN/recorder.log" 2>&1 &
        rec_pid=$!
        sleep 3
        kill -0 $rec_pid 2>/dev/null || { log "$RUNID: recorder died at start"; tail -3 "$RUN/recorder.log"; return 1; }
    fi

    warm=$(now_ms)
    log "$RUNID: warm-up ${WARMUP}s"
    pinned pgbw "$ROOT/bench/workload.sh" "$RUN/warmup" "$WARMUP" "$CLIENTS" "$THREADS" >/dev/null
    meas=$(now_ms)
    log "$RUNID: measure ${MEASURE}s"
    pinned pgbm "$ROOT/bench/workload.sh" "$RUN/workload" "$MEASURE" "$CLIENTS" "$THREADS" >/dev/null
    mend=$(now_ms)
    sed -n 2p "$RUN/workload/workload.csv" | awk -F, '{printf "    tps %.0f  lat avg %s ms  p95 %s ms  p99 %s ms  p99.9 %s ms\n", $1, $2, $4, $5, $6}'

    if [[ -n $rec_pid ]]; then
        kill -0 $rec_pid 2>/dev/null || { log "$RUNID: recorder exited during the run"; status=recorder_died; }
        systemctl stop "sosvbench-rec-$RUNID.scope" 2>/dev/null || true # SIGTERM, clean shutdown
        wait $rec_pid || true
    fi
    if [[ -f $RUN/sosv.db || -d $RUN/data ]]; then
        collect_db "$RUN"
        ((KEEP_DB)) || rm -rf "$RUN"/sosv.db* "$RUN/data"
    fi
    if [[ -f $RUN/atop.raw ]]; then
        stat -c %s "$RUN/atop.raw" >"$RUN/atop_bytes"
        ((KEEP_DB)) || rm -f "$RUN/atop.raw"
    fi
    stop_all
    wait $load_pid 2>/dev/null || true
    sleep 5 # one more sampler tick after everything stopped
    kill $samp_pid $wd_pid 2>/dev/null || true
    wait $samp_pid 2>/dev/null || true
    gzip -f "$RUN"/*.csv
    end=$(now_ms)
    [[ -f $RUN/LOWDISK ]] && status=lowdisk
    echo "$RUNID,$order,$profile,$config,$rep,$start,$warm,$meas,$mend,$end,$status" >>"$MATRIX"
    [[ $status != lowdisk ]]
}

# --- matrix ------------------------------------------------------------------
trap 'stop_all; chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT" 2>/dev/null' EXIT
stop_all # leftovers from an aborted earlier run
nruns=$(($(wc -w <<<"$PROFILES") * REPEATS * $(wc -w <<<"$CONFIGS")))
log "results: $OUT"
log "$nruns runs, about $((nruns * (WARMUP + MEASURE + 60) / 60)) min"
order=0 failed=0
for profile in $PROFILES; do
    for rep in $(seq "$REPEATS"); do
        for config in $CONFIGS; do
            order=$((order + 1))
            RUNID=$(printf '%02d' "$order")-$profile-$config-r$rep
            RUN=$OUT/runs/$RUNID
            # Plain command, not in an if/||: set -e must stay active inside.
            set +e
            (set -e; run_one "$order" "$profile" "$config" "$rep")
            rc=$?
            set -e
            if ((rc != 0)); then
                if [[ -f $RUN/LOWDISK ]]; then
                    die "stopped: free disk below ${MIN_FREE_GB} GB (results so far in $OUT)"
                fi
                log "$RUNID: FAILED"
                failed=$((failed + 1))
                grep -q "^$RUNID," "$MATRIX" || echo "$RUNID,$order,$profile,$config,$rep,,,,,$(now_ms),failed" >>"$MATRIX"
            else
                validate "$OUT"
            fi
        done
    done
done
log "done: $order runs, $failed failed; results in $OUT"
