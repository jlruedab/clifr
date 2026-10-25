#!/usr/bin/env bash
# Real-server mode: measure the recorder's cost on a real (non-test) server.
# No load is generated. The recorder runs as a transient systemd service with
# the limits and sandbox of deploy/clifrd.service (read from the unit at
# start), plus a 5 s cgroup sampler; both survive logout. Run as root.
#
#   sudo bench/passive.sh start [--duration 24h] [--interval 30s]
#                               [--fd-interval 120s] [--out DIR] [--min-free-gb 1.5]
#   sudo bench/passive.sh status
#   sudo bench/passive.sh stop
#
# start   checks free disk, writes machine.env, starts clifr-passive.service
#         (the recorder, which stops by itself after --duration) and
#         clifr-passive-sampler.service. Results go to DIR (default
#         bench/results/passive-<timestamp>).
# status  shows both services, elapsed time, recording size and free disk.
# stop    stops both services (SIGTERM: the recorder closes its rows
#         cleanly), saves `clifr stats`, the samples and guard_events tables
#         and the recording's size. Run it after --duration has passed, or
#         earlier to cut the run short. The recording (DIR/data) is kept: on
#         a real server it is the flight record.
#
# Safety on a production server:
#   - The recorder runs with every [Service] setting of deploy/clifrd.service
#     (CPUWeight=10, CPUQuota=50%, MemoryMax=768M, Nice=10, IOSchedulingClass=idle, its
#     capabilities, ProtectSystem=strict and the other protections) except
#     how it is started, restarted and where it writes: DIR only. On kernels
#     before 5.8 (no CAP_BPF/CAP_PERFMON) CAP_SYS_ADMIN is added for eBPF, as
#     the unit's comment says. Its own guard rail (2% CPU budget) lengthens
#     the fd interval if needed. If the quota throttles the recorder
#     (cgroup.csv nr_throttled, throttled_us) its samples take longer in wall
#     time; the average CPU is still the true cost as long as it stays well
#     below the quota.
#   - If free disk drops below --min-free-gb the sampler stops the recorder
#     and writes DIR/LOWDISK.
#   - To stop everything at any time: sudo bench/passive.sh stop
#     (or: systemctl stop clifr-passive clifr-passive-sampler).
#   - Nothing else on the server is changed; the services are transient and
#     disappear on reboot.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
STATE=/run/clifr-passive.out # path of the current results directory
REC=clifr-passive.service
SAMP=clifr-passive-sampler.service

CMD=${1:-}
[[ -n $CMD ]] && shift
DURATION=24h INTERVAL=30s FD_INTERVAL=120s OUT="" MIN_FREE_GB=1.5
while (($#)); do
    case $1 in
    --duration) DURATION=$2; shift ;;
    --interval) INTERVAL=$2; shift ;;
    --fd-interval) FD_INTERVAL=$2; shift ;;
    --out) OUT=$2; shift ;;
    --min-free-gb) MIN_FREE_GB=$2; shift ;;
    *) echo "unknown option $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done
. "$ROOT/bench/lib.sh"

# seconds DURATION: 90s / 30m / 24h / 2d -> seconds.
seconds() {
    local n=${1%[smhd]} u=${1##*[0-9]}
    case $u in
    s | "") echo "$n" ;;
    m) echo $((n * 60)) ;;
    h) echo $((n * 3600)) ;;
    d) echo $((n * 86400)) ;;
    esac
}

# unit_props: the [Service] settings of deploy/clifrd.service as systemd-run
# -p arguments, without the ones about starting, restarting and the state
# directory (the results directory replaces it). Before Linux 5.8 eBPF
# needs CAP_SYS_ADMIN.
unit_props() {
    local line k v old=false
    [[ $(printf '%s\n' 5.8 "$(uname -r)" | sort -V | head -1) != 5.8 ]] && old=true
    while IFS= read -r line; do
        k=${line%%=*} v=${line#*=}
        case $k in
        Type | ExecStart | Restart | RestartSec | StateDirectory | StateDirectoryMode | Group) continue ;;
        CapabilityBoundingSet) $old && v="$v CAP_SYS_ADMIN" ;;
        esac
        printf '%s\n' "-p" "$k=$v"
    done < <(awk '/^\[/ {s = ($0 == "[Service]")} s && /^[A-Za-z]+=/' "$ROOT/deploy/clifrd.service")
}

start() {
    check_common clifr clifrd benchtool
    systemctl is-active -q $REC && die "already running (results: $(cat $STATE 2>/dev/null)); use stop first"
    OUT=${OUT:-$ROOT/bench/results/passive-$(date +%Y%m%d-%H%M%S)}
    mkdir -p "$OUT"
    OUT=$(cd "$OUT" && pwd)
    check_free "$OUT"
    disk_devices "$OUT"
    local secs
    secs=$(seconds "$DURATION")
    [[ $secs =~ ^[0-9]+$ ]] || die "bad --duration $DURATION"
    {
        machine_info "$OUT"
        echo "mode=passive"
        echo "duration=$DURATION"
        echo "interval=$INTERVAL"
        echo "fd_interval=$FD_INTERVAL"
        echo "start_ms=$(now_ms)"
    } >"$OUT/machine.env"
    systemctl reset-failed $REC $SAMP 2>/dev/null || true

    # The limits and sandbox of deploy/clifrd.service.
    local props
    mapfile -t props < <(unit_props)
    ((${#props[@]})) || die "no [Service] settings read from deploy/clifrd.service"
    printf '%s %s\n' "${props[@]}" | sed 's/^-p /  /' >"$OUT/unit-props.txt"
    systemd-run --quiet --unit=$REC --description="clifr recorder (passive benchmark)" \
        "${props[@]}" -p "ReadWritePaths=$OUT" \
        -p StandardOutput=append:"$OUT/recorder.log" -p StandardError=append:"$OUT/recorder.log" \
        "$BIN/clifrd" --config /dev/null --data-dir "$OUT/data" --interval "$INTERVAL" --fd-interval "$FD_INTERVAL" \
        --duration "$DURATION"
    local reccg
    reccg=$(systemctl show -p ControlGroup --value $REC)
    systemd-run --quiet --unit=$SAMP --description="clifr passive benchmark sampler" \
        -p RuntimeMaxSec=$((secs + 900)) -p Nice=10 \
        "$BIN/benchtool" cgsample --out "$OUT" --interval 5s --disk "$DISKS" --free-path "$OUT" \
        --min-free "$(min_free_bytes)" --stop-unit $REC rec="$reccg"
    echo "$OUT" >$STATE
    sleep 2
    systemctl is-active -q $REC || { tail -5 "$OUT/recorder.log"; die "recorder did not start"; }
    # What the recorder could use inside the sandbox: eBPF, or the fallbacks
    # (logged once its event sources are set up, a few seconds after start).
    local i
    for i in $(seq 1 30); do grep -q "TCP:" "$OUT/recorder.log" && break; sleep 1; done
    grep -E "process events:|TCP:|open files:" "$OUT/recorder.log" | sed 's/^/    /' || true
    log "recording for $DURATION; results in $OUT"
    log "check: sudo bench/passive.sh status    finish: sudo bench/passive.sh stop"
}

current() {
    [[ -f $STATE ]] || die "no passive run found ($STATE missing)"
    OUT=$(cat $STATE)
}

status() {
    current
    local s
    for s in $REC $SAMP; do printf '%-30s %s\n' "$s" "$(systemctl is-active "$s" || true)"; done
    echo "results:   $OUT"
    echo "started:   $(sed -n 's/^start_ms=//p' "$OUT/machine.env" | awk '{print strftime("%F %T", $1/1000)}')"
    echo "data size: $(du -sh "$OUT/data" 2>/dev/null | cut -f1)"
    echo "free disk: $(df -h --output=avail "$OUT" | tail -1 | xargs)"
    [[ -f $OUT/LOWDISK ]] && echo "LOW DISK: the recorder was stopped by the sampler"
    tail -3 "$OUT/recorder.log"
}

stop() {
    check_common clifr clifrd benchtool
    current
    systemctl stop $REC 2>/dev/null || true # SIGTERM: clean shutdown
    sleep 6                                 # one more sampler tick
    systemctl stop $SAMP 2>/dev/null || true
    echo "end_ms=$(now_ms)" >>"$OUT/machine.env"
    [[ -d $OUT/data ]] || die "no recording in $OUT"
    collect_db "$OUT"
    gzip -f "$OUT"/*.csv
    rm -f $STATE
    chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT" 2>/dev/null || true
    cat "$OUT/sosv-stats.txt"
    log "results in $OUT (the recording is kept: $OUT/data)"
}

case $CMD in
start) start ;;
status) status ;;
stop) stop ;;
-h | --help | "") sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//' ;;
*) die "unknown command $CMD (start, status or stop)" ;;
esac
