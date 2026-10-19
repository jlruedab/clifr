# Shared helpers for run.sh, scaling.sh and passive.sh (sourced, not run).
# Expects ROOT (repository root) and MIN_FREE_GB to be set by the caller.
# shellcheck shell=bash

BIN=$ROOT/bench/bin

die() { echo "$(basename "$0"): $*" >&2; exit 1; }
log() { echo "[$(date +%H:%M:%S)] $*"; }
# Bash's own clock, not `date +%s%3N`: uutils date (Ubuntu 26.04) ignores the
# width and prints unpadded nanoseconds.
now_ms() { local t=${EPOCHREALTIME/[.,]/}; echo $((t / 1000)); }
free_bytes() { df --output=avail -B1 "$1" | tail -1; }
min_free_bytes() { awk -v g="$MIN_FREE_GB" 'BEGIN { printf "%d", g * 1024 * 1024 * 1024 }'; }

# check_free DIR: die unless DIR's filesystem has at least MIN_FREE_GB free.
check_free() {
    (($(free_bytes "$1") >= $(min_free_bytes))) ||
        die "less than ${MIN_FREE_GB} GB free on $(df --output=target "$1" | tail -1)"
}

# check_common BINARY...: root, cgroup v2 and the named bench/bin binaries.
check_common() {
    [[ $EUID -eq 0 ]] || die "run as root"
    [[ -f /sys/fs/cgroup/cgroup.controllers ]] ||
        die "cgroup v2 is required (/sys/fs/cgroup is not a cgroup2 mount)"
    [[ $(now_ms) =~ ^[0-9]{13}$ ]] || die "now_ms gives '$(now_ms)', not milliseconds"
    local b
    for b in "$@"; do [[ -x $BIN/$b ]] || die "missing $BIN/$b; run bench/setup.sh (or go build)"; done
}

# validate DIR: stop the batch if the results so far have missing or
# implausible metrics (bench/report -validate), instead of finding out
# hours later from a blank report.
validate() {
    "$BIN/report" -validate "$1" || die "validation failed for $1 (see above); stopping"
}

# disk_devices DIR: sets DISKS (all block devices under DIR's filesystem,
# e.g. dm-0,sda3,sda) and DISK (the physical disk).
disk_devices() {
    local src
    src=$(findmnt -no SOURCE --target "$1")
    DISKS=$(lsblk -nso KNAME "$src" | paste -sd,)
    DISK=$(lsblk -nso KNAME,TYPE "$src" | awk '$2 == "disk" {print $1; exit}')
}

# machine_info DIR: key=value lines describing the machine (callers append
# their own parameters). Needs disk_devices first.
machine_info() {
    echo "date=$(date -Is)"
    echo "hostname=$(hostname)"
    echo "cpu_model=$(lscpu | sed -n 's/^Model name: *//p' | head -1)"
    echo "cpus=$(nproc)"
    echo "mem_total_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
    echo "kernel=$(uname -r)"
    # shellcheck disable=SC1091
    echo "distro=$(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "virt=$(systemd-detect-virt || true)"
    echo "fs=$(findmnt -no FSTYPE --target "$1")"
    echo "disks=$DISKS"
    echo "disk=$DISK"
    echo "disk_model=$(xargs </sys/block/"$DISK"/device/model 2>/dev/null)"
    echo "disk_rotational=$(cat /sys/block/"$DISK"/queue/rotational 2>/dev/null)"
    echo "sosv_commit=$(git -c safe.directory="$ROOT" -C "$ROOT" rev-parse --short HEAD 2>/dev/null)$(git -c safe.directory="$ROOT" -C "$ROOT" diff --quiet HEAD 2>/dev/null || echo -dirty)"
    echo "go=$(go version 2>/dev/null | awk '{print $3}')"
}

# collect_db DIR: after the recorder has stopped, save the size of what it
# wrote, `clifr stats` and the samples/guard_events tables into DIR. The
# recording is DIR/data (v2, Parquet) or DIR/sosv.db (v1 recorder, SQLite).
collect_db() {
    local dir=$1 t
    if [[ -d $dir/data ]]; then
        du -sb "$dir/data" | cut -f1 >"$dir/db_bytes"
        du -b "$dir"/data/* | sort -rn >"$dir/table_bytes.txt"
        "$BIN/clifr" stats --data-dir "$dir/data" >"$dir/sosv-stats.txt" 2>&1 || true
        "$BIN/clifr" stats --data-dir "$dir/data" --json >"$dir/sosv-stats.json" 2>/dev/null || true
        for t in samples guard_events recorder_stats reconcile; do
            "$BIN/clifr" export "$t" --data-dir "$dir/data" >"$dir/$t.csv"
        done
    else
        du -cb "$dir"/sosv.db* | tail -1 | cut -f1 >"$dir/db_bytes"
        "$BIN/sosv-v1" stats --db "$dir/sosv.db" >"$dir/sosv-stats.txt" 2>&1 || true
        "$BIN/sosv-v1" stats --db "$dir/sosv.db" --json >"$dir/sosv-stats.json" 2>/dev/null || true
        "$BIN/benchtool" dbexport "$dir/sosv.db" samples >"$dir/samples.csv"
        "$BIN/benchtool" dbexport "$dir/sosv.db" guard_events >"$dir/guard_events.csv"
    fi
}
