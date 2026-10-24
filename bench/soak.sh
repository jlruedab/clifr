#!/usr/bin/env bash
# Soak test of the installed clifrd service: an hourly sample of what the
# service uses, and a daily summary. Run as root.
#
#   sudo bench/soak.sh sample OUTDIR   append one line to OUTDIR/soak.csv
#   bench/soak.sh report OUTDIR        per-day summary of soak.csv
#
# Columns of soak.csv: time (Unix s), service state, restarts since the
# unit was loaded, the main PID, CPU used by the service in total (ns),
# memory now and its peak (bytes, cgroup), the recording's size on disk
# (bytes) and the number of files in it.
set -euo pipefail
cmd=${1:-}
OUT=${2:-}
[[ -n $cmd && -n $OUT ]] || { echo "usage: $0 sample|report OUTDIR" >&2; exit 2; }
CSV=$OUT/soak.csv

case $cmd in
sample)
	mkdir -p "$OUT"
	[[ -f $CSV ]] || echo "ts,state,restarts,pid,cpu_ns,mem_bytes,mem_peak_bytes,data_bytes,data_files" >"$CSV"
	get() { systemctl show clifrd -p "$1" --value; }
	data=/var/lib/clifr
	[[ -L $data ]] && data=$(readlink -f "$data")
	bytes=$(du -sb "$data" 2>/dev/null | cut -f1)
	files=$(find "$data" -type f 2>/dev/null | wc -l)
	echo "$(date +%s),$(get ActiveState),$(get NRestarts),$(get MainPID),$(get CPUUsageNSec),$(get MemoryCurrent),$(get MemoryPeak),${bytes:-0},$files" >>"$CSV"
	;;
report)
	# Per day: CPU as % of one core over the day, memory average and the
	# highest peak, the recording's size at the end of the day, restarts.
	awk -F, 'NR == 1 { next }
	{
		day = strftime("%Y-%m-%d", $1)
		if (!(day in first)) { first[day] = $1; cpu0[day] = $5; order[++n] = day }
		last[day] = $1; cpu1[day] = $5
		mem[day] += $6; cnt[day]++
		if ($7 > peak[day]) peak[day] = $7
		size[day] = $8; rs[day] = $3; st[day] = $2
	}
	END {
		printf "%-10s %8s %10s %10s %10s %9s %s\n", "day", "samples", "cpu%core", "mem avg", "mem peak", "data", "restarts"
		for (i = 1; i <= n; i++) {
			d = order[i]
			secs = last[d] - first[d]
			cpu = secs > 0 ? (cpu1[d] - cpu0[d]) / 1e9 / secs * 100 : 0
			printf "%-10s %8d %9.2f%% %8.0fMi %8.0fMi %7.2fGi %s\n", d, cnt[d], cpu, mem[d] / cnt[d] / 1048576,
				peak[d] / 1048576, size[d] / 1073741824, rs[d]
		}
	}' "$CSV"
	;;
*)
	echo "usage: $0 sample|report OUTDIR" >&2
	exit 2
	;;
esac
