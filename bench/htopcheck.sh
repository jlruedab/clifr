#!/bin/bash
# bench/htopcheck.sh: record with clifrd while capturing real htop screens,
# for bench/htopcheck (run as root, on the host to check).
#
#   bench/htopcheck.sh CLIFRD OUTDIR
#
# Starts CLIFRD (--interval 5s) into OUTDIR/rec, then captures htop in a
# detached tmux pane (200 columns, 300 lines) with htop's own default htoprc
# (written by htop itself at its first exit) and hide_userland_threads=1, as
# clifr draws it: the default screen, -t, -s PERCENT_MEM, -u root, -p 1, -C,
# and the default at 80 columns. OUTDIR/NAME.txt is the screen, NAME.time
# the moment, NAME.args htop's arguments, NAME.cols the width. Then stops
# clifrd. Needs tmux and htop.
set -u
CLIFRD=${1:?clifrd binary}
OUT=${2:?outdir}
mkdir -p "$OUT"
H=$(mktemp -d)
"$CLIFRD" --config /dev/null --data-dir "$OUT/rec" --interval 5s --flush-interval 30s >"$OUT/clifrd.log" 2>&1 &
CPID=$!
run() { # COLS ROWS htop-args...
	local cols=$1 rows=$2; shift 2
	tmux -f /dev/null -L clifrcheck new-session -d -s cap -x "$cols" -y "$rows" \
		"env -i HOME=$H TERM=screen-256color LC_ALL=C.UTF-8 PATH=/usr/sbin:/usr/bin:/sbin:/bin htop $*"
	# tmux 3.2a (RHEL 9) keeps a detached session at 80x24 despite -x/-y;
	# 2.7 (RHEL 8) has no resize-window but takes -x/-y.
	tmux -L clifrcheck resize-window -t cap -x "$cols" -y "$rows" 2>/dev/null
}
# htop writes its default configuration when it quits.
run 200 50
sleep 3
tmux -L clifrcheck send-keys -t cap q
sleep 1
tmux -L clifrcheck kill-server 2>/dev/null
RC=$H/.config/htop/htoprc
if [ ! -f "$RC" ]; then
	echo "htop wrote no htoprc" >&2
	kill "$CPID"
	exit 1
fi
sed -i 's/^hide_userland_threads=0/hide_userland_threads=1/' "$RC"
cp "$RC" "$OUT/htoprc"
cp "$RC" "$OUT/htoprc.orig"
sleep 20 # clifrd's first samples
cap() { # NAME COLS htop-args...
	local name=$1 cols=$2; shift 2
	cp "$OUT/htoprc.orig" "$RC" # htop rewrites it at exit
	run "$cols" 300 "$@"
	sleep 7
	date '+%Y-%m-%d %H:%M:%S' >"$OUT/$name.time"
	tmux -L clifrcheck capture-pane -p -S 0 -E 299 -t cap >"$OUT/$name.txt"
	tmux -L clifrcheck kill-server 2>/dev/null
	echo "$*" >"$OUT/$name.args"
	echo "$cols" >"$OUT/$name.cols"
	sleep 1
}
cap main 200
cap tree 200 -t
cap mem 200 -s PERCENT_MEM
cap root 200 -u root
cap pid1 200 -p 1
cap mono 200 -C
cap main80 80
sleep 6
kill "$CPID"
wait "$CPID"
htop --version >"$OUT/version.txt" 2>&1
rm -rf "${H:?}"
