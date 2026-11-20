#!/bin/bash
# Inside a container: real pty sessions, a utmp naming them, w's output and the /proc state w read.
command -v w >/dev/null || dnf -y -q install procps-ng >/dev/null 2>&1
export TZ=UTC
script -qfc "bash -c 'sleep 600; :'" /dev/null </dev/null >/dev/null 2>&1 &
script -qfc "sh -c 'i=0; while [ \$i -lt 400000 ]; do i=\$((i+1)); done; sleep 600; :'" /dev/null </dev/null >/dev/null 2>&1 &
sleep 4
A=$(pgrep -f "^bash -c sleep 600; :"); B=$(pgrep -f "^sh -c i=0")
NOW=$(date +%s)
/ref/gen/utmpgen "$A" "$B" "$NOW" > /var/run/utmp
echo "NOW $NOW"
w -V 2>&1 | head -1
for o in "" -h -s -f -o -i -u "-s -u" "-u bin" root bin nobody; do echo "=== $o"; w $o; done
echo "=== PROCS"
for d in /proc/[0-9]*; do
  p=${d#/proc/}; [ -r $d/stat ] || continue
  st=$(cat $d/stat 2>/dev/null) || continue
  rest=${st##*) }; comm=${st#*(}; comm=${comm%) *}
  set -- $rest
  # state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime ... starttime(22)
  euid=$(awk '/^Uid:/{print $3}' $d/status); ruid=$(awk '/^Uid:/{print $2}' $d/status)
  cmd=$(tr '\0' ' ' < $d/cmdline | sed 's/ $//')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$2" "$5" "$3" "$6" "$euid" "$ruid" "${20}" "$((${12}+${13}))" "$1" "$comm|$cmd"
done
echo "=== TTYS"
for t in pts/0 pts/1; do stat -c "$t	%X	%a	%t	%T" /dev/$t; done
echo "=== UTMP"
od -An -tx1 -v /var/run/utmp | tr -d ' \n'; echo
