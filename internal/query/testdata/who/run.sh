#!/bin/bash
# Inside a container: the test utmp as the system's, terminals with chosen access times, who's output.
cp /ref/utmp /var/run/utmp
NOW=$(date +%s)
mk() { : > /dev/$1; chgrp tty /dev/$1; chmod $2 /dev/$1; touch -a -d @$3 /dev/$1; }
mk tty7 620 $((NOW-30))
mk tty8 600 $((NOW-7500))
mk ttyS9 620 $((NOW-3*86400))
echo "NOW $NOW"
who --version | head -1
for loc in C C.UTF-8; do
  for o in "" -H -u -a -aH -b -r -q -T -d -l -p -t "-s -u" "-uT" "-H -u" "-bH" "-bu"; do
    echo "=== $loc|$o"
    LC_ALL=$loc TZ=UTC who $o
  done
done
