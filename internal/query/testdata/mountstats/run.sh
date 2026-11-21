#!/bin/bash
# In a VM: run its mountstats on each input with each option set.
cd /tmp/msin; T=$(mktemp -d)
ver=$(rpm -q nfs-utils 2>/dev/null || dpkg-query -W -f='${Version}' nfs-common)
for in in input-*.txt; do
  for opts in "" "-n" "-r" "-x" "-R" "/mnt/v3" "-n /mnt/v42" "-x /mnt/v3" "/mnt/none"; do
    echo "=== INPUT ${in#input-} | OPTS $opts"
    mountstats -f $in $opts > $T/o 2> $T/e; rc=$?
    echo "--- rc $rc"; echo "--- stdout"; cat $T/o; echo "--- stderr"; cat $T/e
  done
done > /tmp/golden.txt
echo "$ver" > /tmp/golden.version
