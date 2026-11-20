#!/bin/bash
# Inside a container: a crafted wtmp and the real last's output on it.
export TZ=UTC
echo "ghost:x:4294967295:4294967295::/:/bin/sh" >> /etc/passwd
for u in alice bob carol frank gina eve longusername1; do echo "$u:x:$((2000+${#u})):100::/:/bin/sh" >> /etc/passwd; done
NOW=$(date +%s)
/ref/gen/wtmpgen $NOW > /tmp/wtmp
echo "NOW $NOW"
last --version | head -1
for o in "" -F -R -a -i -w "-n 3" reboot alice "pts/4" "-F reboot" "-a -F"; do echo "=== $o"; last -f /tmp/wtmp $o | sed 's/^\(.*\) begins /wtmp begins /'; done
echo "=== -t"
last -f /tmp/wtmp -t "$(date -d @$((NOW-2*86400)) '+%Y-%m-%d %H:%M:%S')" | sed 's/^\(.*\) begins /wtmp begins /'
echo "=== -s"
last -f /tmp/wtmp -s "$(date -d @$((NOW-3*86400)) '+%Y-%m-%d %H:%M:%S')" | sed 's/^\(.*\) begins /wtmp begins /'
echo "=== WTMP"
od -An -tx1 -v /tmp/wtmp | tr -d ' \n'; echo
