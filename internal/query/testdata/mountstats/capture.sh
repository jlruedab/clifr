#!/bin/bash
# Runs inside a test VM as root: loopback NFS mounts, I/O, captures.
set -e
if command -v dnf >/dev/null; then dnf -q -y install nfs-utils >/dev/null; systemctl enable --now nfs-server >/dev/null 2>&1
else export DEBIAN_FRONTEND=noninteractive; apt-get -qq update >/dev/null; apt-get -qq -y install nfs-kernel-server >/dev/null; systemctl enable --now nfs-kernel-server >/dev/null 2>&1; fi
mkdir -p /srv/nfs /mnt/v3 /mnt/v42
grep -q /srv/nfs /etc/exports || echo '/srv/nfs 127.0.0.1(rw,no_root_squash,sync)' >> /etc/exports
exportfs -ra
mountpoint -q /mnt/v3 || mount -t nfs -o vers=3 127.0.0.1:/srv/nfs /mnt/v3
mountpoint -q /mnt/v42 || mount -t nfs -o vers=4.2 127.0.0.1:/srv/nfs /mnt/v42
for m in /mnt/v3 /mnt/v42; do
  dd if=/dev/urandom of=$m/f.$$ bs=64k count=64 conv=fsync status=none
  dd if=$m/f.$$ of=/dev/null bs=64k status=none iflag=direct 2>/dev/null || cat $m/f.$$ >/dev/null
  dd if=/dev/zero of=$m/d.$$ bs=4k count=16 oflag=direct status=none 2>/dev/null || true
  mkdir -p $m/dir.$$; for i in 1 2 3 4 5; do touch $m/dir.$$/x$i; done; ls -la $m/dir.$$ >/dev/null; stat $m/f.$$ >/dev/null
  truncate -s 1M $m/f.$$; mv $m/dir.$$/x1 $m/dir.$$/y1; rm -rf $m/dir.$$ $m/d.$$
done
sync
out=/tmp/mscap; rm -rf $out; mkdir -p $out
cp /proc/self/mountstats $out/mountstats.txt
mountstats --version > $out/version.txt 2>&1 || true
rpm -q nfs-utils >> $out/version.txt 2>/dev/null || dpkg -s nfs-common 2>/dev/null | grep ^Version >> $out/version.txt
uname -r >> $out/version.txt
