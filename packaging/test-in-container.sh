#!/bin/bash
# Run by packaging/test.sh inside each distribution's container.
set -euo pipefail
if command -v apt-get >/dev/null; then
	apt-get -qq update
	DEBIAN_FRONTEND=noninteractive apt-get -qq install -y sosreport /dist/*.deb >/dev/null 2>&1
	files() { dpkg -L clifr clifrd; }
	plugins=/usr/lib/python3/dist-packages/sos/report/plugins
else
	dnf -q -y install sos /dist/*.rpm >/dev/null 2>&1
	files() { rpm -ql clifr clifrd; }
	plugins=$(rpm -ql sos | sed -n 's|/__init__.py$||p' | grep 'report/plugins$')
fi
clifr --version
clifrd --version
# In the package (minimized container images drop man pages on install).
files | grep -E 'man1/clifr.1.gz|man8/clifrd.8.gz'
test -f /usr/lib/systemd/system/clifrd.service
test -f /etc/clifr/clifrd.yml
# The license files, notices and eBPF sources (from the file list: a
# minimized image may skip docs on install; read once, as grep -q would
# make the lister fail with SIGPIPE under pipefail).
list=$(files)
for f in clifr/LICENSE clifr/THIRD_PARTY_NOTICES clifrd/LICENSE clifrd/THIRD_PARTY_NOTICES clifrd/ebpf/tcpevents.bpf.c; do
	grep -qx "/usr/share/doc/$f" <<<"$list" || { echo "missing /usr/share/doc/$f"; exit 1; }
done
getent group clifr
sos report --list-plugins 2>/dev/null | grep -E '^ *clifr '
clifrd doctor | tail -1
if [ -f /bundle.tar ]; then
	start=$(clifr -D /bundle.tar info | awk '/^Recording:/ {print $2, $3}')
	echo "bundle starts $start: ps aux $(clifr -D /bundle.tar --plain --at "$start" "ps aux" 2>/dev/null | wc -l) lines"
	test "$(clifr -D /bundle.tar --plain --at "$start" "ps aux" 2>/dev/null | wc -l)" -gt 100
fi
if command -v apt-get >/dev/null; then
	apt-get -qq purge -y clifrd clifr >/dev/null 2>&1
else
	dnf -q -y remove clifrd clifr >/dev/null 2>&1
fi
test ! -e "$plugins/clifr.py"
! command -v clifr
echo "ALL OK"
