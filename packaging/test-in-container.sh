#!/bin/bash
# Run by packaging/test.sh inside each distribution's container.
set -euo pipefail
# The packages first without sos, then sos added, removed and added again:
# the plugin is linked into sos's directory only while sos is installed, and
# nothing of sos's directory is left without it.
if command -v apt-get >/dev/null; then
	apt-get -qq update
	export DEBIAN_FRONTEND=noninteractive
	install_sos() { apt-get -qq install -y sosreport >/dev/null 2>&1; }
	remove_sos() { apt-get -qq purge -y sosreport 2>&1 | grep -i 'warning' || true; }
	apt-get -qq install -y /dist/*.deb >/dev/null 2>&1
	files() { dpkg -L clifr clifrd; }
	sos_dirs() { ls -d /usr/lib/python3/dist-packages/sos 2>/dev/null || true; }
	plugins_dir() { echo /usr/lib/python3/dist-packages/sos/report/plugins; }
else
	install_sos() { dnf -q -y install sos >/dev/null 2>&1; }
	remove_sos() { dnf -q -y remove sos 2>&1 | grep -i 'warning\|error' || true; }
	dnf -q -y install /dist/*.rpm >/dev/null 2>&1
	files() { rpm -ql clifr clifrd; }
	sos_dirs() { ls -d /usr/lib/python3*/site-packages/sos 2>/dev/null || true; }
	plugins_dir() { rpm -ql sos | sed -n 's|/__init__.py$||p' | grep 'report/plugins$'; }
fi
[ -z "$(sos_dirs)" ] || { echo "without sos, a sos directory exists: $(sos_dirs)"; exit 1; }
echo "without sos: no sos directory"
install_sos
plugins=$(plugins_dir)
test -L "$plugins/clifr.py" || { echo "sos installed after clifrd: no plugin link in $plugins"; exit 1; }
echo "sos installed after clifrd: plugin linked"
remove_sos
[ -z "$(sos_dirs)" ] || { echo "sos removed: left $(sos_dirs): $(find "$(sos_dirs)" | head -5)"; exit 1; }
echo "sos removed: no sos directory left"
install_sos
plugins=$(plugins_dir)
test -L "$plugins/clifr.py" || { echo "sos installed again: no plugin link"; exit 1; }
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
