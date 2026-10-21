#!/bin/bash
# Run as root inside a test VM by packaging/vm.sh test: WHAT is any of
# service ebpf e2e truth sos.
set -uo pipefail
T=$(dirname "$(readlink -f "$0")")
what=${*:-service ebpf e2e truth sos}
pass=0 fail=0
ok() { echo "PASS $*"; pass=$((pass + 1)); }
bad() { echo "FAIL $*"; fail=$((fail + 1)); }
has() { [[ " $what " == *" $1 "* ]]; }
rhel=false
command -v dnf >/dev/null && rhel=true
echo "== $(. /etc/os-release; echo "$PRETTY_NAME"), kernel $(uname -r), SELinux $(getenforce 2>/dev/null || echo none)"

if ! command -v clifrd >/dev/null; then
	if $rhel; then
		dnf -q -y install "$T"/pkg/*.rpm lsof sysstat sos >/dev/null 2>&1
		systemctl enable --now clifrd
	else
		apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y "$T"/pkg/*.deb lsof sysstat sosreport >/dev/null 2>&1
	fi
	usermod -aG clifr tester
elif $rhel; then # a VM kept from an earlier test: these packages, even if the version is the same
	rpm -U --force --quiet "$T"/pkg/*.rpm && systemctl restart clifrd
else
	dpkg -i "$T"/pkg/*.deb >/dev/null && systemctl restart clifrd
fi
# Nothing of the new run is on disk before its first flush (5 min by
# default); until then the latest moment is the old run's shutdown, when
# its connections were closed.
t0=$(date +%s)
recorded_to() { date -d "$(clifr info 2>/dev/null | awk '/^Recording:/ {print $5, $6}')" +%s 2>/dev/null || echo 0; }
until [ "$(recorded_to)" -gt "$t0" ] || [ $(($(date +%s) - t0)) -gt 400 ]; do sleep 10; done
echo "   first data of this run readable after $(($(date +%s) - t0)) s"
command -v clifrd >/dev/null && ok "packages installed: $(clifrd --version)" || bad "packages not installed"

if has service; then
	systemctl is-active --quiet clifrd && ok "service active" || bad "service not active: $(systemctl status clifrd --no-pager 2>&1 | tail -5)"
	journalctl -u clifrd -b --no-pager -o cat | grep -iE "level=(warn|error)|error|warn" | head -5
	echo "   $(clifrd doctor 2>&1 | tail -1)"
	# The latest data on disk (the last flush; newer samples are still in memory).
	end=$(clifr info 2>/dev/null | awk '/^Recording:/ {print $5, $6}')
	n=$(clifr --plain --at "$end" "ps aux" 2>/dev/null | wc -l)
	[ "$n" -gt 50 ] && ok "clifr ps aux from the service's recording: $n lines" || bad "clifr ps aux: $n lines"
	n=$(clifr --plain --at "$end" dmesg 2>/dev/null | grep -vc '^#')
	[ "$n" -gt 10 ] && ok "clifr dmesg from the service's recording: $n lines" || bad "clifr dmesg: $n lines (the kernel log is not recorded)"
	n=$(clifr --plain --at "$end" "systemctl list-units" 2>/dev/null | grep -c '\.service ')
	[ "$n" -gt 10 ] && ok "clifr systemctl list-units from the service's recording: $n services" || bad "clifr systemctl list-units: $n services (systemd units are not recorded)"
	out=$(su - tester -c "clifr --plain --at '$end' 'ss -tan'" 2>&1)
	n=$(echo "$out" | grep -vc '^#')
	[ "$n" -gt 1 ] && ok "clifr as a member of the clifr group: ss -tan $n lines" || bad "clifr as the clifr group at $end: $(echo "$out" | tail -3)"
	stat -c '%a %U:%G %n' /var/lib/clifr
	if $rhel; then
		d=$(grep -c 'avc: *denied.*clifrd' /var/log/audit/audit.log 2>/dev/null)
		[ "${d:-0}" -eq 0 ] && ok "no SELinux denials for clifrd" || { bad "$d SELinux denials for clifrd"; grep 'avc: *denied.*clifrd' /var/log/audit/audit.log | sed 's/.*avc: *denied *//' | sort | uniq -c | head -20; }
	fi
fi

if has ebpf; then
	for m in "" "--ebpf-force-perf --ebpf-classic-fork" "--ebpf-kprobes"; do
		out=$(clifrd --test-ebpf $m 2>&1)
		p=$(echo "$out" | grep -c '^PASS') f=$(echo "$out" | grep -c '^FAIL')
		[ "$f" -eq 0 ] && [ "$p" -gt 0 ] && ok "--test-ebpf $m: $p pass" || { bad "--test-ebpf $m: $p pass, $f fail"; echo "$out" | grep -E '^FAIL|rror' | head; }
	done
fi

if has e2e; then
	systemctl stop clifrd
	out=$(cd "$T/test/e2e" && CLIFR_TEST_BIN=$T/bin "$T/e2e.test" -test.count=1 -test.timeout 20m 2>&1)
	echo "$out" | tail -1 | grep -q '^PASS' && ok "e2e" || { bad "e2e"; echo "$out" | grep -E 'FAIL|_test.go' | head -20; }
	systemctl start clifrd
fi

if has truth; then
	systemctl stop clifrd
	out=$(cd "$T/test/truth" && CLIFR_TEST_BIN=$T/bin "$T/truth.test" -test.count=1 -test.v -test.timeout 40m -scale small 2>&1)
	sum=$(echo "$out" | grep -E 'checks differ' | tail -1 | sed 's/^ *//')
	echo "$out" | grep -E 'DIFF' | head -10
	echo "$sum" | grep -q '^0 of' && ok "ground truth small: $sum" || bad "ground truth small: ${sum:-no result}"
	systemctl start clifrd
fi

if has sos; then
	rm -rf /var/tmp/sostest && mkdir -p /var/tmp/sostest
	sos report -o clifr --batch -k clifr.window=10m --tmp-dir /var/tmp/sostest >/dev/null 2>&1
	f=$(ls /var/tmp/sostest/sosreport-*.tar.xz 2>/dev/null | head -1)
	if [ -n "$f" ] && tar -C /var/tmp/sostest -xJf "$f" --wildcards '*/sos_commands/clifr/clifr-bundle.tar' 2>/dev/null; then
		b=$(ls /var/tmp/sostest/*/sos_commands/clifr/clifr-bundle.tar)
		r=$(clifr -D "$b" info 2>&1 | grep '^Recording:')
		[ -n "$r" ] && ok "sos report bundle reads: $r" || bad "sos bundle unreadable"
	else
		bad "sos report has no clifr bundle"
	fi
fi
echo "== $pass passed, $fail failed"
