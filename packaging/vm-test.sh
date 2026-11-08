#!/bin/bash
# Run as root inside a test VM by packaging/vm.sh test: WHAT is any of
# service ebpf e2e truth tls sos.
set -uo pipefail
T=$(dirname "$(readlink -f "$0")")
what=${*:-service ebpf e2e truth tls sos}
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

if has tls; then
	# --metrics and --serve with the admin's certificate (one Node Exporter web
	# configuration file for both) under the unit and its drop-ins, reached at
	# this VM's own address (not loopback).
	ip=$(hostname -I | awk '{print $1}')
	d=/etc/clifr/tlstest
	rm -rf $d && mkdir -m 700 $d && cd $d || exit 1
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 1 -subj /CN=vmtest-ca 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout srv.key -out srv.csr -subj /CN=clifrd 2>/dev/null
	echo "subjectAltName=IP:$ip,IP:127.0.0.1" >ext
	openssl x509 -req -in srv.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out srv.crt -days 1 -extfile ext 2>/dev/null
	cp ca.crt /tmp/vmtest-ca.crt && chmod 644 /tmp/vmtest-ca.crt
	# bcrypt of "vmtest-pw" (cost 10)
	printf 'tls_server_config:\n  cert_file: srv.crt\n  key_file: srv.key\nbasic_auth_users:\n  prom: %s\n' \
		'$2b$10$Q8gBI1CaFT9/r2Az2PsZI.CdKi9QtcHbHNBOahVHhTbtF6CZSwlK6' >web.yml
	chmod 600 web.yml srv.key ca.key
	token=$(clifrd token new --file $d/tokens --comment vmtest 2>&1 | grep -o 'clifr_[A-Za-z0-9_-]*' | head -1)
	cp /etc/clifr/clifrd.yml /etc/clifr/clifrd.yml.vmtest 2>/dev/null || : >/etc/clifr/clifrd.yml.vmtest
	printf '\nmetrics: ":19100"\nmetrics_tls_config: %s/web.yml\n' $d >>/etc/clifr/clifrd.yml
	dropins=/etc/systemd/system/clifrd.service.d
	mkdir -p $dropins
	restart() { # restart and wait until clifrd logs $1
		local since
		since=$(date '+%Y-%m-%d %H:%M:%S')
		systemctl daemon-reload && systemctl restart clifrd
		for _ in $(seq 1 60); do [ "$(journalctl -u clifrd --since "$since" -o cat | grep -c "$1")" -gt 0 ] && return 0; sleep 1; done
		echo "   clifrd did not log '$1':"; journalctl -u clifrd --since "$since" -o cat | tail -5
	}
	scrape() { curl -s -o /dev/null -m 5 -w '%{http_code}' --cacert $d/ca.crt "$@" "https://$ip:19100/metrics"; }

	install -m 0644 /usr/share/clifr/clifrd-metrics.conf $dropins/metrics.conf
	restart "metrics at https://"
	c=$(scrape -u prom:vmtest-pw)
	if [ "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs ]; then
		[ "$c" = 000 ] && ok "tls: metrics at $ip blocked by the shipped drop-in (loopback-only IP)" || bad "tls: metrics at $ip answered $c with the shipped drop-in"
	else # cgroup v1 (RHEL 8): systemd cannot enforce IPAddressDeny/Allow, and says so
		[ "$(journalctl -b -o cat | grep -c "does not support BPF/cgroup based firewalling")" -gt 0 ] &&
			ok "tls: cgroup v1: systemd logs that the drop-in's IP firewall is not enforced (answered $c; documented)" ||
			bad "tls: cgroup v1 without systemd's firewall warning (answered $c)"
	fi
	sed -i "s|^#IPAddressAllow=.*|IPAddressAllow=$ip|" $dropins/metrics.conf
	restart "metrics at https://"
	c1=$(scrape -u prom:vmtest-pw) c2=$(scrape) c3=$(scrape -u prom:wrong)
	[ "$c1" = 200 ] && [ "$c2" = 401 ] && [ "$c3" = 401 ] && ok "tls: metrics over TLS at $ip: password 200, none 401, wrong 401" ||
		bad "tls: metrics: password $c1, none $c2, wrong $c3"
	n=$(curl -s -m 5 --cacert $d/ca.crt -u prom:vmtest-pw "https://$ip:19100/metrics" | grep -c '^node_cpu_seconds_total')
	[ "$n" -gt 0 ] && ok "tls: metrics body: $n node_cpu_seconds_total series" || bad "tls: no node_cpu_seconds_total"
	m=$(curl -s -m 5 "http://$ip:19100/metrics" | grep -c '^node_')
	[ "$m" -eq 0 ] && ok "tls: plain HTTP gets no metrics" || bad "tls: plain HTTP got $m metrics"

	printf 'serve: ":18443"\nserve_tokens: %s/tokens\nserve_tls_config: %s/web.yml\n' $d $d >>/etc/clifr/clifrd.yml
	install -m 0644 /usr/share/clifr/clifrd-serve.conf $dropins/serve.conf
	restart "serve: recording served at https://"
	journalctl -u clifrd -b -o cat | grep "serve: recording served" | tail -1 | sed 's/^/   /'
	rm -f ~tester/.config/clifr/known_hosts
	out=$(su - tester -c "CLIFR_TOKEN=$token clifr --host https://$ip:18443 --tls-ca /tmp/vmtest-ca.crt info" 2>&1 </dev/null)
	echo "$out" | grep -q '^Recording:' && ok "tls: clifr --host --tls-ca: $(echo "$out" | grep '^Recording:')" ||
		bad "tls: clifr --host --tls-ca: $(echo "$out" | tail -3)"
	[ ! -e ~tester/.config/clifr/known_hosts ] && ok "tls: nothing pinned with --tls-ca" || bad "tls: known_hosts written with --tls-ca"
	out=$(su - tester -c "CLIFR_TOKEN=$token clifr --host https://$ip:18443 info" 2>&1 </dev/null)
	echo "$out" | grep -q "not known yet" && ok "tls: without --tls-ca (not a system CA): asks for a pin" || bad "tls: without --tls-ca: $(echo "$out" | tail -2)"
	c=$(curl -s -o /dev/null -m 5 -w '%{http_code}' --cacert $d/ca.crt --tls-max 1.2 "https://$ip:18443/v1/info")
	[ "$c" = 000 ] && ok "tls: --serve refuses TLS 1.2" || bad "tls: --serve answered $c to TLS 1.2"
	[ "$(scrape -u prom:vmtest-pw)" = 200 ] && ok "tls: metrics still 200 with both drop-ins" || bad "tls: metrics with both drop-ins"
	if $rhel; then
		n=$(grep -c 'avc: *denied.*clifrd' /var/log/audit/audit.log 2>/dev/null)
		[ "${n:-0}" -eq 0 ] && ok "tls: no SELinux denials" || bad "tls: $n SELinux denials"
	fi
	# Back to the shipped configuration.
	mv /etc/clifr/clifrd.yml.vmtest /etc/clifr/clifrd.yml
	rm -f $dropins/metrics.conf $dropins/serve.conf /tmp/vmtest-ca.crt
	cd / && rm -rf $d
	systemctl daemon-reload && systemctl restart clifrd
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
