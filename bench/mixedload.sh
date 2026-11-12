#!/bin/bash
# bench/mixedload.sh: a small server's mixed load for clifr soak tests, run
# inside a test VM (Rocky 8, Alma 9, Ubuntu 22.04) as root.
#
#   mixedload.sh setup    install PostgreSQL and nginx, configure them, install
#                         this script as /usr/local/sbin/clifr-mixedload and
#                         the unit clifr-mixedload.service (not started)
#   mixedload.sh run      the load itself (what the unit runs)
#   mixedload.sh remove   stop and remove the unit (the packages stay)
#
# The load (about 5-10% of a 4-vCPU VM's CPU):
#   - PostgreSQL: pgbench over TCP, 4 persistent connections at 200 tps, and 2
#     clients opening a new connection per transaction at 10 tps (10 conn/s);
#     every 15 min a pg_dump compressed to a file, the oldest of 8 deleted
#   - nginx: a client making 5 requests/s, each on a new connection, and 20
#     keep-alive connections that each make a request every 5-30 s, some
#     reopened every few minutes
#   - cron-like jobs: every minute a burst of short processes (find, sort,
#     tar, gzip, sha256sum, sed: about 40-80 processes); every 10 min a few
#     hundred in a shell loop
#   - files: a writer appending to logs rotated every 10 min; a process holding
#     200 files, 20 of them reopened every 2 min
#   - mounts: every 30 min a tmpfs mounted, written to and unmounted 10 min later
#   - memory: every hour a process holding 400 MiB for 2 minutes
#   - a job run as an ordinary user (nobody) every 5 min
set -u
self=$(readlink -f "$0")
W=/var/lib/clifr-mixedload   # work directory: logs, dumps, held files

pgbin() { # the directory with pgbench and pg_dump
	local d
	for d in /usr/bin /usr/lib/postgresql/*/bin; do
		[[ -x $d/pgbench ]] && { echo "$d"; return; }
	done
	return 1
}

setup() {
	set -e
	if command -v apt-get >/dev/null; then
		export DEBIAN_FRONTEND=noninteractive
		apt-get -q update >/dev/null
		apt-get -q -y install postgresql postgresql-contrib nginx >/dev/null
		hba=$(ls /etc/postgresql/*/main/pg_hba.conf)
		pgsvc=postgresql
	else
		dnf -q -y install postgresql-server postgresql-contrib nginx >/dev/null
		[[ -f /var/lib/pgsql/data/PG_VERSION ]] || postgresql-setup --initdb >/dev/null
		hba=/var/lib/pgsql/data/pg_hba.conf
		pgsvc=postgresql
	fi
	# a test VM: TCP from loopback without a password
	grep -q '^host all all 127.0.0.1/32 trust' "$hba" ||
		sed -i '1i host all all 127.0.0.1/32 trust' "$hba"
	systemctl enable -q --now "$pgsvc" nginx
	systemctl restart "$pgsvc"
	b=$(pgbin)
	su - postgres -c "psql -q -c 'SELECT 1' bench" >/dev/null 2>&1 ||
		su - postgres -c "createdb bench && $b/pgbench -q -i -s 10 bench" >/dev/null 2>&1
	# static files for nginx: a page and a 1 MiB file
	html=/usr/share/nginx/html
	[[ -d /var/www/html ]] && html=/var/www/html
	echo "<html><body>clifr mixed load</body></html>" > "$html/load.html"
	head -c 1048576 /dev/urandom > "$html/load.bin"
	mkdir -p "$W"
	install -m 0755 "$self" /usr/local/sbin/clifr-mixedload
	cat > /etc/systemd/system/clifr-mixedload.service <<-EOF
	[Unit]
	Description=clifr soak: mixed load
	After=postgresql.service nginx.service
	[Service]
	ExecStart=/usr/local/sbin/clifr-mixedload run
	KillMode=control-group
	Restart=on-failure
	RestartSec=10
	EOF
	systemctl daemon-reload
	echo "setup done: $(command -v nginx) $b/pgbench"
}

# Each part runs in a loop of its own: a part that fails starts again.
forever() { while :; do "$@"; sleep 5; done; }

pg() {
	local b; b=$(pgbin)
	forever "$b/pgbench" -h 127.0.0.1 -U postgres -n -c 4 -j 1 -R 200 -T 86400 bench >/dev/null 2>&1 &
	forever "$b/pgbench" -h 127.0.0.1 -U postgres -n -C -c 2 -j 1 -R 10 -T 86400 bench >/dev/null 2>&1 &
	while :; do
		sleep 900
		"$b/pg_dump" -h 127.0.0.1 -U postgres bench | gzip > "$W/bench-$(date +%s).sql.gz"
		ls -t "$W"/bench-*.sql.gz | tail -n +9 | xargs -r rm -f
	done &
}

http() {
	# short requests: a new connection each (curl exits after one)
	while :; do
		curl -s -o /dev/null http://127.0.0.1/load.html
		(( RANDOM % 20 == 0 )) && curl -s -o /dev/null http://127.0.0.1/load.bin
		sleep 0.2
	done &
	# keep-alive connections
	python3 - <<-'EOF' &
	import http.client, random, time
	conns = [None] * 20
	nxt = [0.0] * 20
	while True:
	    now = time.time()
	    for i in range(20):
	        if now < nxt[i]:
	            continue
	        try:
	            if conns[i] is None or random.random() < 0.05:
	                if conns[i] is not None:
	                    conns[i].close()
	                conns[i] = http.client.HTTPConnection("127.0.0.1", 80, timeout=10)
	            conns[i].request("GET", "/load.html")
	            conns[i].getresponse().read()
	        except Exception:
	            conns[i] = None
	        nxt[i] = now + random.uniform(5, 30)
	    time.sleep(1)
	EOF
}

jobs_() {
	while :; do
		sleep 60
		(
			find /usr/share/doc -maxdepth 2 -name '*.gz' | head -50 | sort > "$W/docs.txt"
			tar -C /etc -cf - ssh systemd 2>/dev/null | gzip > "$W/etc.tar.gz"
			for f in /etc/*.conf; do sha256sum "$f"; done > "$W/sums.txt" 2>/dev/null
			sed -n '1,100p' /var/log/*.log 2>/dev/null | sort | uniq -c | sort -rn | head > /dev/null
			ls -lR /usr/lib/systemd > /dev/null 2>&1
		) 2>/dev/null
		if (( 10#$(date +%M) % 10 == 0 )); then
			for i in $(seq 300); do /bin/true; done
			bash -c 'for i in $(seq 50); do date +%s%N | md5sum; done' > /dev/null
		fi
		if (( 10#$(date +%M) % 5 == 0 )); then
			su -s /bin/bash nobody -c 'cd /tmp; ps aux > /dev/null; sleep 20; id' > /dev/null 2>&1 &
		fi
	done &
}

files() {
	# logs rotated every 10 min
	while :; do
		for i in $(seq 600); do
			echo "$(date '+%F %T') line $i $RANDOM" >> "$W/app.log"
			sleep 1
		done
		mv -f "$W/app.log" "$W/app.log.1"
	done &
	# 200 held files, 20 reopened every 2 min
	python3 - "$W" <<-'EOF' &
	import os, sys, time, random
	d = os.path.join(sys.argv[1], "held")
	os.makedirs(d, exist_ok=True)
	fs = [open(os.path.join(d, f"f{i}"), "a") for i in range(200)]
	while True:
	    time.sleep(120)
	    for i in random.sample(range(200), 20):
	        fs[i].close()
	        fs[i] = open(os.path.join(d, f"f{i}"), "a")
	        fs[i].write(f"{time.time()}\n")
	        fs[i].flush()
	EOF
}

mounts() {
	while :; do
		sleep 1200
		mkdir -p /mnt/clifr-load
		mount -t tmpfs -o size=64m clifr-load /mnt/clifr-load &&
			head -c 16777216 /dev/urandom > /mnt/clifr-load/data &&
			sleep 600
		umount /mnt/clifr-load 2>/dev/null
	done &
}

memory() {
	while :; do
		sleep 3480
		python3 -c 'import time; b = bytearray(400 << 20); b[::4096] = b"x" * len(b[::4096]); time.sleep(120)'
	done &
}

run() {
	mkdir -p "$W"
	pg; http; jobs_; files; mounts; memory
	wait
}

remove() {
	systemctl disable -q --now clifr-mixedload 2>/dev/null
	rm -f /etc/systemd/system/clifr-mixedload.service /usr/local/sbin/clifr-mixedload
	systemctl daemon-reload
	umount /mnt/clifr-load 2>/dev/null
	rm -rf "$W"
}

case ${1:-} in
setup) setup ;;
run) run ;;
remove) remove ;;
*) echo "usage: $0 setup|run|remove" >&2; exit 2 ;;
esac
