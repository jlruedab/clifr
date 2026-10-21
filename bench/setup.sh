#!/usr/bin/env bash
# One-time setup of the benchmark machine. Run as root.
#
#   sudo bench/setup.sh            # install packages, prepare the pgbench database
#   SCALE=20 sudo bench/setup.sh   # pgbench scale factor (default 20, ~300 MB)
#
# What it does:
#   - installs postgresql, postgresql-contrib (pgbench) and atop
#     (apt on Ubuntu/Debian, dnf on RHEL; PCP is optional and not installed)
#   - stops and disables atop's own background services so atop only runs
#     when the benchmark runs it (configuration R1)
#   - creates database "sosvbench" with pgbench tables at scale $SCALE and
#     sets synchronous_commit=off on it, so throughput is bounded by CPU and
#     memory rather than by fsync latency of the test disk (which makes runs
#     very noisy on virtual disks). This is a benchmark choice; see README.
#   - caps max_wal_size at 512 MB to bound disk use
#   - creates the pg_prewarm extension (run.sh caches the tables before each run)
#   - builds clifr and the bench tools
set -euo pipefail
cd "$(dirname "$0")/.."
SCALE=${SCALE:-20}

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

if command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q postgresql postgresql-contrib atop g++
elif command -v dnf >/dev/null; then
    dnf install -y postgresql-server postgresql-contrib atop gcc-c++
    [[ -d /var/lib/pgsql/data/base ]] || postgresql-setup --initdb
    systemctl enable --now postgresql
fi

# atop ships services that log every 10 minutes; they would add their own
# cost to every configuration.
for u in atop.service atopacct.service atop-rotate.timer atopgpu.service; do
    systemctl disable --now "$u" 2>/dev/null || true
done

# Find the PostgreSQL service unit (Ubuntu: postgresql@16-main, RHEL: postgresql).
PGUNIT=$(systemctl list-units --type=service --no-legend 'postgresql*' | awk '$1 ~ /@/ {print $1; exit}')
PGUNIT=${PGUNIT:-postgresql.service}
systemctl start "$PGUNIT"
echo "PostgreSQL unit: $PGUNIT"

if ! sudo -u postgres psql -lqt | cut -d'|' -f1 | grep -qw sosvbench; then
    sudo -u postgres createdb sosvbench
fi
# Initialise when the tables are missing or empty (e.g. an earlier setup was interrupted).
if [[ "$(sudo -u postgres psql -Atc 'select count(*) from pgbench_branches' sosvbench 2>/dev/null)" != "$SCALE" ]]; then
    sudo -u postgres pgbench -i -q -s "$SCALE" sosvbench
fi
sudo -u postgres psql -q -c "ALTER DATABASE sosvbench SET synchronous_commit = off" sosvbench
# pg_prewarm (postgresql-contrib) loads the tables into the page cache before each run.
sudo -u postgres psql -q -c "CREATE EXTENSION IF NOT EXISTS pg_prewarm" sosvbench
sudo -u postgres psql -q -c "ALTER SYSTEM SET max_connections = 200"
# Cap WAL at 512 MB (default 1 GB): the test disk has little free space.
sudo -u postgres psql -q -c "ALTER SYSTEM SET max_wal_size = '512MB'"
systemctl restart "$PGUNIT"

# Results directory owned by the invoking user, so reports can be written without sudo.
mkdir -p bench/results
chown "${SUDO_UID:-0}:${SUDO_GID:-0}" bench/results

mkdir -p bench/bin
# clifr (the CLI) links DuckDB through cgo; everything else is static Go.
CGO_ENABLED=1 go build -o bench/bin/clifr ./cmd/clifr
export CGO_ENABLED=0
go build -o bench/bin/clifrd ./cmd/clifrd
go build -o bench/bin/load ./bench/load
go build -o bench/bin/benchtool ./bench/benchtool
go build -o bench/bin/report ./bench/report
echo "setup done: database sosvbench (scale $SCALE), binaries in bench/bin/"
