#!/bin/bash
# packaging/test.sh [BUNDLE]: install dist/'s packages in containers of the
# target distributions, with sos, and check them: versions, man pages, the
# sos plugin, clifrd doctor (privileged: this machine's kernel), a query of
# BUNDLE if given, and removal. The service itself needs a VM (systemd).
set -uo pipefail
cd "$(dirname "$0")/.."
DOCKER=${DOCKER:-docker}
fails=0
mounts=(-v "$PWD/dist:/dist:ro" -v "$PWD/packaging/test-in-container.sh:/check.sh:ro")
[ -n "${1:-}" ] && mounts+=(-v "$(realpath "$1"):/bundle.tar:ro")
for img in ubuntu:22.04 ubuntu:24.04 rockylinux:8 rockylinux:9; do
	out=$($DOCKER run --rm --privileged "${mounts[@]}" -e TZ=UTC "$img" bash /check.sh 2>&1)
	if echo "$out" | grep -q "^ALL OK$"; then
		echo "== $img: ok"
	else
		echo "== $img: FAILED"
		fails=$((fails + 1))
	fi
	echo "$out" | grep -v "^ALL OK$" | sed 's/^/   /'
done
exit $fails
