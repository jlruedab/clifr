#!/bin/bash
# packaging/build.sh: build the clifr and clifrd packages (.deb and .rpm,
# x86_64) into dist/.
#
#   packaging/build.sh                         (needs docker)
#   DOCKER="sudo docker" packaging/build.sh    (if only root may use it)
#
# clifrd is static (CGO_ENABLED=0) and runs anywhere. clifr links DuckDB
# (cgo): it is built in a Rocky Linux 8 container with gcc-toolset-13, so it
# needs only glibc 2.28 (RHEL 8+, Ubuntu 20.04+). The .rpm is made in the same
# image with rpmbuild; the .deb with dpkg-deb on this machine.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${VERSION:-0.1.0}
DOCKER=${DOCKER:-docker}
IMAGE=rockylinux:8

rev=$(git rev-parse --short=12 HEAD)
git diff --quiet HEAD -- . ':!sessions.txt' ':!docs/clifr command line flight.txt' || rev=$rev.dirty
snap=$(date -u +%Y%m%d).$rev
full=$VERSION-$snap              # what --version prints
debver=$VERSION~git$snap         # sorts before the release $VERSION
rpmrel=0.git$snap

dist=$PWD/dist
stage=$dist/stage
rm -rf "$stage" && mkdir -p "$stage" "$dist/.cache"
rm -f "$dist"/*.deb "$dist"/*.rpm
owner=$(stat -c %u:%g .)

echo "== clifrd $full (static)"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.releaseVersion=$full" -o "$dist/clifrd" ./cmd/clifrd

echo "== clifr $full (in $IMAGE)"
# The host's Go and module cache, mounted read-only (copied under dist/:
# a snap docker sees no hidden or system directories).
rm -rf "$dist/.cache/go" && cp -a "$(go env GOROOT)" "$dist/.cache/go"
$DOCKER run --rm -v "$dist/.cache/go:/usr/local/go:ro" -v "$(go env GOMODCACHE):/gomod:ro" -v "$PWD:/src" \
	-e GOMODCACHE=/gomod -e GOFLAGS=-mod=mod -e GOCACHE=/src/dist/.cache/gocache -e GOTOOLCHAIN=local -e GOPROXY=off \
	-w /src "$IMAGE" bash -euc "
		dnf -q -y install gcc-toolset-13-gcc-c++ >/dev/null
		source /opt/rh/gcc-toolset-13/enable
		CGO_ENABLED=1 /usr/local/go/bin/go build -buildvcs=false -trimpath -ldflags '-s -w -X main.releaseVersion=$full' -o dist/clifr ./cmd/clifr
		chown -R $owner dist"
glibc=$(objdump -T "$dist/clifr" | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1)
echo "   clifr needs $glibc"

echo "== man pages, completion"
packaging/genman.sh "$dist/clifrd" "$dist/clifr" "$full" "$stage/man"
# Every clifrd option is in its completion (clifr's: cmd/clifr TestCompletion).
for o in $("$dist/clifrd" --help 2>&1 | grep -o '^  -[a-z-]*' | sed 's/^  -//'); do
	[ ${#o} -le 1 ] && continue
	grep -qw -- "--$o" packaging/completion/clifrd.bash || { echo "clifrd --$o missing from packaging/completion/clifrd.bash"; exit 1; }
done

echo "== file trees"
c=$stage/clifr d=$stage/clifrd
install -D -m 0755 "$dist/clifr" "$c/usr/bin/clifr"
install -D -m 0644 "$stage/man/clifr.1" "$c/usr/share/man/man1/clifr.1"
install -D -m 0644 packaging/completion/clifr.bash "$c/usr/share/bash-completion/completions/clifr"
install -D -m 0644 README.md "$c/usr/share/doc/clifr/README.md"
install -D -m 0755 "$dist/clifrd" "$d/usr/sbin/clifrd"
install -D -m 0644 deploy/clifrd.service "$d/usr/lib/systemd/system/clifrd.service"
install -D -m 0644 deploy/clifr-sysusers.conf "$d/usr/lib/sysusers.d/clifr.conf"
install -D -m 0644 deploy/clifrd.yml "$d/etc/clifr/clifrd.yml"
install -D -m 0644 "$stage/man/clifrd.8" "$d/usr/share/man/man8/clifrd.8"
install -D -m 0644 packaging/completion/clifrd.bash "$d/usr/share/bash-completion/completions/clifrd"
install -D -m 0644 deploy/sos/clifr.py "$d/usr/share/clifr/sos/clifr.py"
gzip -9n "$c/usr/share/man/man1/clifr.1" "$d/usr/share/man/man8/clifrd.8"

echo "== rpm (in $IMAGE)"
mkdir -p "$stage/rpm" && cp -a "$c" "$stage/rpm/clifr" && cp -a "$d" "$stage/rpm/clifrd"
$DOCKER run --rm -v "$PWD:/src" -w /src "$IMAGE" bash -euc "
	dnf -q -y install rpm-build systemd >/dev/null
	rpmbuild -bb --quiet --define '_topdir /tmp/rpm' --define 'ver $VERSION' --define 'rel $rpmrel' \
		--define 'stage /src/dist/stage/rpm' --define 'dist %{nil}' packaging/rpm/clifr.spec
	cp /tmp/rpm/RPMS/x86_64/*.rpm dist/
	chown $owner dist/*.rpm"
rm -rf "$stage/rpm"

echo "== deb"
# Debian ships the sos plugin straight into sos's directory.
install -D -m 0644 deploy/sos/clifr.py "$d/usr/lib/python3/dist-packages/sos/report/plugins/clifr.py"
rm -rf "$d/usr/share/clifr"
for p in clifr clifrd; do
	r=$stage/$p
	mkdir -p "$r/DEBIAN" "$r/usr/share/doc/$p"
	printf 'clifr\nLicense: proprietary (to be decided)\n' >"$r/usr/share/doc/$p/copyright"
	size=$(du -sk --exclude=DEBIAN "$r" | cut -f1)
	{
		echo "Package: $p"
		echo "Version: $debver"
		echo "Architecture: amd64"
		echo "Maintainer: clifr <clifr@example.invalid>"
		echo "Installed-Size: $size"
		echo "Section: admin"
		echo "Priority: optional"
		if [ $p = clifr ]; then
			echo "Depends: libc6 (>= 2.28), libstdc++6"
			echo "Description: shows what ps, ss, lsof, vmstat and others printed at a past moment"
			echo " clifr rebuilds the output of ps, lsof, ss, netstat, vmstat, mpstat, iostat,"
			echo " free, uptime, df and mount for a past moment or range from a recording made"
			echo " by clifrd, on the recorded host or elsewhere (a bundle)."
		else
			echo "Depends: systemd"
			echo "Recommends: clifr"
			echo "Suggests: sosreport"
			echo "Description: flight recorder of processes, sockets, open files and counters"
			echo " clifrd records which processes existed, which sockets and open files each"
			echo " one held, process start and exit events and the system-wide counters, with"
			echo " eBPF and /proc, for clifr to query. It includes a plugin for sos report."
		fi
	} >"$r/DEBIAN/control"
	if [ $p = clifrd ]; then
		cp packaging/deb/clifrd/postinst packaging/deb/clifrd/prerm packaging/deb/clifrd/postrm "$r/DEBIAN/"
		echo /etc/clifr/clifrd.yml >"$r/DEBIAN/conffiles"
	fi
	dpkg-deb --root-owner-group -Zxz --build "$r" "$dist/${p}_${debver}_amd64.deb" >/dev/null
done
rm -rf "$stage"
ls -la "$dist"/*.deb "$dist"/*.rpm
