#!/bin/bash
# packaging/build.sh: build the clifr and clifrd packages (.deb and .rpm,
# x86_64) into dist/.
#
#   packaging/build.sh                         (needs docker)
#   DOCKER="sudo docker" packaging/build.sh    (if only root may use it)
#
# At a release tag (HEAD tagged vX.Y.Z, clean tree) the packages are version
# X.Y.Z; otherwise a snapshot of the next release, X.Y.Z~git..., which sorts
# before it.
#
# clifrd is static (CGO_ENABLED=0) and runs anywhere. clifr links DuckDB
# (cgo): it is built in a Rocky Linux 8 container with gcc-toolset-13, so it
# needs only glibc 2.28 (RHEL 8+, Ubuntu 20.04+). The .rpm is made in the same
# image with rpmbuild; the .deb with dpkg-deb on this machine.
set -euo pipefail
cd "$(dirname "$0")/.."
tag=$(git describe --exact-match --tags --match 'v[0-9]*.[0-9]*.[0-9]*' HEAD 2>/dev/null || true)
if [ -n "$tag" ] && [ -n "${VERSION:-}" ] && [ "$VERSION" != "${tag#v}" ]; then
	echo "build.sh: VERSION=$VERSION but HEAD is tagged $tag" >&2
	exit 1
fi
VERSION=${VERSION:-${tag#v}}
VERSION=${VERSION:-0.1.0}
DOCKER=${DOCKER:-docker}
# Pinned by digest (the multi-arch index of rockylinux:8 as of 2023-11-24, used
# for every package so far): a moved tag cannot change a build. The compiler
# and rpmbuild are still installed with dnf at build time (printed below).
IMAGE=${IMAGE:-rockylinux:8@sha256:9794037624aaa6212aeada1d28861ef5e0a935adaf93e4ef79837119f2a2d04c}

maintainer="Jorge L. Rueda B. <jlrueda@gmail.com>"
homepage=https://github.com/jlruedab/clifr
rev=$(git rev-parse --short=12 HEAD)
git diff --quiet HEAD -- . ':!sessions.txt' ':!docs/clifr command line flight.txt' || rev=$rev.dirty
# Snapshots sort by the commit's time (UTC, to the second), then its hash:
# a later commit is always a newer package, and rebuilding a commit gives the
# same version. (The build date alone made same-day builds sort by hash.)
snap=$(TZ=UTC0 git log -1 --format=%cd --date=format-local:%Y%m%d.%H%M%S HEAD).$rev
full=$VERSION-$snap              # what --version prints
debver=$VERSION~git$snap         # sorts before the release $VERSION
rpmrel=0.git$snap
if [ -n "$tag" ] && [ "${rev%.dirty}" = "$rev" ]; then # the release itself
	full=$VERSION debver=$VERSION rpmrel=1
fi

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
		echo \"   \$(rpm -q gcc-toolset-13-gcc-c++), glibc \$(rpm -q --qf '%{VERSION}-%{RELEASE}' glibc)\"
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
# Licenses: clifr is AGPL-3.0-only; the eBPF programs GPL-2.0-only OR
# BSD-2-Clause (their sources ship with clifrd); the sos plugin GPL-2.0-only
# (as sos); third-party notices from what each binary links.
for p in clifr clifrd; do
	install -D -m 0644 LICENSE "$stage/$p/usr/share/doc/$p/LICENSE"
	install -D -m 0644 LICENSING.md "$stage/$p/usr/share/doc/$p/LICENSING.md"
done
packaging/notices.sh "$dist/clifr" "$c/usr/share/doc/clifr/THIRD_PARTY_NOTICES"
packaging/notices.sh "$dist/clifrd" "$stage/clifrd/usr/share/doc/clifrd/THIRD_PARTY_NOTICES"
install -D -m 0644 internal/bpfproc/procevents.bpf.c "$d/usr/share/doc/clifrd/ebpf/procevents.bpf.c"
install -D -m 0644 internal/bpftcp/tcpevents.bpf.c "$d/usr/share/doc/clifrd/ebpf/tcpevents.bpf.c"
install -D -m 0755 "$dist/clifrd" "$d/usr/sbin/clifrd"
install -D -m 0644 deploy/clifrd.service "$d/usr/lib/systemd/system/clifrd.service"
install -D -m 0644 deploy/clifr-sysusers.conf "$d/usr/lib/sysusers.d/clifr.conf"
install -D -m 0644 deploy/clifrd.yml "$d/etc/clifr/clifrd.yml"
install -D -m 0644 "$stage/man/clifrd.8" "$d/usr/share/man/man8/clifrd.8"
install -D -m 0644 packaging/completion/clifrd.bash "$d/usr/share/bash-completion/completions/clifrd"
install -D -m 0644 deploy/sos/clifr.py "$d/usr/share/clifr/sos/clifr.py"
install -D -m 0644 deploy/clifrd-metrics.conf "$d/usr/share/clifr/clifrd-metrics.conf" # opt-in: copied by the admin
install -D -m 0644 deploy/clifrd-serve.conf "$d/usr/share/clifr/clifrd-serve.conf"     # opt-in: copied by the admin
gzip -9n "$c/usr/share/man/man1/clifr.1" "$d/usr/share/man/man8/clifrd.8"

echo "== rpm (in $IMAGE)"
mkdir -p "$stage/rpm" && cp -a "$c" "$stage/rpm/clifr" && cp -a "$d" "$stage/rpm/clifrd"
$DOCKER run --rm -v "$PWD:/src" -w /src "$IMAGE" bash -euc "
	dnf -q -y install rpm-build systemd >/dev/null
	rpmbuild -bb --quiet --define '_topdir /tmp/rpm' --define 'ver $VERSION' --define 'rel $rpmrel' --define 'homepage $homepage' \
		--define 'stage /src/dist/stage/rpm' --define 'dist %{nil}' packaging/rpm/clifr.spec
	cp /tmp/rpm/RPMS/x86_64/*.rpm dist/
	chown $owner dist/*.rpm"
rm -rf "$stage/rpm"

echo "== deb"
# The sos plugin stays in /usr/share/clifr/sos, as in the rpm: clifrd's
# postinst links it into sos's directory while sosreport is installed (a
# file trigger on that directory: packaging/deb/clifrd/triggers).
for p in clifr clifrd; do
	r=$stage/$p
	mkdir -p "$r/DEBIAN" "$r/usr/share/doc/$p"
	cat >"$r/usr/share/doc/$p/copyright" <<-EOT
		Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
		Upstream-Name: clifr
		Upstream-Contact: $maintainer
		Comment: clifr is licensed under AGPL-3.0-only (see LICENSING.md).
		 Third-party software and its licenses: THIRD_PARTY_NOTICES in this
		 directory.

		Files: *
		Copyright: 2026 Jorge L. Rueda B.
		License: AGPL-3.0-only
		 The full text is in /usr/share/doc/$p/LICENSE.
	EOT
	if [ $p = clifrd ]; then
		cat >>"$r/usr/share/doc/$p/copyright" <<-EOT

			Files: usr/share/doc/clifrd/ebpf/*
			Copyright: 2026 Jorge L. Rueda B.
			License: GPL-2.0-only or BSD-2-Clause
			Comment: The eBPF programs compiled into clifrd.

			Files: usr/share/clifr/sos/clifr.py
			Copyright: 2026 Jorge L. Rueda B.
			License: GPL-2.0-only
			Comment: The plugin for sos report, licensed as sos is.

			License: GPL-2.0-only
			 On Debian systems, the full text of the GNU General Public License
			 version 2 can be found in /usr/share/common-licenses/GPL-2.

			License: BSD-2-Clause
			 Copyright (c) 2026 Jorge L. Rueda B.
			 .
			 Redistribution and use in source and binary forms, with or without
			 modification, are permitted provided that the following conditions are met:
			 .
			 1. Redistributions of source code must retain the above copyright notice,
			    this list of conditions and the following disclaimer.
			 .
			 2. Redistributions in binary form must reproduce the above copyright notice,
			    this list of conditions and the following disclaimer in the documentation
			    and/or other materials provided with the distribution.
			 .
			 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
			 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
			 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
			 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
			 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
			 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
			 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
			 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
			 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
			 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
			 POSSIBILITY OF SUCH DAMAGE.
		EOT
	fi
	size=$(du -sk --exclude=DEBIAN "$r" | cut -f1)
	{
		echo "Package: $p"
		echo "Version: $debver"
		echo "Architecture: amd64"
		echo "Maintainer: $maintainer"
		echo "Homepage: $homepage"
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
		cp packaging/deb/clifrd/postinst packaging/deb/clifrd/prerm packaging/deb/clifrd/postrm packaging/deb/clifrd/triggers "$r/DEBIAN/"
		chmod 0644 "$r/DEBIAN/triggers"
		echo /etc/clifr/clifrd.yml >"$r/DEBIAN/conffiles"
	fi
	dpkg-deb --root-owner-group -Zxz --build "$r" "$dist/${p}_${debver}_amd64.deb" >/dev/null
done
rm -rf "$stage"
ls -la "$dist"/*.deb "$dist"/*.rpm
