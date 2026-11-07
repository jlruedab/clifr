# Built by packaging/build.sh from binaries it built itself (clifr in a
# Rocky Linux 8 container for glibc 2.28): no build step here.
%global debug_package %{nil}
%global __strip /bin/true

Name:           clifr
Version:        %{ver}
Release:        %{rel}%{?dist}
Summary:        Shows what ps, ss, lsof, vmstat and others printed at a past moment
License:        AGPL-3.0-only
Packager:       Jorge L. Rueda B. <jlrueda@gmail.com>
ExclusiveArch:  x86_64

%description
clifr rebuilds the output of ps, lsof, ss, netstat, vmstat, mpstat, iostat,
free, uptime, df and mount for a past moment or range from a recording made
by clifrd, on the recorded host or elsewhere (a bundle).

%package -n clifrd
Summary:        Flight recorder of processes, sockets, open files and system counters
License:        AGPL-3.0-only AND (GPL-2.0-only OR BSD-2-Clause) AND GPL-2.0-only
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Recommends:     clifr

%description -n clifrd
clifrd records which processes existed, which sockets and open files each one
held, process start and exit events and the system-wide counters, with eBPF
and /proc, for clifr to query. It includes a plugin for sos report.

%install
cp -a %{stage}/clifr/. %{buildroot}/
cp -a %{stage}/clifrd/. %{buildroot}/

%post -n clifrd
systemd-sysusers /usr/lib/sysusers.d/clifr.conf || :
%systemd_post clifrd.service

%preun -n clifrd
%systemd_preun clifrd.service
if [ $1 -eq 0 ]; then
	d=$(rpm -ql sos 2>/dev/null | sed -n 's|/__init__.py$||p' | grep 'sos/report/plugins$' | head -1)
	[ -n "$d" ] && [ -L "$d/clifr.py" ] && rm -f "$d/clifr.py" || :
fi

%postun -n clifrd
%systemd_postun_with_restart clifrd.service

# The sos plugin lives in sos's own directory, whose path depends on the
# Python version: linked there when both packages are installed.
%triggerin -n clifrd -- sos
d=$(rpm -ql sos 2>/dev/null | sed -n 's|/__init__.py$||p' | grep 'sos/report/plugins$' | head -1)
[ -n "$d" ] && ln -sf /usr/share/clifr/sos/clifr.py "$d/clifr.py" || :

# sos removed (not upgraded: $2, the sos packages left, is 0): the link goes
# first, so that rpm can remove sos's directory.
%triggerun -n clifrd -- sos
[ "$2" -eq 0 ] || exit 0
d=$(rpm -ql sos 2>/dev/null | sed -n 's|/__init__.py$||p' | grep 'sos/report/plugins$' | head -1)
[ -n "$d" ] && [ -L "$d/clifr.py" ] && rm -f "$d/clifr.py" || :

%files
/usr/bin/clifr
/usr/share/man/man1/clifr.1*
/usr/share/bash-completion/completions/clifr
%doc /usr/share/doc/clifr

%files -n clifrd
/usr/sbin/clifrd
/usr/lib/systemd/system/clifrd.service
/usr/lib/sysusers.d/clifr.conf
%dir /etc/clifr
%config(noreplace) /etc/clifr/clifrd.yml
/usr/share/man/man8/clifrd.8*
/usr/share/bash-completion/completions/clifrd
/usr/share/clifr
%doc /usr/share/doc/clifrd
