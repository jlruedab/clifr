#!/bin/bash
# genman.sh CLIFRD CLIFR VERSION OUTDIR: man pages from the binaries' own
# help texts (clifr.1, clifrd.8), so they cannot drift from them.
set -euo pipefail
clifrd=$1 clifr=$2 version=$3 out=$4
date=$(date -u +%Y-%m-%d)
mkdir -p "$out"

# roff-safe preformatted text from standard input.
pre() {
	echo ".nf"
	sed -e 's/\\/\\e/g' -e "s/^\([.']\)/\\\\\&\1/"
	echo ".fi"
}

{
	echo ".TH CLIFR 1 \"$date\" \"clifr $version\" \"User Commands\""
	echo ".SH NAME"
	echo "clifr \\- show what ps, ss, lsof, vmstat and others printed at a past moment"
	echo ".SH DESCRIPTION"
	"$clifr" --help | pre
	echo ".SH COMMANDS"
	for c in ps lsof ss netstat vmstat mpstat iostat free uptime df mount events life oom mounts pstore diff; do
		echo ".SS $c"
		"$clifr" help "$c" | pre
	done
	echo ".SH FILES"
	echo ".TP"
	echo ".I /var/lib/clifr"
	echo "the recording (root and the clifr group)"
	echo ".SH SEE ALSO"
	echo ".BR clifrd (8)"
} >"$out/clifr.1"

{
	echo ".TH CLIFRD 8 \"$date\" \"clifr $version\" \"System Administration\""
	echo ".SH NAME"
	echo "clifrd \\- record processes, sockets, open files and system counters for clifr"
	echo ".SH DESCRIPTION"
	"$clifrd" --help 2>&1 | pre
	echo ".SH BUNDLE"
	"$clifrd" bundle --help 2>&1 | pre
	echo ".SH SEALING"
	"$clifrd" seal-setup --help 2>&1 | pre
	echo ".SH FILES"
	echo ".TP"
	echo ".I /etc/clifr/clifrd.yml"
	echo "settings (flags override them)"
	echo ".TP"
	echo ".I /var/lib/clifr"
	echo "the recording"
	echo ".SH SEE ALSO"
	echo ".BR clifr (1),"
	echo ".BR sos (1)"
} >"$out/clifrd.8"
