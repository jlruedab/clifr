#!/bin/bash
# packaging/notices.sh BINARY OUT: write the third-party notices of a built
# clifr or clifrd binary to OUT.
#
# The Go modules are read from the binary itself (go version -m), so the list
# is exactly what was linked; each module's license, notice and patents files
# come from the module cache. If the binary links DuckDB's prebuilt library,
# packaging/notices/duckdb-<version>.txt is appended (DuckDB's own license and
# those of the libraries it bundles, taken from the DuckDB source of that
# version); a DuckDB version without such a file is an error, so updating
# duckdb-go-bindings means adding the new version's notices.
set -euo pipefail
bin=$1 out=$2
here=$(dirname "$0")
modcache=$(go env GOMODCACHE)
# The module cache spells upper-case letters as "!" + lower case.
esc() { sed -E 's/([A-Z])/!\L\1/g' <<<"$1"; }
sep() { printf '\n%s\n%s\n\n' "================================================================================" "$1"; }
deps=$(go version -m "$bin" | awk '$1 == "dep" {print $2, $3}')
[ -n "$deps" ] || { echo "notices.sh: no module information in $bin" >&2; exit 1; }
duckdb=
{
	echo "Third-party software in $(basename "$bin")"
	echo
	echo "$(basename "$bin") is licensed under the GNU Affero General Public License v3.0"
	echo "(see LICENSE and LICENSING.md). It includes the following third-party"
	echo "software, each under its own license, reproduced below."
	while read -r path ver; do
		dir=$modcache/$(esc "$path")@$ver
		files=$(find "$dir" -maxdepth 1 -type f \( -iname 'licen[cs]e*' -o -iname 'copying*' -o -iname 'notice*' -o -iname 'patents*' \) | sort)
		[ -n "$files" ] || { echo "notices.sh: no license file in $dir" >&2; exit 1; }
		for f in $files; do
			sep "Go module $path $ver: $(basename "$f")"
			cat "$f"
		done
		[ "$path" = github.com/duckdb/duckdb-go-bindings ] && duckdb=$ver
	done <<<"$deps"
	if [ -n "$duckdb" ]; then
		# Module v0.1MMPP.0 carries DuckDB vM.MM.PP (v0.10505.0: v1.5.5).
		v=${duckdb#v0.}; v=${v%.0}
		dv=v$((10#${v:0:1})).$((10#${v:1:2})).$((10#${v:3:2}))
		f=$here/notices/duckdb-$dv.txt
		[ -f "$f" ] || { echo "notices.sh: $bin links DuckDB $dv ($duckdb): add $f (see packaging/notices/)" >&2; exit 1; }
		sep "DuckDB $dv"
		cat "$f"
	fi
} >"$out"
echo "   $(basename "$bin"): $(wc -l <<<"$deps") Go modules${duckdb:+, DuckDB}: $out"
