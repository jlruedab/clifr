package query

import (
	"os"
	"slices"
	"strings"

	"clifr/internal/store"
)

// ToolStyle is how the recorded host's versions of the tools print the
// things that differ between versions. clifr prints as the host's own tools
// would, so its output agrees with them and with sosreports of that host.
type ToolStyle struct {
	Name string // a key of Styles
	// OldUsed: procps-ng 3.3 of RHEL 8 and Ubuntu 22.04 (free, top): used =
	// total - free - buffers - cache, not total - available (RHEL 9's 3.3.17
	// already computes the latter).
	OldUsed bool
	// DFListAll: GNU df of RHEL 8 and 9 (coreutils 8.30, 8.32): devtmpfs and
	// squashfs are listed (Ubuntu 22.04's coreutils 8.32 leaves them out).
	DFListAll bool
	// LsofNoUnixState: lsof 4.93 (RHEL 8, Ubuntu 22.04): a unix socket's NAME
	// has no "(CONNECTED)", "(LISTEN)" or "(UNCONNECTED)".
	LsofNoUnixState bool
	// VmstatTickRates: procps-ng before 4.0 (vmstat): the since-boot rates
	// are per second of CPU time summed over all CPUs.
	VmstatTickRates bool
	// IostatV11: sysstat 11 (iostat): no discard/flush columns, svctm, sr
	// devices named scd.
	IostatV11 bool
	// DmesgTime: util-linux's dmesg -T arithmetic ("2.32", "2.37"; "" =
	// 2.41: see recordTime). DmesgCaller: the PRINTK_CALLER field is
	// printed (2.41; older versions leave it out).
	DmesgTime   string
	DmesgCaller bool
	// SystemdList: systemctl list-units' layout: "239" (its own printf
	// columns), "249" (the table, legend "LOAD   = ..."; also 252), "" (258
	// and later: "Legend: LOAD   → ...").
	SystemdList string
	// SystemdCgls: systemd-cgls's layout: "239" (header "Control group /:",
	// no delegation mark), "249" (the same, a space after each cgroup name),
	// "252" (also each cgroup's id and its user./trusted. attributes), ""
	// (258 and later: "CGroup /:", delegated cgroups marked).
	SystemdCgls string
	// SwapSummaryOwn: util-linux 2.32's swapon --summary prints its own
	// columns ("%-39s\t%-8s\t%d\t%d\t%d"), not /proc/swaps.
	SwapSummaryOwn bool
	// LsblkV232: util-linux 2.32's lsblk: one MOUNTPOINT (2.37: all of them,
	// MOUNTPOINTS), -f without FSVER, FSAVAIL and FSUSE%.
	LsblkV232 bool
}

// Styles by distribution and major version (Ubuntu: its release). "current"
// is the newest tools' (procps-ng 4, coreutils 9.7, lsof 4.99), for unknown
// distributions and recordings without the distribution (before 2026-10-21).
var Styles = map[string]ToolStyle{
	"current": {Name: "current", DmesgCaller: true},
	// Each checked with clifr verify in a VM (2026-10-21): Rocky Linux 8.10
	// (procps-ng 3.3.15, coreutils 8.30, lsof 4.93.2, sysstat 11.7.3), AlmaLinux
	// 9.8 (procps-ng 3.3.17, coreutils 8.32, lsof 4.94.0, sysstat 12.5.4),
	// Ubuntu 22.04.5 (procps-ng 3.3.17, coreutils 8.32, lsof 4.93.2).
	"rhel-8": {Name: "rhel-8", OldUsed: true, DFListAll: true, LsofNoUnixState: true, VmstatTickRates: true, IostatV11: true,
		DmesgTime: "2.32", SystemdList: "239", SystemdCgls: "239", SwapSummaryOwn: true, LsblkV232: true},
	"rhel-9": {Name: "rhel-9", DFListAll: true, VmstatTickRates: true, DmesgTime: "2.37", SystemdList: "249", SystemdCgls: "252"},
	"ubuntu-22.04": {Name: "ubuntu-22.04", OldUsed: true, LsofNoUnixState: true, VmstatTickRates: true,
		DmesgTime: "2.37", SystemdList: "249", SystemdCgls: "249"},
}

// StyleOverride, if set (clifr --style), is used instead of the recorded
// distribution.
var StyleOverride string

// StyleName maps /etc/os-release's ID, VERSION_ID and ID_LIKE to a key of
// Styles ("" when there is no entry for it).
func StyleName(id, version, like string) string {
	major, _, _ := strings.Cut(version, ".")
	rhel := slices.Contains([]string{"rhel", "centos", "rocky", "almalinux", "ol"}, id) ||
		slices.Contains(strings.Fields(like), "rhel")
	var name string
	switch {
	case rhel:
		name = "rhel-" + major
	case id == "ubuntu":
		name = "ubuntu-" + version
	}
	if _, ok := Styles[name]; ok {
		return name
	}
	return ""
}

// StyleAt is the style of the tools of the host recorded at t (the clifrd
// run covering t), or the override.
func StyleAt(db *store.DB, t int64) ToolStyle {
	if s, ok := Styles[StyleOverride]; ok {
		return s
	}
	name := StyleName(MetaAt(db, "os_id", t), MetaAt(db, "os_version_id", t), MetaAt(db, "os_id_like", t))
	if name == "" {
		return Styles["current"]
	}
	return Styles[name]
}

// StyleNote describes the style for an informational line, "" for current.
func StyleNote(db *store.DB, t int64) string {
	s := StyleAt(db, t)
	if s.Name == "current" {
		return ""
	}
	if StyleOverride != "" {
		return "output in the style of " + s.Name + "'s tools (--style)"
	}
	return "output in the style of " + s.Name + "'s tools, the recorded host's (" + MetaAt(db, "os_pretty_name", t) + ")"
}

// unixState strips a unix socket NAME's state for lsof before 4.95:
// "/run/x type=STREAM (CONNECTED)" -> "/run/x type=STREAM".
func unixState(name string) string {
	for _, st := range []string{" (CONNECTED)", " (UNCONNECTED)", " (LISTEN)"} {
		if s, ok := strings.CutSuffix(name, st); ok && strings.Contains(s, "type=") {
			return s
		}
	}
	return name
}

// LocaleUTF8 is whether the tools would print UTF-8 in clifr's environment,
// as systemd decides it: the first of LC_ALL, LC_CTYPE and LANG that is set
// names a UTF-8 locale, or none is set (the C locale, taken as UTF-8).
func LocaleUTF8() bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := os.Getenv(k); v != "" {
			v = strings.ToLower(v)
			return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
		}
	}
	return true
}
