package query

import (
	"os"
	"slices"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// ToolStyle is how the recorded host's versions of the tools print the
// things that differ between versions. clifr prints as the host's own tools
// would, so its output agrees with them and with sosreports of that host.
type ToolStyle struct {
	Name string // a key of Styles
	// Iotop: the Python iotop build (iotop -b): "" 0.6-42, "0.6-24" (Ubuntu
	// 22.04), "rhel" (RHEL 8's 0.6-18 and RHEL 9's 0.6-30).
	Iotop string
	// Htop: the htop release (htop's screen): "" 3.4.1, "3.3" 3.3.0 (RHEL 9's
	// EPEL, Ubuntu 24.04), "3.2" 3.2.1 (RHEL 8's EPEL), "3.0" 3.0.5 (Ubuntu 22.04).
	Htop string
	// Sar: the sysstat release (sar): "" 12.7.7, "12.6" 12.6.1 (Ubuntu 24.04),
	// "12.5" 12.5.x (RHEL 9's 12.5.4, Ubuntu 22.04's 12.5.2), "11.7" 11.7.3 (RHEL 8).
	Sar string
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
	// Vmstat: procps-ng's vmstat release: "" 4.0.4, "3.3.17" (RHEL 9,
	// Ubuntu 22.04: no gu column), "3.3.15" (RHEL 8: wide r and b 2 wide).
	Vmstat string
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
	// IPNeighOld: iproute2 5.15's ip neigh: a space before each field
	// after the link-layer address instead of after it (no trailing space).
	IPNeighOld bool
	// LslocksOld: util-linux before 2.41: an OFD lock's holder is not
	// looked up (pid -1, "(undefined)", the mount point and "..." as path).
	LslocksOld bool
	// Lsipc: util-linux's lsipc release: "" 2.41 (System V and POSIX
	// summary), "2.39" (ubuntu-24.04), "2.37" (rhel-9, ubuntu-22.04), "2.32"
	// (rhel-8: limits as plain numbers).
	Lsipc string
	// LslocksZeroSize: util-linux 2.32's lslocks prints an empty file's
	// size as 0B.
	LslocksZeroSize bool
	// Slabtop3: procps 3.3's slabtop: its own merge sort (equal caches in
	// another order) and USE computed as 100 * (float)a / b.
	Slabtop3 bool
	// NumastatOld: numactl before 2.0.15 (numastat "20130723"): fixed rows.
	NumastatOld bool
	// ConntrackOld: conntrack-tools before 1.4.7 (RHEL 8's 1.4.4, Ubuntu
	// 22.04's 1.4.6): the counters past search_restart named "(null)".
	ConntrackOld bool
	// Mountstats233: nfs-utils 2.3.3's mountstats (RHEL 8): no mount age;
	// -R knows the NFSv4 operations only up to CLONE.
	Mountstats233 bool
	// Atop271: atop 2.7.1 (EPEL on RHEL 8 and 9, Ubuntu 22.04): one MEM line,
	// no #tidle, numcpu or BDELAY, its own header and banner.
	Atop271 bool
	// Atop210: atop 2.10.0 (Ubuntu 24.04): 2.12.1's lines and views with
	// 2.7.1's header (no cgroup depth digit, 52 columns of fixed text).
	Atop210 bool
	// UnameUnknown: uutils coreutils (Ubuntu 25.10 and later): uname -p and -i
	// print "unknown" and -a leaves them out. RHEL's and Debian's coreutils
	// print the machine for both. Set by StyleAt from the distribution, not
	// a style of its own (all else is the current tools').
	UnameUnknown bool
	// Procps3: procps-ng 3.3's w and uptime, which read utmp (procps 4 reads
	// logind's sessions first). WNoFrom: w without the FROM column unless -f
	// (RHEL 9's procps-ng 3.3.17 is built without W_SHOWFROM; RHEL 8's and
	// Ubuntu's with it). Both checked in containers, 2026-11-20.
	Procps3, WNoFrom bool
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
	"rhel-8": {Name: "rhel-8", Lsipc: "2.32", Iotop: "rhel", Htop: "3.2", Sar: "11.7", Atop271: true, OldUsed: true, DFListAll: true, LsofNoUnixState: true, VmstatTickRates: true, Vmstat: "3.3.15", IostatV11: true,
		DmesgTime: "2.32", SystemdList: "239", SystemdCgls: "239", SwapSummaryOwn: true, LsblkV232: true, LslocksOld: true,
		LslocksZeroSize: true, Slabtop3: true, NumastatOld: true, ConntrackOld: true, Mountstats233: true, Procps3: true},
	"rhel-9": {Name: "rhel-9", Lsipc: "2.37", Iotop: "rhel", Htop: "3.3", Sar: "12.5", Atop271: true, DFListAll: true, VmstatTickRates: true, Vmstat: "3.3.17", DmesgTime: "2.37", SystemdList: "249", SystemdCgls: "252", LslocksOld: true, Slabtop3: true,
		Procps3: true, WNoFrom: true},
	"ubuntu-22.04": {Name: "ubuntu-22.04", Lsipc: "2.37", Iotop: "0.6-24", Htop: "3.0", Sar: "12.5", Atop271: true, OldUsed: true, LsofNoUnixState: true, VmstatTickRates: true, Vmstat: "3.3.17",
		DmesgTime: "2.37", SystemdList: "249", SystemdCgls: "249", IPNeighOld: true, LslocksOld: true, Slabtop3: true,
		NumastatOld: true, ConntrackOld: true, Procps3: true},
	// Ubuntu 24.04.5 (2026-11-21): the current tools' style and atop 2.10.0
	// (checked against its root captures of every view in a VM).
	"ubuntu-24.04": {Name: "ubuntu-24.04", Lsipc: "2.39", Htop: "3.3", Sar: "12.6", DmesgCaller: true, Atop210: true},
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
	id, version := MetaAt(db, "os_id", t), MetaAt(db, "os_version_id", t)
	name := StyleName(id, version, MetaAt(db, "os_id_like", t))
	if name == "" {
		s := Styles["current"]
		s.UnameUnknown = uutils(id, version)
		return s
	}
	return Styles[name]
}

// uutils is whether the distribution ships uutils coreutils (Ubuntu since
// 25.10, 2026-11-20: 26.04's uname is uutils 0.10.0).
func uutils(id, version string) bool {
	if id != "ubuntu" {
		return false
	}
	y, m, _ := strings.Cut(version, ".")
	year, err1 := strconv.Atoi(y)
	month, err2 := strconv.Atoi(m)
	return err1 == nil && err2 == nil && (year > 25 || year == 25 && month >= 10)
}

// UnameAt is uname's fields for the clifrd run covering t, by long option
// name, as the host's uname prints them ("" values: not recorded).
func UnameAt(db *store.DB, t int64) map[string]string {
	at := func(key string) string { return MetaAt(db, key, t) }
	m, cpu := at("uname_machine"), at("uname_machine")
	if StyleAt(db, t).UnameUnknown {
		cpu = "unknown"
	}
	return map[string]string{"kernel-name": at("uname_sysname"), "nodename": HostnameAt(db, t),
		"kernel-release": at("uname_release"), "kernel-version": at("uname_version"), "machine": m,
		"processor": cpu, "hardware-platform": cpu, "operating-system": "GNU/Linux"}
}

// UnameKeys is uname -a's order. -a leaves out processor and
// hardware-platform when they are "unknown" (coreutils and uutils alike).
var UnameKeys = []string{"kernel-name", "nodename", "kernel-release", "kernel-version", "machine", "processor", "hardware-platform", "operating-system"}

// UnameLine joins the fields of keys (all: uname -a).
func UnameLine(vals map[string]string, keys []string, all bool) string {
	var out []string
	for _, k := range keys {
		if all && vals[k] == "unknown" && (k == "processor" || k == "hardware-platform") {
			continue
		}
		out = append(out, vals[k])
	}
	return strings.Join(out, " ")
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
