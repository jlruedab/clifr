package recorder

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"clifr/internal/cpuid"
	"clifr/internal/procfs"
)

// readCPUs is what lscpu reads under /sys/devices/system/cpu and node (for
// clifr lscpu), as "path\tcontent" lines keyed by the path: the CPU lists,
// the vulnerabilities, cpufreq/boost, and per CPU its online state,
// topology, caches and frequency limits (not scaling_cur_freq, which
// changes all the time: the MHz are cpu_samples'), each node's CPU map,
// and the hypervisor as an unprivileged lscpu finds it ("virt\tVENDOR\tTYPE").
// Some 1,300 files on 22 CPUs (15 ms): the CPU lists and vulnerabilities
// once a minute, the per-CPU files (cpuCache) again only when the lists
// changed or every cpuFilesMS.
func readCPUs() ([]procfs.SnapLine, error) {
	const base = "/sys/devices/system/cpu/"
	var out []procfs.SnapLine
	add := func(rel string) {
		b, err := os.ReadFile(base + rel)
		if err != nil {
			return
		}
		v := strings.TrimRight(string(b), "\n")
		v = strings.ReplaceAll(v, "\n", "\\n")
		out = append(out, procfs.SnapLine{Key: rel, Line: rel + "\t" + v})
	}
	for _, f := range []string{"possible", "present", "online", "offline", "kernel_max", "isolated", "nohz_full", "cpufreq/boost"} {
		add(f)
	}
	lists := ""
	for _, l := range out[:min(3, len(out))] {
		lists += l.Line + "\n"
	}
	if ents, err := os.ReadDir(base + "vulnerabilities"); err == nil {
		for _, e := range ents {
			add("vulnerabilities/" + e.Name())
		}
	}
	// hotplug/states: only its ": online" line, the state of a CPU fully
	// online (lscpu's get_online_state).
	if b, err := os.ReadFile(base + "hotplug/states"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasSuffix(l, ": online") {
				out = append(out, procfs.SnapLine{Key: "hotplug/states", Line: "hotplug/states\t" + strings.TrimSpace(l)})
				break
			}
		}
	}
	c := &cpuCache
	now := time.Now()
	if c.lists == lists && now.Sub(c.read) < cpuFilesMS*time.Millisecond {
		return append(out, c.lines...), nil
	}
	global := len(out)
	ents, err := os.ReadDir(base)
	if err != nil {
		return out, err
	}
	var cpus []int
	for _, e := range ents {
		if n, err := strconv.Atoi(strings.TrimPrefix(e.Name(), "cpu")); err == nil && strings.HasPrefix(e.Name(), "cpu") {
			cpus = append(cpus, n)
		}
	}
	sort.Ints(cpus)
	files := func(dir string) []string {
		ents, _ := os.ReadDir(base + dir)
		var names []string
		for _, e := range ents {
			if e.Type().IsRegular() && e.Name() != "uevent" {
				names = append(names, e.Name())
			}
		}
		return names
	}
	for _, n := range cpus {
		cpu := "cpu" + strconv.Itoa(n) + "/"
		for _, f := range []string{"online", "hotplug/state", "polarization", "address", "configure", "cpufreq/cpuinfo_max_freq", "cpufreq/cpuinfo_min_freq"} {
			add(cpu + f)
		}
		for _, f := range files(cpu + "topology") {
			add(cpu + "topology/" + f)
		}
		idx, _ := filepath.Glob(base + cpu + "cache/index*")
		sort.Slice(idx, func(i, j int) bool { return cacheIndex(idx[i]) < cacheIndex(idx[j]) })
		for _, d := range idx {
			rel := cpu + "cache/" + filepath.Base(d)
			for _, f := range files(rel) {
				add(rel + "/" + f)
			}
		}
	}
	nodes, _ := filepath.Glob("/sys/devices/system/node/node*/cpumap")
	for _, p := range nodes {
		if b, err := os.ReadFile(p); err == nil {
			rel := "node/" + filepath.Base(filepath.Dir(p)) + "/cpumap"
			out = append(out, procfs.SnapLine{Key: rel, Line: rel + "\t" + strings.TrimSpace(string(b))})
		}
	}
	vendor, typ := hypervisor()
	out = append(out, procfs.SnapLine{Key: "virt", Line: "virt\t" + vendor + "\t" + typ})
	// arm64: whether ACPI's PPTT table exists (lscpu's cluster wording) and
	// whether 32-bit code runs (its "CPU op-mode(s)").
	if runtime.GOARCH == "arm64" {
		_, err := os.Stat("/sys/firmware/acpi/tables/PPTT")
		out = append(out, procfs.SnapLine{Key: "pptt", Line: "pptt\t" + strconv.FormatBool(err == nil)},
			procfs.SnapLine{Key: "aarch32", Line: "aarch32\t" + strconv.FormatBool(aarch32())})
	}
	c.lists, c.read, c.lines = lists, now, append([]procfs.SnapLine(nil), out[global:]...)
	return out, nil
}

// cpuCache is readCPUs' per-CPU part as last read, with the CPU lists then.
var cpuCache struct {
	lists string
	read  time.Time
	lines []procfs.SnapLine
}

// cpuFilesMS: how often the per-CPU files are read when the CPU lists do
// not change (CPU hotplug changes them).
const cpuFilesMS = 600_000

func cacheIndex(p string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(filepath.Base(p), "index"))
	return n
}

var hypervisorOnce struct {
	sync.Once
	vendor, typ string
}

// hypervisor is lscpu's read_virtualization as an unprivileged user runs it
// (sys-utils/lscpu-virt.c, util-linux 2.41): WSL from the kernel release,
// else CPUID's signature (the DMI table is root's only, so lscpu stops
// there), else Xen (/proc/xen), else OpenVZ (/proc/vz without /proc/bc).
// Vendor as lscpu names it, "" none; type none, para, full or container.
// It does not change while the system runs: read once. (Following
// lscpu-virt.c, GPL-2.0-or-later; packaging/notices/util-linux.txt.)
func hypervisor() (string, string) {
	h := &hypervisorOnce
	h.Do(func() {
		if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil && strings.Contains(string(b), "Microsoft") {
			h.vendor, h.typ = "Windows Subsystem for Linux", "container"
			return
		}
		sig := cpuid.HypervisorSignature()
		for _, v := range []struct{ sig, name string }{{"XenVMMXenVMM", "Xen"}, {"KVMKVMKVM", "KVM"},
			{"Microsoft Hv", "Microsoft"}, {"VMwareVMware", "VMware"}, {"UnisysSpar64", "Unisys s-Par"}} {
			if strings.HasPrefix(sig, v.sig) {
				h.vendor, h.typ = v.name, "full"
				if v.name == "Xen" {
					if b, err := os.ReadFile("/sys/hypervisor/properties/features"); err == nil {
						f, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 16, 32)
						// XEN_FEATURES_PV_MASK, XEN_FEATURES_PVH_MASK
						const pv, pvh = 1 << 5, 1<<3 | 1<<8
						if f&pv != 0 || f&pvh == pvh {
							h.typ = "para"
						}
					}
				}
				return
			}
		}
		if _, err := os.Stat("/proc/xen"); err == nil {
			h.vendor, h.typ = "Xen", "para"
			if b, err := os.ReadFile("/proc/xen/capabilities"); err == nil && strings.TrimSpace(string(b)) == "control_d" {
				h.typ = "none"
			}
			return
		}
		_, vz := os.Stat("/proc/vz")
		_, bc := os.Stat("/proc/bc")
		if vz == nil && bc != nil {
			h.vendor, h.typ = "Parallels", "container"
		}
	})
	return h.vendor, h.typ
}

// readCPUInfo is /proc/cpuinfo without its "cpu MHz" lines (they change at
// every read; the MHz are cpu_samples'), keyed by the processor's position
// and the field ("3:flags").
func readCPUInfo() ([]procfs.SnapLine, error) {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return nil, err
	}
	var out []procfs.SnapLine
	proc := 0
	for i, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		name, _, _ := strings.Cut(l, ":")
		name = strings.TrimSpace(name)
		switch {
		case name == "cpu MHz":
			continue
		case l == "":
			proc++
			out = append(out, procfs.SnapLine{Key: "#" + strconv.Itoa(i), Line: l})
			continue
		}
		out = append(out, procfs.SnapLine{Key: strconv.Itoa(proc) + ":" + name, Line: l})
	}
	return out, nil
}
