package query

import (
	"strings"
	"testing"
)

func TestLscpuSets(t *testing.T) {
	s := parseCPUList("0-3,5,7-8")
	if got := cpulistCreate(s); got != "0-3,5,7-8" {
		t.Errorf("cpulist %q", got)
	}
	m := parseCPUMask("00000000,0000003f")
	if len(m) != 6 || !m[5] || m[6] {
		t.Errorf("mask %v", m.list())
	}
	if got := cpumaskCreate(parseCPUList("0-21"), 8192); got != "3fffff" {
		t.Errorf("cpumask %q", got)
	}
	if got := sizeHuman3(557056); got != "544 KiB" {
		t.Errorf("sizeHuman3 %q", got)
	}
}

// a 2-core, 4-thread x86 machine in one socket.
func lscpuX86() *Lscpu {
	var sys []string
	add := func(k, v string) { sys = append(sys, k+"\t"+v) }
	add("possible", "0-3")
	add("present", "0-3")
	add("online", "0-3")
	add("kernel_max", "8191")
	add("vulnerabilities/spectre_v1", "Mitigation: usercopy/swapgs barriers")
	add("vulnerabilities/meltdown", "Not affected")
	for c, core := range []string{"0", "0", "1", "1"} {
		p := "cpu" + string(rune('0'+c)) + "/"
		sib := map[string]string{"0": "3", "1": "c"}[core]
		add(p+"topology/thread_siblings", sib)
		add(p+"topology/core_siblings", "f")
		add(p+"topology/core_id", core)
		add(p+"topology/physical_package_id", "0")
		add(p+"cpufreq/cpuinfo_max_freq", "4000000")
		add(p+"cpufreq/cpuinfo_min_freq", "800000")
		add(p+"cache/index0/level", "1")
		add(p+"cache/index0/type", "Data")
		add(p+"cache/index0/size", "48K")
		add(p+"cache/index0/id", core)
		add(p+"cache/index0/shared_cpu_map", sib)
		add(p+"cache/index1/level", "2")
		add(p+"cache/index1/type", "Unified")
		add(p+"cache/index1/size", "2048K")
		add(p+"cache/index1/id", "0")
		add(p+"cache/index1/shared_cpu_map", "f")
	}
	add("node/node0/cpumap", "f")
	add("virt", "KVM\tfull")
	var info []string
	for c := 0; c < 4; c++ {
		info = append(info, "processor\t: "+string(rune('0'+c)), "vendor_id\t: GenuineIntel", "cpu family\t: 6", "model\t\t: 170",
			"model name\t: Test CPU", "stepping\t: 4", "flags\t\t: fpu lm vmx", "bogomips\t: 5990.40",
			"address sizes\t: 46 bits physical, 48 bits virtual", "")
	}
	return newLscpu("x86_64", sys, info, map[int]float64{0: 2000, 1: 1000, 2: 1000, 3: 1000})
}

func TestLscpuSummary(t *testing.T) {
	x := lscpuX86()
	var b strings.Builder
	PrintLscpu(&b, x, LscpuOpts{})
	out := collapse(b.String())
	for _, want := range []string{
		"CPU op-mode(s):                         32-bit, 64-bit\n", "CPU(s):                                 4\n",
		"Thread(s) per core:                     2\n", "Core(s) per socket:                     2\n", "Socket(s):                              1\n",
		"CPU(s) scaling MHz:                     31%\n", "CPU max MHz:                            4000.0000\n",
		"BogoMIPS:                               5990.40\n", "Virtualization:                         VT-x\n",
		"Hypervisor vendor:                      KVM\n", "L1d cache:                              96 KiB (2 instances)\n",
		"L2 cache:                               2 MiB (1 instance)\n", "NUMA node0 CPU(s):                      0-3\n",
		"Vulnerability Meltdown:                 Not affected\n",
		"Vulnerability Spectre v1:               Mitigation; usercopy/swapgs barriers\n"} {
		if !strings.Contains(out, collapse(want)) {
			t.Errorf("summary lacks %q:\n%s", want, b.String())
		}
	}
	b.Reset()
	PrintLscpu(&b, x, LscpuOpts{Mode: "p"})
	if !strings.Contains(b.String(), "# CPU,Core,Socket,Node,,L1d,L2\n0,0,0,0,,0,0\n1,0,0,0,,0,0\n2,1,0,0,,1,0\n") {
		t.Errorf("-p:\n%s", b.String())
	}
	b.Reset()
	PrintLscpu(&b, x, LscpuOpts{Mode: "e"})
	if !strings.HasPrefix(b.String(), "CPU NODE SOCKET CORE L1d:L2 ONLINE    MAXMHZ   MINMHZ       MHZ\n  0    0      0    0 0:0       yes 4000.0000 800.0000 2000.0000\n") {
		t.Errorf("-e:\n%s", b.String())
	}
}

func TestLscpuARM(t *testing.T) {
	sys := []string{"possible\t0-1", "present\t0-1", "online\t0-1", "pptt\tfalse", "aarch32\tfalse",
		"cpu0/topology/thread_siblings\t1", "cpu0/topology/core_siblings\t3",
		"cpu1/topology/thread_siblings\t2", "cpu1/topology/core_siblings\t3"}
	var info []string
	for _, c := range []string{"0", "1"} {
		info = append(info, "processor\t: "+c, "BogoMIPS\t: 108.00", "Features\t: fp asimd", "CPU implementer\t: 0x41",
			"CPU architecture: 8", "CPU variant\t: 0x3", "CPU part\t: 0xd08", "CPU revision\t: 3", "")
	}
	x := newLscpu("aarch64", sys, info, nil)
	var b strings.Builder
	PrintLscpu(&b, x, LscpuOpts{})
	out := collapse(b.String())
	for _, want := range []string{"Vendor ID:           ARM\n", "Model name:          Cortex-A72\n", "Stepping:            r3p3\n",
		"Core(s) per cluster: 2\n", "Socket(s):           -\n", "Cluster(s):          1\n", "CPU op-mode(s):      64-bit\n"} {
		if !strings.Contains(out, collapse(want)) {
			t.Errorf("arm summary lacks %q:\n%s", want, b.String())
		}
	}
}

// collapse: each line's words joined by one space (the summary's padding
// depends on its longest field).
func collapse(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		out = append(out, strings.Join(strings.Fields(l), " "))
	}
	return strings.Join(out, "\n")
}
