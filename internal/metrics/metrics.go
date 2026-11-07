// Package metrics serves clifrd's latest sample as Prometheus metrics
// (clifrd --metrics): Node Exporter's names for the system counters, so its
// dashboards work, and clifr_* for the recorder itself. The text exposition
// format is written here (no client library). A scrape formats the newest
// Snapshot the recorder published; it reads no file.
package metrics

import (
	"bufio"
	"io"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// Snapshot is what one scrape shows. The recorder replaces it after each
// system sample and each full sample; a published Snapshot is never changed.
type Snapshot struct {
	Version string
	BootMS  int64 // boot time, Unix ms

	SysTS int64 // time of the system sample below (0: none yet)
	Sys   store.SysSample
	CPUs  []store.CPUSample // per CPU (the total, CPU -1, is left out)

	Sample  store.Sample        // the recorder's last full sample (its own CPU, memory, data size)
	Samples int64               // full samples written since start
	Stats   map[string][2]int64 // events received and dropped per source, since start
	Guard   map[string]int64    // guard events per kind, since start
}

// Write writes s in the Prometheus text format (version 0.0.4).
func Write(w io.Writer, s *Snapshot) error {
	e := &enc{w: bufio.NewWriter(w)}
	if s.SysTS > 0 {
		e.node(s)
	}
	e.self(s)
	return e.w.Flush()
}

type enc struct {
	w *bufio.Writer
}

// family starts a metric family: its HELP and TYPE lines.
func (e *enc) family(name, typ, help string) {
	e.w.WriteString("# HELP " + name + " " + help + "\n# TYPE " + name + " " + typ + "\n")
}

// sample writes one value; labels are name, value pairs.
func (e *enc) sample(name string, v float64, labels ...string) {
	e.w.WriteString(name)
	if len(labels) > 0 {
		e.w.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				e.w.WriteByte(',')
			}
			e.w.WriteString(labels[i] + `="` + escape(labels[i+1]) + `"`)
		}
		e.w.WriteByte('}')
	}
	e.w.WriteByte(' ')
	e.w.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	e.w.WriteByte('\n')
}

// one writes a family with a single unlabelled value.
func (e *enc) one(name, typ, help string, v float64) {
	e.family(name, typ, help)
	e.sample(name, v)
}

var escaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func escape(s string) string { return escaper.Replace(s) }

// cpuModes are node_cpu_seconds_total's modes: store.CPUCols without guest
// and guest_nice, which are node_cpu_guest_seconds_total (/proc/stat counts
// them in user and nice too; Node Exporter reports both as the kernel does).
var cpuModes = []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"}

func (e *enc) node(s *Snapshot) {
	sec := func(ticks int64) float64 { return float64(ticks) / procfs.ClockTicks }
	cpus := make([]store.CPUSample, 0, len(s.CPUs))
	for _, c := range s.CPUs {
		if c.CPU >= 0 {
			cpus = append(cpus, c)
		}
	}
	sort.Slice(cpus, func(i, j int) bool { return cpus[i].CPU < cpus[j].CPU })
	e.family("node_cpu_seconds_total", "counter", "Seconds the CPUs spent in each mode.")
	for _, c := range cpus {
		cpu := strconv.Itoa(c.CPU)
		for i, m := range cpuModes {
			e.sample("node_cpu_seconds_total", sec(c.T[i]), "cpu", cpu, "mode", m)
		}
	}
	e.family("node_cpu_guest_seconds_total", "counter", "Seconds the CPUs spent in guests (VMs) for each mode.")
	for _, c := range cpus {
		cpu := strconv.Itoa(c.CPU)
		e.sample("node_cpu_guest_seconds_total", sec(c.T[8]), "cpu", cpu, "mode", "user")
		e.sample("node_cpu_guest_seconds_total", sec(c.T[9]), "cpu", cpu, "mode", "nice")
	}

	y := &s.Sys
	e.one("node_load1", "gauge", "1m load average.", float64(y.Load1)/100)
	e.one("node_load5", "gauge", "5m load average.", float64(y.Load5)/100)
	e.one("node_load15", "gauge", "15m load average.", float64(y.Load15)/100)

	// /proc/meminfo, in kB there: the fields clifrd records.
	for _, m := range []struct {
		field string
		kb    int64
	}{
		{"MemTotal", y.MemTotal}, {"MemFree", y.MemFree}, {"MemAvailable", y.MemAvailable},
		{"Buffers", y.Buffers}, {"Cached", y.Cached}, {"SwapCached", y.SwapCached},
		{"Active", y.Active}, {"Inactive", y.Inactive}, {"SwapTotal", y.SwapTotal}, {"SwapFree", y.SwapFree},
		{"Dirty", y.Dirty}, {"Writeback", y.Writeback}, {"Shmem", y.Shmem}, {"Slab", y.Slab},
		{"SReclaimable", y.SReclaimable},
	} {
		name := "node_memory_" + m.field + "_bytes"
		e.one(name, "gauge", "Memory information field "+m.field+"_bytes.", float64(m.kb*1024))
	}

	e.one("node_boot_time_seconds", "gauge", "Node boot time, in unixtime.", float64(s.BootMS/1000))
	e.one("node_context_switches_total", "counter", "Total number of context switches.", float64(y.Ctxt))
	e.one("node_forks_total", "counter", "Total number of forks.", float64(y.Forks))
	e.one("node_intr_total", "counter", "Total number of interrupts serviced.", float64(y.Intr))
	e.one("node_procs_blocked", "gauge", "Number of processes blocked waiting for I/O to complete.", float64(y.ProcsBlocked))
	e.one("node_procs_running", "gauge", "Number of processes in runnable state.", float64(y.ProcsRunning))

	// /proc/vmstat: the fields of Node Exporter's default filter it has.
	for _, v := range []struct {
		field string
		n     int64
	}{
		{"pgfault", y.PgFault}, {"pgmajfault", y.PgMajFault}, {"pgpgin", y.PgpgIn}, {"pgpgout", y.PgpgOut},
		{"pswpin", y.PswpIn}, {"pswpout", y.PswpOut},
	} {
		name := "node_vmstat_" + v.field
		e.one(name, "untyped", "/proc/vmstat information field "+v.field+".", float64(v.n))
	}
}

// self writes clifr_*: the recorder's own state.
func (e *enc) self(s *Snapshot) {
	e.family("clifr_build_info", "gauge", "clifrd's version, as a label; the value is always 1.")
	e.sample("clifr_build_info", 1, "version", s.Version)
	if s.SysTS > 0 {
		e.one("clifr_system_sample_timestamp_seconds", "gauge",
			"When the system counters served here were read (they are as old as clifrd's system interval).", float64(s.SysTS)/1000)
	}
	if s.Sample.TS == 0 {
		return
	}
	x := &s.Sample
	e.one("clifr_sample_timestamp_seconds", "gauge", "When clifrd last sampled processes and sockets.", float64(x.TS)/1000)
	e.one("clifr_samples_total", "counter", "Samples clifrd wrote since it started.", float64(s.Samples))
	e.one("clifr_sample_duration_seconds", "gauge", "How long the last sample took (processes, sockets, open files, write).",
		float64(x.DurProcUS+x.DurSockUS+x.DurFDUS+x.DurDBUS)/1e6)
	e.one("clifr_recorder_cpu_seconds_total", "counter", "CPU time clifrd used since it started (user and system).", float64(x.CPUUS)/1e6)
	e.one("clifr_recorder_resident_memory_bytes", "gauge", "clifrd's resident memory.", float64(x.RSSKB*1024))
	e.one("clifr_data_bytes", "gauge", "Size of clifrd's data directory.", float64(x.DBBytes))
	e.one("clifr_processes", "gauge", "Processes seen at the last sample.", float64(x.NProc))
	e.one("clifr_fd_interval_seconds", "gauge", "Current interval between full open-file walks (the CPU budget may lengthen it).", float64(x.FDIntervalS))

	var events, progs []string
	for src := range s.Stats {
		if strings.HasPrefix(src, "bpf_runs:") {
			progs = append(progs, strings.TrimPrefix(src, "bpf_runs:"))
		} else if !strings.HasPrefix(src, "bpf_ns:") {
			events = append(events, src)
		}
	}
	sort.Strings(events)
	sort.Strings(progs)
	if len(events) > 0 {
		e.family("clifr_events_total", "counter", "Events and items clifrd received, per source, since it started.")
		for _, src := range events {
			e.sample("clifr_events_total", float64(s.Stats[src][0]), "source", src)
		}
		e.family("clifr_events_dropped_total", "counter", "Events lost before clifrd read them (kernel buffer full), per source.")
		for _, src := range events {
			e.sample("clifr_events_dropped_total", float64(s.Stats[src][1]), "source", src)
		}
	}
	if len(progs) > 0 { // with --bpf-stats
		e.family("clifr_ebpf_program_runs_total", "counter", "Runs of each eBPF program (clifrd --bpf-stats).")
		for _, p := range progs {
			e.sample("clifr_ebpf_program_runs_total", float64(s.Stats["bpf_runs:"+p][0]), "program", p)
		}
		e.family("clifr_ebpf_program_seconds_total", "counter", "Time the kernel spent in each eBPF program (clifrd --bpf-stats).")
		for _, p := range progs {
			e.sample("clifr_ebpf_program_seconds_total", float64(s.Stats["bpf_ns:"+p][0])/1e9, "program", p)
		}
	}
	if len(s.Guard) > 0 {
		kinds := make([]string, 0, len(s.Guard))
		for k := range s.Guard {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		e.family("clifr_guard_events_total", "counter", "clifrd's guard-rail events per kind since it started (budget exceeded, reconciled connections, ...).")
		for _, k := range kinds {
			e.sample("clifr_guard_events_total", float64(s.Guard[k]), "kind", k)
		}
	}
}
