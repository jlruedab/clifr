package metrics

import (
	"regexp"
	"sort"

	"clifr/internal/procfs"
	"clifr/internal/store"
)

// FSUsage is one mounted file system for node_filesystem_*: its statfs
// numbers (as of clifrd's last round) and what mountinfo says of it.
type FSUsage struct {
	Device, FSType, MountPoint string
	ReadOnly                   bool
	Size, Free, Avail          int64 // bytes
	Files, FilesFree           int64
}

// Node Exporter 1.10.2's default filters (its --help), so the same devices
// and file systems are served.
var (
	diskExclude    = regexp.MustCompile(`^(z?ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\d+n\d+p)\d+$`)
	mountExclude   = regexp.MustCompile(`^/(dev|proc|run|sys|mnt|media|var/lib/docker/.+|var/lib/containers/storage/.+)($|/)`)
	fsTypesExclude = regexp.MustCompile(`^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|rpc_pipefs|securityfs|selinuxfs|squashfs|erofs|sysfs|tracefs)$`)
)

// ServedFS reports whether Node Exporter's default filters keep a mount.
func ServedFS(mountPoint, fsType string) bool {
	return !mountExclude.MatchString(mountPoint) && !fsTypesExclude.MatchString(fsType)
}

// disks writes node_disk_*: /proc/diskstats (sectors of 512 bytes, times in
// ms), the devices Node Exporter's default filter keeps.
func (e *enc) disks(ds []store.DiskSample) {
	var keep []store.DiskSample
	for _, d := range ds {
		if !diskExclude.MatchString(d.Name) {
			keep = append(keep, d)
		}
	}
	if len(keep) == 0 {
		return
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].Name < keep[j].Name })
	const sector, ms = 512, 1.0 / 1000
	for _, f := range []struct {
		name, typ, help string
		i               int
		scale           float64
	}{
		{"node_disk_reads_completed_total", "counter", "The total number of reads completed successfully.", 0, 1},
		{"node_disk_reads_merged_total", "counter", "The total number of reads merged.", 1, 1},
		{"node_disk_read_bytes_total", "counter", "The total number of bytes read successfully.", 2, sector},
		{"node_disk_read_time_seconds_total", "counter", "The total number of seconds spent by all reads.", 3, ms},
		{"node_disk_writes_completed_total", "counter", "The total number of writes completed successfully.", 4, 1},
		{"node_disk_writes_merged_total", "counter", "The number of writes merged.", 5, 1},
		{"node_disk_written_bytes_total", "counter", "The total number of bytes written successfully.", 6, sector},
		{"node_disk_write_time_seconds_total", "counter", "This is the total number of seconds spent by all writes.", 7, ms},
		{"node_disk_discards_completed_total", "counter", "The total number of discards completed successfully.", 8, 1},
		{"node_disk_discards_merged_total", "counter", "The total number of discards merged.", 9, 1},
		{"node_disk_discarded_sectors_total", "counter", "The total number of sectors discarded successfully.", 10, 1},
		{"node_disk_discard_time_seconds_total", "counter", "This is the total number of seconds spent by all discards.", 11, ms},
		{"node_disk_io_now", "gauge", "The number of I/Os currently in progress.", 12, 1},
		{"node_disk_io_time_seconds_total", "counter", "Total seconds spent doing I/Os.", 13, ms},
		{"node_disk_io_time_weighted_seconds_total", "counter", "The weighted # of seconds spent doing I/Os.", 14, ms},
		{"node_disk_flush_requests_total", "counter", "The total number of flush requests completed successfully", 15, 1},
		{"node_disk_flush_requests_time_seconds_total", "counter", "This is the total number of seconds spent by all flush requests.", 16, ms},
	} {
		e.family(f.name, f.typ, f.help)
		for _, d := range keep {
			e.sample(f.name, float64(d.V[f.i])*f.scale, "device", d.Name)
		}
	}
}

// netdevStats maps Node Exporter's node_network_{receive,transmit}_* (its
// netlink source with the legacy names) to rtnl_link_stats64 fields, as
// indices into store.LinkRow.Stats; several are sums, as in /proc/net/dev.
var netdevStats = []struct {
	name   string
	fields []int
}{
	{"receive_bytes", []int{2}}, {"receive_compressed", []int{21}}, {"receive_drop", []int{6, 15}},
	{"receive_errs", []int{4}}, {"receive_fifo", []int{14}}, {"receive_frame", []int{13, 10, 11, 12}},
	{"receive_multicast", []int{8}}, {"receive_nohandler", []int{23}}, {"receive_packets", []int{0}},
	{"transmit_bytes", []int{3}}, {"transmit_carrier", []int{17, 16, 19, 20}}, {"transmit_colls", []int{9}},
	{"transmit_compressed", []int{22}}, {"transmit_drop", []int{7}}, {"transmit_errs", []int{5}},
	{"transmit_fifo", []int{18}}, {"transmit_packets", []int{1}},
}

const (
	ifOperUp      = 6                        // IF_OPER_UP
	rtnlOnlyFlags = 0x40 | 0x10000 | 0x20000 // IFF_RUNNING, IFF_LOWER_UP, IFF_DORMANT
)

// network writes node_network_*: the counters of every interface with
// statistics, and the netclass gauges clifrd's rtnetlink rows hold.
func (e *enc) network(links []store.LinkRow) {
	if len(links) == 0 {
		return
	}
	links = append([]store.LinkRow(nil), links...)
	sort.Slice(links, func(i, j int) bool { return links[i].Name < links[j].Name })
	for _, m := range netdevStats {
		name := "node_network_" + m.name + "_total"
		e.family(name, "counter", "Network device statistic "+m.name+".")
		for _, l := range links {
			if !l.HasStats {
				continue
			}
			var v int64
			for _, i := range m.fields {
				v += l.Stats[i]
			}
			e.sample(name, float64(v), "device", l.Name)
		}
	}
	for _, g := range []struct {
		name, typ, help string
		v               func(l *store.LinkRow) int64
	}{
		{"node_network_carrier_changes_total", "counter", "Network device property: carrier_changes_total", func(l *store.LinkRow) int64 { return l.CarrierChanges }},
		// sysfs flags are dev->flags; rtnetlink's are dev_get_flags(), which
		// adds RUNNING, LOWER_UP and DORMANT from the device's state.
		{"node_network_flags", "gauge", "Network device property: flags", func(l *store.LinkRow) int64 { return l.Flags &^ rtnlOnlyFlags }},
		{"node_network_iface_id", "gauge", "Network device property: iface_id", func(l *store.LinkRow) int64 { return int64(l.Index) }},
		{"node_network_iface_link", "gauge", "Network device property: iface_link", func(l *store.LinkRow) int64 {
			if l.Link >= 0 {
				return l.Link
			}
			return int64(l.Index) // sysfs iflink: IFLA_LINK, else the device itself
		}},
		{"node_network_iface_link_mode", "gauge", "Network device property: iface_link_mode", func(l *store.LinkRow) int64 { return l.LinkMode }},
		{"node_network_mtu_bytes", "gauge", "Network device property: mtu_bytes", func(l *store.LinkRow) int64 { return l.MTU }},
		{"node_network_net_dev_group", "gauge", "Network device property: net_dev_group", func(l *store.LinkRow) int64 { return l.Group }},
		{"node_network_protocol_type", "gauge", "Network device property: protocol_type", func(l *store.LinkRow) int64 { return int64(l.Type) }},
		{"node_network_transmit_queue_length", "gauge", "Network device property: transmit_queue_length", func(l *store.LinkRow) int64 { return l.TxQLen }},
		{"node_network_up", "gauge", "Value is 1 if operstate is 'up', 0 otherwise.", func(l *store.LinkRow) int64 {
			if l.OperState == ifOperUp {
				return 1
			}
			return 0
		}},
	} {
		e.family(g.name, g.typ, g.help)
		for i := range links {
			e.sample(g.name, float64(g.v(&links[i])), "device", links[i].Name)
		}
	}
}

// filesystems writes node_filesystem_*. clifrd's statfs never fails visibly
// (a mount it cannot stat is left out), so device_error is always 0 and its
// label empty, as in Node Exporter for a mount it could read.
func (e *enc) filesystems(fss []FSUsage) {
	if len(fss) == 0 {
		return
	}
	fss = append([]FSUsage(nil), fss...)
	sort.Slice(fss, func(i, j int) bool { return fss[i].MountPoint < fss[j].MountPoint })
	labels := func(f *FSUsage) []string {
		return []string{"device", f.Device, "device_error", "", "fstype", f.FSType, "mountpoint", f.MountPoint}
	}
	for _, m := range []struct {
		name, help string
		v          func(f *FSUsage) int64
	}{
		{"node_filesystem_avail_bytes", "Filesystem space available to non-root users in bytes.", func(f *FSUsage) int64 { return f.Avail }},
		{"node_filesystem_device_error", "Whether an error occurred while getting statistics for the given device.", func(*FSUsage) int64 { return 0 }},
		{"node_filesystem_files", "Filesystem total file nodes.", func(f *FSUsage) int64 { return f.Files }},
		{"node_filesystem_files_free", "Filesystem total free file nodes.", func(f *FSUsage) int64 { return f.FilesFree }},
		{"node_filesystem_free_bytes", "Filesystem free space in bytes.", func(f *FSUsage) int64 { return f.Free }},
		{"node_filesystem_readonly", "Filesystem read-only status.", func(f *FSUsage) int64 {
			if f.ReadOnly {
				return 1
			}
			return 0
		}},
		{"node_filesystem_size_bytes", "Filesystem size in bytes.", func(f *FSUsage) int64 { return f.Size }},
	} {
		e.family(m.name, "gauge", m.help)
		for i := range fss {
			e.sample(m.name, float64(m.v(&fss[i])), labels(&fss[i])...)
		}
	}
}

// pressure writes node_pressure_* (PSI totals are in µs), as Node Exporter
// does: cpu "some" only, memory and io both lines, irq "full" (it has no
// "some").
func (e *enc) pressure(p map[string]procfs.Pressure) {
	us := func(v uint64) float64 { return float64(v) / 1e6 }
	if c, ok := p["cpu"]; ok {
		e.one("node_pressure_cpu_waiting_seconds_total", "counter", "Total time in seconds that processes have waited for CPU time", us(c.Some))
	}
	for _, r := range []string{"io", "memory"} {
		if v, ok := p[r]; ok {
			e.one("node_pressure_"+r+"_waiting_seconds_total", "counter", "Total time in seconds that processes have waited due to "+r+" congestion", us(v.Some))
			if v.HasFull {
				e.one("node_pressure_"+r+"_stalled_seconds_total", "counter", "Total time in seconds no process could make progress due to "+r+" congestion", us(v.Full))
			}
		}
	}
	if v, ok := p["irq"]; ok && v.HasFull {
		e.one("node_pressure_irq_stalled_seconds_total", "counter", "Total time in seconds no process could make progress due to IRQ congestion", us(v.Full))
	}
}

// PressureResources are the /proc/pressure files the recorder reads for the
// metrics (only with --metrics: PSI is not recorded).
var PressureResources = []string{"cpu", "io", "memory", "irq"}
