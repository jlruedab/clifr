package recorder

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// readBlockDevs reads every block device of /sys/block and its partitions
// as lsblk sees them: sysfs attributes, device-mapper and md names, the
// holders and slaves, a loop device's backing file, and the file system
// udev found on it (/run/udev/data, which lsblk reads first).
func readBlockDevs() ([]store.BlockDevRow, error) {
	ents, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}
	var out []store.BlockDevRow
	for _, e := range ents {
		dir := "/sys/block/" + e.Name()
		d, ok := readBlockDev(dir, e.Name(), "")
		if !ok {
			continue
		}
		out = append(out, d)
		parts, _ := os.ReadDir(dir)
		for _, p := range parts {
			if _, err := os.Stat(dir + "/" + p.Name() + "/partition"); err == nil {
				if pd, ok := readBlockDev(dir+"/"+p.Name(), p.Name(), e.Name()); ok {
					out = append(out, pd)
				}
			}
		}
	}
	return out, nil
}

func readBlockDev(dir, name, parent string) (store.BlockDevRow, bool) {
	attr := func(f string) string {
		b, err := os.ReadFile(dir + "/" + f)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	num := func(f string) int64 {
		n, err := strconv.ParseInt(attr(f), 10, 64)
		if err != nil {
			return -1
		}
		return n
	}
	maj, min, ok := strings.Cut(attr("dev"), ":")
	if !ok {
		return store.BlockDevRow{}, false
	}
	d := store.BlockDevRow{Name: name, Parent: parent, RO: num("ro"), RM: num("removable"), Hidden: num("hidden") == 1,
		SCSIType: num("device/type"), DMName: attr("dm/name"), DMUUID: attr("dm/uuid"), MDLevel: attr("md/level"),
		LoopFile: attr("loop/backing_file"), Holders: dirNames(dir + "/holders"), Slaves: dirNames(dir + "/slaves")}
	d.Maj, _ = strconv.Atoi(maj)
	d.Min, _ = strconv.Atoi(min)
	if s := num("size"); s > 0 {
		d.Size = s * 512
	}
	if f, err := os.Open("/run/udev/data/b" + maj + ":" + min); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(strings.TrimPrefix(sc.Text(), "E:"), "=")
			if !ok {
				continue
			}
			switch k {
			case "ID_FS_TYPE":
				d.FSType = v
			case "ID_FS_VERSION":
				d.FSVer = v
			case "ID_FS_LABEL_ENC":
				d.Label = v
			case "ID_FS_UUID_ENC":
				d.UUID = v
			}
		}
		f.Close()
	}
	return d, true
}

// dirNames lists a directory's entries, comma-separated ("" when it has
// none or does not exist).
func dirNames(dir string) string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	names := make([]string, len(ents))
	for i, e := range ents {
		names[i] = e.Name()
	}
	return strings.Join(names, ",")
}

// addBlockDevs writes the block devices that changed, all of them every
// NetCountersFullMS, and a Gone row for each that went away.
func (s *sysSampler) addBlockDevs(ts int64, devs []store.BlockDevRow, b *store.Batch) {
	full := s.blockLast == nil || ts-s.blockFull >= store.NetCountersFullMS
	if full {
		s.blockFull = ts
	}
	seen := make(map[string]store.BlockDevRow, len(devs))
	for _, d := range devs {
		seen[d.Name] = d
		if old, ok := s.blockLast[d.Name]; full || !ok || old != d {
			d.TS = ts
			b.BlockDevs = append(b.BlockDevs, d)
		}
	}
	for name := range s.blockLast {
		if _, ok := seen[name]; !ok {
			b.BlockDevs = append(b.BlockDevs, store.BlockDevRow{TS: ts, Name: name, Gone: true})
		}
	}
	s.blockLast = seen
}
