package recorder

import (
	"os"
	"strconv"
	"strings"

	"clifr/internal/procfs"
)

// readMountstats keeps the NFS mounts' sections of the host's mountstats
// (hostMountNS), as mountstats reads them: each line trimmed, keyed by
// mount point and position in its section.
func readMountstats() ([]procfs.SnapLine, error) {
	proc, _ := hostMountNS()
	b, err := os.ReadFile(proc + "/mountstats")
	if err != nil {
		return nil, err
	}
	var out []procfs.SnapLine
	mp, keep, i := "", false, 0
	for _, l := range strings.Split(string(b), "\n") {
		w := strings.Fields(l)
		if len(w) == 0 {
			continue
		}
		if w[0] == "device" && len(w) >= 8 {
			mp, i = w[4], 0
			keep = w[7] == "nfs" || w[7] == "nfs4"
		}
		if !keep {
			continue
		}
		out = append(out, procfs.SnapLine{Key: mp + " " + strconv.Itoa(i), Line: strings.TrimSpace(l)})
		i++
	}
	return out, nil
}
