package procfs

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// SnapLine is one line of a file recorded as a snapshot (the snapshots
// table): its key within the file and the line as the kernel wrote it.
type SnapLine struct {
	Key, Line string
}

// SnapSource is a file under /proc recorded whole, line by line. Key names
// a line so that a change can be written alone; lines it gives no key (""),
// such as headers, are keyed by their position ("#0", "#1", ...).
type SnapSource struct {
	Name    string   // the snapshots table's source column
	Path    []string // under the proc root
	Key     func(line string) string
	EveryMS int64 // read every EveryMS (0: at every system sample)
}

// SnapSources are the files of phase 8 step 4 read at system samples.
var SnapSources = []SnapSource{
	{Name: "swaps", Path: []string{"swaps"}, Key: firstField},
	{Name: "modules", Path: []string{"modules"}, Key: firstField},
	{Name: "hostname", Path: []string{"sys", "kernel", "hostname"}},
	{Name: "sysvipc/msg", Path: []string{"sysvipc", "msg"}, Key: secondField},
	{Name: "sysvipc/sem", Path: []string{"sysvipc", "sem"}, Key: secondField},
	{Name: "sysvipc/shm", Path: []string{"sysvipc", "shm"}, Key: secondField},
	// Most of its lines change all the time: once a minute.
	{Name: "slabinfo", Path: []string{"slabinfo"}, Key: slabName, EveryMS: 60_000},
	// NFS client and server counters (nfsstat): absent without NFS.
	{Name: "rpc/nfs", Path: []string{"net", "rpc", "nfs"}, Key: firstField, EveryMS: 60_000},
	{Name: "rpc/nfsd", Path: []string{"net", "rpc", "nfsd"}, Key: firstField, EveryMS: 60_000},
}

// slabName keys /proc/slabinfo lines by cache name (the version line and
// the "# name" header by position).
func slabName(line string) string {
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "slabinfo ") {
		return ""
	}
	return firstField(line)
}

// secondField keys /proc/sysvipc lines by their id (the header: "id").
func secondField(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 {
		return ""
	}
	return f[1]
}

// SysctlSecret reports whether a sysctl (sysctl -a's name) holds a secret,
// which is not recorded: net.ipv6.conf.*.stable_secret, the key of the
// stable privacy addresses (RFC 7217), readable by root once it is set.
func SysctlSecret(name string) bool {
	return strings.HasSuffix(name, ".stable_secret")
}

func firstField(line string) string {
	if i := strings.IndexAny(line, " \t"); i > 0 {
		return line[:i]
	}
	return ""
}

// ReadSnap reads a snapshot source. A file that does not exist (a module
// not loaded, a fixture without it) has no lines and no error. Keys are
// unique: a repeated one gets "#n" appended.
func (f FS) ReadSnap(s SnapSource) ([]SnapLine, error) {
	b, err := os.ReadFile(f.path(s.Path...))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	text := strings.TrimSuffix(string(b), "\n")
	if text == "" {
		return nil, nil
	}
	lines := strings.Split(text, "\n")
	out := make([]SnapLine, len(lines))
	seen := make(map[string]int, len(lines))
	for i, l := range lines {
		k := ""
		if s.Key != nil {
			k = s.Key(l)
		}
		if k == "" {
			k = "#" + strconv.Itoa(i)
		}
		if n := seen[k]; n > 0 {
			seen[k] = n + 1
			k += "#" + strconv.Itoa(n)
		} else {
			seen[k] = 1
		}
		out[i] = SnapLine{Key: k, Line: l}
	}
	return out, nil
}
