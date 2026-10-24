package recorder

import (
	"os"
	"sync"
)

// hostMountNS is where the host's mount table is read: /proc/1 (init's
// mount namespace) when it can be read, else clifrd's own (/proc/self).
// Under the shipped unit clifrd runs in a namespace of its own:
// ProtectSystem=strict remounts every file system read-only there and
// StateDirectory adds a bind mount, so its own mountinfo is not what the
// host's mount, df, findmnt and lsblk show. statfsRoot prefixes a mount
// point for statfs: /proc/1/root when the namespaces differ.
var hostMountNS = sync.OnceValues(func() (proc, statfsRoot string) {
	if f, err := os.Open("/proc/1/mountinfo"); err == nil {
		f.Close()
		self, err1 := os.Readlink("/proc/self/ns/mnt")
		host, err2 := os.Readlink("/proc/1/ns/mnt")
		if err1 == nil && err2 == nil && self != host {
			return "/proc/1", "/proc/1/root"
		}
		return "/proc/1", ""
	}
	return "/proc/self", ""
})
