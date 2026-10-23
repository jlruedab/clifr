package recorder

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"clifr/internal/store"
)

// verifyCommands are run right after a checkpoint sample. Their output is
// stored so `clifr verify` can compare it with the reconstruction.
var verifyCommands = [][]string{
	// The system-wide tools first: they are compared with the counters of
	// the sample, which keep moving.
	{"uptime"},
	{"vmstat"},
	{"mpstat", "-P", "ALL"},
	{"iostat", "-dx"},
	{"free"},
	{"ss", "-s"},
	{"nstat", "-zas"}, // iproute2; -s: no history file written
	{"netstat", "-s"}, // net-tools; skipped where it is not installed
	{"netstat", "-s", "-6"},
	{"ip", "-s", "-d", "link"},
	{"ip", "-o", "addr"},
	{"ip", "-d", "address"},
	{"ip", "route", "show", "table", "all"},
	{"ip", "-6", "route", "show", "table", "all"},
	{"ip", "-4", "rule", "list"},
	{"ip", "-6", "rule", "list"},
	{"dmesg"},
	{"dmesg", "-T"},
	{"systemctl", "list-units", "--no-pager"},
	{"systemctl", "list-units", "--all", "--no-pager"},
	{"systemctl", "list-units", "--failed", "--no-pager"},
	{"uname", "-a"},
	{"df"},
	{"df", "-al", "-x", "autofs"},
	{"mount"},
	{"findmnt"},
	{"ps", "aux"},
	{"top", "-b", "-n", "1", "-w", "512"}, // wide: command names are not cut
	{"pstree", "-lpT"},                    // psmisc; skipped where it is not installed
	{"ps", "auxfwww"},
	{"ps", "-ef"},
	{"ps", "alxwww"},
	{"ps", "auxZww"},
	{"pidstat", "-h", "-u", "-r", "-d", "-w", "-p", "ALL"}, // sysstat; skipped where it is not installed
	{"systemd-cgls", "--no-pager"},
	{"systemd-cgls", "--no-pager", "-l"},
	{"swapon", "--show"},
	{"swapon", "--summary"},
	{"lsmod"},
	{"lsblk"},
	{"lsblk", "-f"},
	{"mount", "-l"},
	{"ip", "neigh"},
	{"ip", "-s", "-s", "neigh"},
	{"ip", "netns"},
	{"lslocks"},
	{"ipcs"},
	{"ipcs", "-u"},
	{"sysctl", "-a"},
	{"slabtop", "-o"}, // procps; needs root (it is)
	{"numastat"},      // numactl; skipped where it is not installed
	{"numastat", "-m"},
	{"conntrack", "-S"}, // conntrack-tools; skipped where it is not installed
	{"nfsstat"},         // nfs-utils; likewise
	{"mountstats"},
	{"mountstats", "-x"},
	{"ss", "-tanp"},
	{"netstat", "-tanp"}, // net-tools; skipped where it is not installed
	// -K i: no per-thread rows. They repeat the process's rows (a million
	// lines on a busy server) and are not compared.
	{"lsof", "-n", "-P", "-K", "i"},
}

// captureVerify runs the real tools and queues their output for the next
// transaction. The commands run inside the recorder's cgroup, so benchmark
// runs that measure recorder cost must not use --verify-every.
func (r *Recorder) captureVerify(sampleTS int64) {
	for _, argv := range verifyCommands {
		path, err := exec.LookPath(argv[0])
		if err != nil {
			r.log.Warnf("verify: %s not found, skipping", argv[0])
			continue
		}
		cmd := exec.Command(path, argv[1:]...)
		cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		var out bytes.Buffer
		cmd.Stdout = &out
		start := time.Now()
		if err := cmd.Start(); err != nil {
			r.log.Errorf("verify: %s: %v", argv[0], err)
			continue
		}
		pid := cmd.Process.Pid
		err = cmd.Wait()
		end := time.Now()
		if err != nil && out.Len() == 0 { // lsof exits 1 on harmless warnings
			r.log.Errorf("verify: %s: %v", argv[0], err)
			continue
		}
		r.pending.Verify = append(r.pending.Verify, store.VerifySnap{
			TS: start.UnixMilli(), EndTS: end.UnixMilli(), SampleTS: sampleTS,
			Cmd: strings.Join(argv, " "), IgnorePIDs: fmt.Sprintf("%d,%s", os.Getpid(), strconv.Itoa(pid)),
			Output: r.redact.Text(out.String()), // the real tools show the command lines as they are
		})
	}
}
