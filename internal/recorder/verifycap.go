package recorder

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// verifyPath is where the real tools are looked for and what they get as
// PATH: root's system directories only, whatever PATH clifrd was started with
// (a user's directory early in it would have root run that user's "ps").
const verifyPath = "/usr/sbin:/usr/bin:/sbin:/bin"

// lookSystem finds name in verifyPath.
func lookSystem(name string) (string, error) {
	for _, d := range filepath.SplitList(verifyPath) {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", exec.ErrNotFound
}

// captureVerify runs the real tools and queues their output for the next
// transaction. The commands run inside the recorder's cgroup, so benchmark
// runs that measure recorder cost must not use --verify-every.
//
// A tool that is missing, or that fails without output (RHEL's nfsstat exits
// 2 where NFS is not in use: "No Client Stats"), is skipped: nothing is
// compared for it. That is said once per run, not at every checkpoint.
func (r *Recorder) captureVerify(sampleTS int64) {
	for _, argv := range verifyCommands {
		cmdline := strings.Join(argv, " ")
		path, err := lookSystem(argv[0])
		if err != nil {
			r.verifySkip(cmdline, "not found")
			continue
		}
		cmd := exec.Command(path, argv[1:]...)
		cmd.Env = []string{"LC_ALL=C", "PATH=" + verifyPath}
		var out bytes.Buffer
		var stderr limitedBuffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		start := time.Now()
		if err := cmd.Start(); err != nil {
			r.log.Errorf("verify: %s: %v", argv[0], err)
			continue
		}
		pid := cmd.Process.Pid
		err = cmd.Wait()
		end := time.Now()
		if err != nil && out.Len() == 0 { // lsof exits 1 on harmless warnings
			why := err.Error()
			if l := firstLine(stderr.String()); l != "" {
				why += ": " + l
			}
			r.verifySkip(cmdline, why)
			continue
		}
		output := r.redact.Text(out.String()) // the real tools show the command lines as they are
		if argv[0] == "sysctl" {
			output = dropSysctlSecrets(output)
		}
		r.pending.Verify = append(r.pending.Verify, store.VerifySnap{
			TS: start.UnixMilli(), EndTS: end.UnixMilli(), SampleTS: sampleTS,
			Cmd: cmdline, IgnorePIDs: fmt.Sprintf("%d,%s", os.Getpid(), strconv.Itoa(pid)),
			Output: output,
		})
	}
}

// verifySkip logs a verify command skipped, once per run and command.
func (r *Recorder) verifySkip(cmdline, why string) {
	if r.verifySkipped == nil {
		r.verifySkipped = map[string]bool{}
	}
	if r.verifySkipped[cmdline] {
		return
	}
	r.verifySkipped[cmdline] = true
	r.log.Warnf("verify: %s: %s; skipped (not compared), not reported again this run", cmdline, why)
}

// limitedBuffer keeps the first 4 KiB written to it (a tool's stderr).
type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := 4096 - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(l)
}
