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
	// atop (EPEL on RHEL; skipped where it is not installed): its screen since
	// boot (one sample), 80 columns wide into a pipe, in each process view.
	{"atop", "1", "1"},
	{"atop", "-m", "1", "1"},
	{"atop", "-d", "1", "1"},
	{"atop", "-s", "1", "1"},
	{"atop", "-v", "1", "1"},
	{"atop", "-c", "1", "1"},
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

// mountViews show the mount table of the namespace they run in. Under the
// shipped unit clifrd has one of its own (ProtectSystem, ProtectHome and
// ProtectKernelTunables add bind mounts and options), while clifrd records
// the host's (hostMountNS): compared, they would only show the sandbox
// (2026-11-20, the packaged 0.1.0: mount 79%, findmnt 84%, lsblk 0%). Plain
// df matched there (it hides those mounts), but not a namespace with a mount
// of its own (a drop-in's PrivateTmp, another systemd's sandbox).
var mountViews = map[string]bool{"df": true, "df -al -x autofs": true, "mount": true, "mount -l": true, "findmnt": true,
	"lsblk": true, "lsblk -f": true}

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
	r.startIotop(sampleTS)
	_, otherNS := hostMountNS()
	for _, argv := range verifyCommands {
		cmdline := strings.Join(argv, " ")
		if otherNS != "" && mountViews[cmdline] {
			r.verifySkip(cmdline, "clifrd runs in a mount namespace of its own (the service's sandbox), so the tool would show that one, not the host's")
			continue
		}
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
			Cmd: cmdline, IgnorePIDs: fmt.Sprintf("%d,%s%s", os.Getpid(), strconv.Itoa(pid), r.iotopIgnore()),
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

// iotopCapture is a real iotop measuring one interval in the background: it
// starts at a checkpoint, before the other tools, and is collected at a
// later sample (iotop -b -P -n 2 -d INTERVAL: its second screen is the
// interval clifr compares with, from the checkpoint sample to the one at
// its end).
type iotopCapture struct {
	cmdline  string
	sampleTS int64
	start    time.Time
	pid      int
	out      bytes.Buffer
	stderr   limitedBuffer
	done     chan error
	end      time.Time
	cmd      *exec.Cmd
}

// startIotop starts iotop at a checkpoint (Python iotop or iotop-c: skipped
// where it is not installed, and without per-process I/O counters).
func (r *Recorder) startIotop(sampleTS int64) {
	if r.iotopRun != nil || !r.cfg.ProcIO {
		return
	}
	d := max(int((r.cfg.Interval+time.Second/2)/time.Second), 1)
	argv := []string{"-b", "-P", "-n", "2", "-d", strconv.Itoa(d)}
	cmdline := "iotop " + strings.Join(argv, " ")
	path, err := lookSystem("iotop")
	if err != nil {
		r.verifySkip(cmdline, "not found")
		return
	}
	c := &iotopCapture{cmdline: cmdline, sampleTS: sampleTS, done: make(chan error, 1)}
	cmd := exec.Command(path, argv...)
	cmd.Env = []string{"LC_ALL=C", "PATH=" + verifyPath, "COLUMNS=512"}
	cmd.Stdout, cmd.Stderr = &c.out, &c.stderr
	c.start = time.Now()
	if err := cmd.Start(); err != nil {
		r.log.Errorf("verify: iotop: %v", err)
		return
	}
	c.pid = cmd.Process.Pid
	go func() {
		err := cmd.Wait()
		c.end = time.Now()
		c.done <- err
	}()
	c.cmd = cmd
	r.iotopRun = c
}

// iotopIgnore is ",PID" of the iotop running in the background (the other
// tools see it), else "".
func (r *Recorder) iotopIgnore() string {
	if r.iotopRun == nil {
		return ""
	}
	return "," + strconv.Itoa(r.iotopRun.pid)
}

// collectIotop queues iotop's output once it has finished; stop: kill it
// (shutdown).
func (r *Recorder) collectIotop(stop bool) {
	c := r.iotopRun
	if c == nil {
		return
	}
	var err error
	select {
	case err = <-c.done:
	default:
		if !stop {
			return
		}
		c.cmd.Process.Kill()
		<-c.done
		r.iotopRun = nil
		return
	}
	r.iotopRun = nil
	if err != nil && c.out.Len() == 0 {
		why := err.Error()
		if l := firstLine(c.stderr.String()); l != "" {
			why += ": " + l
		}
		r.verifySkip(c.cmdline, why)
		return
	}
	r.pending.Verify = append(r.pending.Verify, store.VerifySnap{
		TS: c.start.UnixMilli(), EndTS: c.end.UnixMilli(), SampleTS: c.sampleTS,
		Cmd: c.cmdline, IgnorePIDs: fmt.Sprintf("%d,%d", os.Getpid(), c.pid),
		Output: r.redact.Text(c.out.String()),
	})
}
