package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"clifr/internal/bpfproc"
	"clifr/internal/bpftcp"
	"clifr/internal/cnproc"
	"clifr/internal/procfs"
	"clifr/internal/sockdiag"
)

// Capabilities clifrd uses (linux/capability.h).
var caps = []struct {
	bit  uint
	name string
}{{2, "CAP_DAC_READ_SEARCH"}, {12, "CAP_NET_ADMIN"}, {19, "CAP_SYS_PTRACE"}, {21, "CAP_SYS_ADMIN"},
	{24, "CAP_SYS_RESOURCE"}, {38, "CAP_PERFMON"}, {39, "CAP_BPF"}}

// doctor checks what this system supports without recording anything: the
// eBPF programs are loaded and closed again, the other sources read once.
// It reports the recording level clifrd would run at and exits non-zero if
// it could not record at all.
func doctor(dataDir, configPath string) error {
	var u unix.Utsname
	unix.Uname(&u)
	line := func(what, detail string, ok bool) {
		mark := "ok"
		if !ok {
			mark = "--"
		}
		fmt.Printf("  %-16s %-2s %s\n", what, mark, detail)
	}
	fmt.Println("clifrd doctor: what this system supports (nothing is recorded)")
	line("kernel", unix.ByteSliceToString(u.Release[:])+" "+runtime.GOARCH, true)
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	line("BTF", "/sys/kernel/btf/vmlinux "+okText(err, "present", "missing: eBPF programs cannot load (CO-RE)"), err == nil)

	eff := effectiveCaps()
	var have, missing []string
	for _, c := range caps {
		if eff&(1<<c.bit) != 0 {
			have = append(have, c.name)
		} else if c.name != "CAP_SYS_ADMIN" {
			missing = append(missing, c.name)
		}
	}
	priv := fmt.Sprintf("uid %d; %s", os.Geteuid(), strings.Join(have, " "))
	if len(missing) > 0 {
		priv += "; missing " + strings.Join(missing, " ")
	}
	line("privileges", priv, len(missing) == 0 || eff&(1<<21) != 0)

	procEvents := ""
	if src, err := bpfproc.Open(bpfproc.Options{}); err == nil {
		procEvents = fmt.Sprintf("eBPF (%s, fork/exec/exit %s", src.Buffer, src.Fork)
		if src.OOM {
			procEvents += ", OOM kills"
		}
		procEvents += ")"
		src.Close()
		line("process events", procEvents, true)
	} else if l, err2 := cnproc.Listen(); err2 == nil {
		l.Close()
		procEvents = "proc connector"
		line("process events", "proc connector (eBPF: "+err.Error()+"): no exit codes, no exec arguments, no OOM victims' RSS", true)
	} else {
		line("process events", "none (eBPF: "+err.Error()+"; proc connector: "+err2.Error()+"): short-lived processes between samples are missed", false)
	}
	tcpEvents := false
	if src, err := bpftcp.Open(bpftcp.Options{}); err == nil {
		d := fmt.Sprintf("eBPF (%s, %s, state %s", src.Buffer, src.Probes, src.State)
		if src.TWEnd {
			d += ", time-wait end exact"
		}
		if len(src.Missing) > 0 {
			d += "; without " + strings.Join(src.Missing, ", ")
		}
		src.Close()
		tcpEvents = true
		line("TCP events", d+")", true)
	} else {
		line("TCP events", "none ("+err.Error()+"): sockets are sampled every interval (short connections are missed)", false)
	}
	if socks, err := sockdiag.Dump(); err == nil {
		line("socket dumps", fmt.Sprintf("sock_diag (%d sockets now)", len(socks)), true)
	} else {
		line("socket dumps", "/proc/net fallback (sock_diag: "+err.Error()+"; slower)", false)
	}
	fs := procfs.New("/proc")
	n, ok := fs.FDCount(os.Getpid())
	line("fd counts", okBool(ok && n > 0, "the size of /proc/<pid>/fd (Linux 6.2+): unchanged processes are not re-read",
		"not available (before Linux 6.2): every process is read at every fd walk"), ok && n > 0)
	_, err = fs.ReadIO(1)
	line("process I/O", "/proc/<pid>/io "+okText(err, "readable", "not readable"), err == nil)
	_, err = fs.ReadMountInfo()
	line("mount events", "mountinfo "+okText(err, "readable (changes via POLLPRI)", "not readable"), err == nil)

	if _, err := os.Stat(configPath); err == nil {
		line("configuration", configPath+" valid", true) // run() has applied it
	} else {
		line("configuration", configPath+" not found: defaults", true)
	}
	d, ok := dataDirState(dataDir)
	line("data directory", d, ok)

	level := "full: process and TCP events from eBPF, samples, fd walks, keyframes"
	switch {
	case procEvents == "" && !tcpEvents:
		level = "sampling only: processes, sockets and files at each sample; short-lived ones are missed"
	case !tcpEvents:
		level = "reduced: process events (" + procEvents + "), TCP sampled every interval"
	case !strings.HasPrefix(procEvents, "eBPF"):
		level = "reduced: process events from the proc connector, TCP from eBPF"
	}
	fmt.Println("Recording level:", level)
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		return fmt.Errorf("cannot read /proc: %w", err)
	}
	return nil
}

func dataDirState(dir string) (string, bool) {
	st, err := os.Stat(dir)
	if err != nil {
		parent := dir[:max(strings.LastIndexByte(dir, '/'), 1)]
		if unix.Access(parent, unix.W_OK) == nil {
			return dir + " does not exist yet (it will be created)", true
		}
		return dir + ": " + err.Error(), false
	}
	var sfs unix.Statfs_t
	free := ""
	if unix.Statfs(dir, &sfs) == nil {
		free = fmt.Sprintf(", %.1f GiB free", float64(sfs.Bavail)*float64(sfs.Bsize)/(1<<30))
	}
	sys := st.Sys().(*syscall.Stat_t)
	d := fmt.Sprintf("%s mode %o, owner %d:%d%s", dir, st.Mode().Perm(), sys.Uid, sys.Gid, free)
	if st.Mode().Perm()&0o007 != 0 {
		return d + ": readable by everyone (command lines of every user are in it)", false
	}
	if unix.Access(dir, unix.W_OK) != nil {
		return d + ": not writable", false
	}
	return d, true
}

// effectiveCaps reads CapEff from /proc/self/status.
func effectiveCaps() uint64 {
	b, _ := os.ReadFile("/proc/self/status")
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "CapEff:"); ok {
			n, _ := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return n
		}
	}
	return 0
}

func okText(err error, ok, bad string) string {
	if err == nil {
		return ok
	}
	return bad + " (" + err.Error() + ")"
}

func okBool(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}
