package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/bpfproc"
	"clifr/internal/bpftcp"
	"clifr/internal/procfs"
)

// testEBPF loads the eBPF programs, triggers each event type and checks that
// it arrives: fork, exec (argv, truncation), exit code, exit by signal and
// an OOM kill in a cgroup limited to 48 MB. It needs root.
func testEBPF(o bpfproc.Options, to bpftcp.Options) error {
	src, err := bpfproc.Open(o)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	defer src.Close()
	fmt.Printf("loaded: buffer %s, fork/exec/exit %s, oom tracepoint %v\n", src.Buffer, src.Fork, src.OOM)

	evs := make(chan bpfproc.Event, 4096)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if e, err := src.Read(200 * time.Millisecond); err == nil {
				evs <- e
			}
		}
	}()
	defer close(stop)
	// wait collects events for pid until all wanted kinds arrived (or 5 s).
	wait := func(pid int, want ...bpfproc.Kind) map[bpfproc.Kind]bpfproc.Event {
		got := map[bpfproc.Kind]bpfproc.Event{}
		wanted := map[bpfproc.Kind]bool{}
		for _, k := range want {
			wanted[k] = true
		}
		deadline := time.After(5 * time.Second)
		for len(got) < len(want) {
			select {
			case e := <-evs:
				if e.PID == pid && wanted[e.Kind] {
					got[e.Kind] = e
				}
			case <-deadline:
				return got
			}
		}
		return got
	}
	failed := 0
	check := func(name string, ok bool, detail string) {
		status := "PASS"
		if !ok {
			status, failed = "FAIL", failed+1
		}
		fmt.Printf("%s  %-34s %s\n", status, name, detail)
	}

	// Fork, exec, exit code.
	cmd := exec.Command("/bin/sh", "-c", "exit 3", "clifr-test-marker")
	cmd.Start()
	cmd.Wait()
	got := wait(cmd.Process.Pid, bpfproc.Fork, bpfproc.Exec, bpfproc.Exit)
	f, x, e := got[bpfproc.Fork], got[bpfproc.Exec], got[bpfproc.Exit]
	check("fork", f.Kind == bpfproc.Fork && f.PPID == os.Getpid(), fmt.Sprintf("child %d, parent %d", f.PID, f.PPID))
	check("exec: filename and argv", x.Filename == "/bin/sh" && x.Cmdline == "/bin/sh -c exit 3 clifr-test-marker",
		fmt.Sprintf("%s: %q", x.Filename, x.Cmdline))
	code, sig := e.ExitStatus()
	check("exit code", e.Kind == bpfproc.Exit && code == 3 && sig == 0, fmt.Sprintf("code %d, signal %d", code, sig))

	// Session, process group and terminal: the child inherits ours.
	if me, err := procfs.New("/proc").ReadStat(os.Getpid()); err != nil {
		check("fork/exec/exit: session, terminal", false, err.Error())
	} else {
		same := func(ev bpfproc.Event) bool {
			return !ev.HaveTTY || ev.SID == me.Session && ev.PGRP == me.PGRP && ev.TTY == me.TTY
		}
		check("fork/exec/exit: session, terminal", same(f) && same(x) && same(e),
			fmt.Sprintf("sid %d, pgrp %d, tty %d in the events (carried: %v); ours %d, %d, %d",
				x.SID, x.PGRP, x.TTY, x.HaveTTY, me.Session, me.PGRP, me.TTY))
	}
	testPTY(wait, check)

	long := strings.Repeat("x", 2000)
	cmd = exec.Command("/bin/sh", "-c", "exit 0", long)
	cmd.Start()
	cmd.Wait()
	x = wait(cmd.Process.Pid, bpfproc.Exec)[bpfproc.Exec]
	check("exec: long argv marked truncated", x.ArgsTruncated && len(x.Cmdline) <= bpfproc.ArgsMax,
		fmt.Sprintf("%d bytes kept, truncated %v", len(x.Cmdline), x.ArgsTruncated))

	// Exit by signal.
	cmd = exec.Command("/bin/sleep", "30")
	cmd.Start()
	time.Sleep(100 * time.Millisecond)
	cmd.Process.Signal(syscall.SIGTERM)
	cmd.Wait()
	e = wait(cmd.Process.Pid, bpfproc.Exec, bpfproc.Exit)[bpfproc.Exit]
	code, sig = e.ExitStatus()
	check("exit by signal", e.Kind == bpfproc.Exit && sig == int(syscall.SIGTERM), fmt.Sprintf("code %d, signal %d", code, sig))

	// A multi-threaded process: its exit is reported by whichever thread exits
	// last, but must carry the process's start time (the key).
	self, _ := os.Executable()
	cmd = exec.Command(self, "--thread-exit")
	cmd.Start()
	cmd.Wait()
	got = wait(cmd.Process.Pid, bpfproc.Exec, bpfproc.Exit)
	x, e = got[bpfproc.Exec], got[bpfproc.Exit]
	check("exit of a multi-threaded process", e.Kind == bpfproc.Exit && x.StartNS != 0 && e.StartNS == x.StartNS && e.Comm == x.Comm,
		fmt.Sprintf("start %d at exec, %d at exit; comm %q", x.StartNS, e.StartNS, e.Comm))

	// OOM kill.
	if !src.OOM {
		check("oom kill", false, "oom:mark_victim tracepoint not attached")
	} else if pid, err := oomVictim(); err != nil {
		check("oom kill", false, err.Error())
	} else {
		got = wait(pid, bpfproc.OOM, bpfproc.Exit)
		o, e := got[bpfproc.OOM], got[bpfproc.Exit]
		_, sig = e.ExitStatus()
		check("oom kill: victim and its RSS", o.Kind == bpfproc.OOM, fmt.Sprintf("pid %d, RSS %d kB (0: kernel lacks the field)", o.PID, o.RSSKB))
		check("oom kill: exit by SIGKILL", sig == int(syscall.SIGKILL), fmt.Sprintf("signal %d", sig))
	}
	fmt.Printf("drops: %v\n", src.Drops())
	testTCP(to, check)
	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	return nil
}

// oomVictim runs this binary as a memory hog in a new cgroup with a 48M
// memory limit and no swap, and returns its pid after it was killed.
func oomVictim() (int, error) {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return oomVictimV1() // cgroup v1 (RHEL 8's default)
	}
	cg := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("clifr-ebpf-test-%d", os.Getpid()))
	if err := os.Mkdir(cg, 0o755); err != nil {
		return 0, fmt.Errorf("cgroup: %w", err)
	}
	defer os.Remove(cg)
	os.WriteFile(filepath.Join(cg, "memory.swap.max"), []byte("0"), 0o644)
	if err := os.WriteFile(filepath.Join(cg, "memory.max"), []byte("48M"), 0o644); err != nil {
		return 0, fmt.Errorf("memory.max: %w", err)
	}
	dir, err := os.Open(cg)
	if err != nil {
		return 0, err
	}
	defer dir.Close()
	self, _ := os.Executable()
	cmd := exec.Command(self, "--oom-hog")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	return waitKilled(cmd)
}

// oomVictimV1 is oomVictim with the cgroup v1 memory controller: the hog
// waits on its standard input until it is moved into the cgroup.
func oomVictimV1() (int, error) {
	cg := filepath.Join("/sys/fs/cgroup/memory", fmt.Sprintf("clifr-ebpf-test-%d", os.Getpid()))
	if err := os.Mkdir(cg, 0o755); err != nil {
		return 0, fmt.Errorf("cgroup v1: %w", err)
	}
	defer os.Remove(cg)
	os.WriteFile(filepath.Join(cg, "memory.swappiness"), []byte("0"), 0o644)
	if err := os.WriteFile(filepath.Join(cg, "memory.limit_in_bytes"), []byte("48M"), 0o644); err != nil {
		return 0, fmt.Errorf("memory.limit_in_bytes: %w", err)
	}
	os.WriteFile(filepath.Join(cg, "memory.memsw.limit_in_bytes"), []byte("48M"), 0o644) // if swap is accounted
	self, _ := os.Executable()
	cmd := exec.Command(self, "--oom-hog")
	in, err := cmd.StdinPipe()
	if err != nil {
		return 0, err
	}
	cmd.Env = append(os.Environ(), "CLIFR_OOM_WAIT=1")
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(fmt.Sprint(cmd.Process.Pid)), 0o644); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return 0, fmt.Errorf("cgroup.procs: %w", err)
	}
	in.Write([]byte("go\n"))
	in.Close()
	return waitKilled(cmd)
}

func waitKilled(cmd *exec.Cmd) (int, error) {
	err := cmd.Wait()
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		return cmd.Process.Pid, fmt.Errorf("the hog was not OOM-killed: %v", err)
	}
	return cmd.Process.Pid, nil
}

// oomHog touches memory until the cgroup limit kills it.
func oomHog() {
	if os.Getenv("CLIFR_OOM_WAIT") != "" { // moved into the cgroup first (v1)
		os.Stdin.Read(make([]byte, 8))
	}
	var keep [][]byte
	for i := 0; i < 1024; i++ {
		b := make([]byte, 1<<20)
		for j := 0; j < len(b); j += 4096 {
			b[j] = 1
		}
		keep = append(keep, b)
	}
	fmt.Fprintln(os.Stderr, "oom hog: allocated 1 GB without being killed", len(keep))
	os.Exit(1)
}

// threadExit exits from a thread other than the main one, with more threads
// still running.
func threadExit() {
	for i := 0; i < 4; i++ {
		go func() {
			runtime.LockOSThread()
			select {}
		}()
	}
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		time.Sleep(50 * time.Millisecond)
		os.Exit(0)
		close(done)
	}()
	<-done
}

// testTCP: a listener, a connection accepted and closed normally, one closed
// with RST (SO_LINGER 0), and a connect to a closed port.
func testTCP(o bpftcp.Options, check func(string, bool, string)) {
	src, err := bpftcp.Open(o)
	if err != nil {
		check("tcp: load", false, err.Error())
		return
	}
	defer src.Close()
	fmt.Printf("tcp loaded: buffer %s, probes %s, state %s, missing %v\n", src.Buffer, src.Probes, src.State, src.Missing)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		check("tcp: listen", false, err.Error())
		return
	}
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Read(make([]byte, 8))
			c.Close()
		}
	}()
	c, _ := net.Dial("tcp4", ln.Addr().String())
	cport := c.LocalAddr().(*net.TCPAddr).Port
	c.Write([]byte("x"))
	time.Sleep(50 * time.Millisecond)
	c.Close()
	c2, _ := net.Dial("tcp4", ln.Addr().String())
	rport := c2.LocalAddr().(*net.TCPAddr).Port
	c2.(*net.TCPConn).SetLinger(0)
	c2.Close()
	dead, _ := net.Listen("tcp4", "127.0.0.1:0")
	deadPort := dead.Addr().(*net.TCPAddr).Port
	dead.Close()
	net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", deadPort), time.Second)
	// IPv6 listeners: Go leaves IPV6_V6ONLY off for "tcp" on the wildcard
	// address and sets it for "tcp6".
	dual, _ := net.Listen("tcp", "[::]:0")
	only6, _ := net.Listen("tcp6", "[::]:0")
	v6ports := [2]int{}
	for i, l := range []net.Listener{dual, only6} {
		if l != nil {
			v6ports[i] = l.Addr().(*net.TCPAddr).Port
			defer l.Close()
		}
	}
	// A connection over IPv6 loopback: its addresses are checked whole.
	v6client := 0
	if only6 != nil {
		if c6, err := net.Dial("tcp6", fmt.Sprintf("[::1]:%d", v6ports[1])); err == nil {
			v6client = c6.LocalAddr().(*net.TCPAddr).Port
			defer c6.Close()
		}
	}
	time.Sleep(300 * time.Millisecond)
	ln.Close()

	var evs []bpftcp.Event
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		if e, err := src.Read(100 * time.Millisecond); err == nil {
			evs = append(evs, e)
		}
	}
	me := os.Getpid()
	sk := map[string]uint64{}
	for _, e := range evs {
		if e.Kind != bpftcp.State {
			continue
		}
		switch {
		case e.New == bpftcp.Listen && e.SPort == port:
			sk["listen"] = e.SK
		case e.SPort == cport && e.DPort == port:
			sk["client"] = e.SK
		case e.SPort == port && e.DPort == cport:
			sk["server"] = e.SK
		case e.SPort == rport && e.DPort == port:
			sk["rst"] = e.SK
		case e.DPort == deadPort:
			sk["refused"] = e.SK
		}
	}
	find := func(s uint64, ok func(bpftcp.Event) bool) (bpftcp.Event, bool) {
		for _, e := range evs {
			if e.SK == s && ok(e) {
				return e, true
			}
		}
		return bpftcp.Event{}, false
	}
	try := check // counts failures
	e, ok := find(sk["listen"], func(e bpftcp.Event) bool { return e.New == bpftcp.Listen })
	try("tcp: listen owner and fd", ok && e.Owner.PID == me && e.Owner.FD >= 0 && e.Owner.Inode != 0, fmt.Sprintf("%+v", e.Owner))
	e, ok = find(sk["client"], func(e bpftcp.Event) bool { return e.New == bpftcp.SynSent })
	try("tcp: connect owner and fd", ok && e.Owner.PID == me && e.Owner.FD >= 0, fmt.Sprintf("%+v", e.Owner))
	// The kernel picks the local port after SYN_SENT: it comes with the
	// connect's return (or the SYN_SENT event has it already).
	// (Perf buffers do not order events across CPUs, and the socket's
	// pointer is soon reused: look for this connection's port among all.)
	lp, ok := find(sk["client"], func(e bpftcp.Event) bool {
		return (e.Kind == bpftcp.LocalPort || e.Kind == bpftcp.State && e.New == bpftcp.SynSent) && e.SPort == cport
	})
	try("tcp: connect's local port", ok, fmt.Sprintf("%v %d, want %d", lp.Kind, lp.SPort, cport))
	lo4, lo6 := netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()
	try("tcp: IPv4 addresses", ok && e.SAddr == lo4 && e.DAddr == lo4, fmt.Sprintf("%v -> %v", e.SAddr, e.DAddr))
	var e6 bpftcp.Event
	for _, x := range evs {
		// At SYN_SENT an IPv6 socket may not have its local port yet.
		if x.Kind == bpftcp.State && x.New == bpftcp.SynSent && x.DPort == v6ports[1] && v6client != 0 {
			e6 = x
		}
	}
	try("tcp: IPv6 addresses", e6.SAddr == lo6 && e6.DAddr == lo6, fmt.Sprintf("%v -> %v", e6.SAddr, e6.DAddr))
	e, ok = find(sk["server"], func(e bpftcp.Event) bool { return e.Kind == bpftcp.AcceptFD })
	try("tcp: accept owner and fd", ok && e.Owner.PID == me && e.Owner.FD >= 0 && e.Owner.Inode != 0, fmt.Sprintf("%+v", e.Owner))
	_, ok = find(sk["client"], func(e bpftcp.Event) bool { return e.Kind == bpftcp.AppClose })
	try("tcp: application close", ok, "")
	_, ok1 := find(sk["client"], func(e bpftcp.Event) bool { return e.Kind == bpftcp.TimeWaitStart })
	_, ok2 := find(sk["server"], func(e bpftcp.Event) bool { return e.Kind == bpftcp.TimeWaitStart })
	try("tcp: time-wait continuation", ok1 || ok2, "")
	_, ok = find(sk["rst"], func(e bpftcp.Event) bool { return e.Kind == bpftcp.ActiveReset })
	try("tcp: reset sent (SO_LINGER 0)", ok, "")
	// By port as well: the pointer may have belonged to an earlier socket of this test.
	e, ok = find(sk["refused"], func(e bpftcp.Event) bool { return e.New == bpftcp.Close && e.DPort == deadPort })
	try("tcp: refused connect, reset received", ok && e.ResetsReceived > 0, fmt.Sprintf("resets received %d", e.ResetsReceived))
	if v6ports[0] != 0 && v6ports[1] != 0 {
		got := map[int]string{}
		for _, e := range evs {
			if e.Kind == bpftcp.State && e.New == bpftcp.Listen && e.Family == 10 {
				got[e.SPort] = fmt.Sprintf("%v v6only=%v", e.SAddr, e.V6Only)
			}
		}
		d, o := got[v6ports[0]], got[v6ports[1]]
		try("tcp: IPv6 listener, v6only flag", d == ":: v6only=false" && o == ":: v6only=true", fmt.Sprintf("dual-stack %q, IPv6 only %q", d, o))
	} else {
		fmt.Println("SKIP  tcp: IPv6 listener, v6only flag (no IPv6 listener possible)")
	}
	fmt.Printf("tcp drops: %v\n", src.Drops())
}

// testPTY starts a process in a new session on a pseudo-terminal and checks
// that its exec event carries what /proc/<pid>/stat shows.
func testPTY(wait func(int, ...bpfproc.Kind) map[bpfproc.Kind]bpfproc.Event, check func(string, bool, string)) {
	const name = "exec: new session on a pty"
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		check(name, false, err.Error())
		return
	}
	defer ptmx.Close()
	n, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err == nil {
		err = unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0)
	}
	if err != nil {
		check(name, false, err.Error())
		return
	}
	pts, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		check(name, false, err.Error())
		return
	}
	defer pts.Close()
	cmd := exec.Command("/bin/sleep", "2")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pts, pts, pts
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		check(name, false, err.Error())
		return
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()
	x := wait(cmd.Process.Pid, bpfproc.Exec)[bpfproc.Exec]
	st, err := procfs.New("/proc").ReadStat(cmd.Process.Pid)
	if err != nil {
		check(name, false, err.Error())
		return
	}
	check(name, x.HaveTTY && x.TTY != 0 && x.TTY == st.TTY && x.SID == st.Session && x.PGRP == st.PGRP,
		fmt.Sprintf("event: tty %d, sid %d, pgrp %d; /proc: %d, %d, %d (/dev/pts/%d)", x.TTY, x.SID, x.PGRP, st.TTY, st.Session, st.PGRP, n))
}
