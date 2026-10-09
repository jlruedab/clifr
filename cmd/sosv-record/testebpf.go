package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"sosv/internal/bpfproc"
)

// testEBPF loads the eBPF programs, triggers each event type and checks that
// it arrives: fork, exec (argv, truncation), exit code, exit by signal and
// an OOM kill in a cgroup limited to 48 MB. It needs root.
func testEBPF(o bpfproc.Options) error {
	src, err := bpfproc.Open(o)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	defer src.Close()
	fmt.Printf("loaded: buffer %s, fork %s, oom tracepoint %v\n", src.Buffer, src.Fork, src.OOM)

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
	cmd := exec.Command("/bin/sh", "-c", "exit 3", "sosv-test-marker")
	cmd.Start()
	cmd.Wait()
	got := wait(cmd.Process.Pid, bpfproc.Fork, bpfproc.Exec, bpfproc.Exit)
	f, x, e := got[bpfproc.Fork], got[bpfproc.Exec], got[bpfproc.Exit]
	check("fork", f.Kind == bpfproc.Fork && f.PPID == os.Getpid(), fmt.Sprintf("child %d, parent %d", f.PID, f.PPID))
	check("exec: filename and argv", x.Filename == "/bin/sh" && x.Cmdline == "/bin/sh -c exit 3 sosv-test-marker",
		fmt.Sprintf("%s: %q", x.Filename, x.Cmdline))
	code, sig := e.ExitStatus()
	check("exit code", e.Kind == bpfproc.Exit && code == 3 && sig == 0, fmt.Sprintf("code %d, signal %d", code, sig))

	// A command line longer than the event carries.
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
	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	return nil
}

// oomVictim runs this binary as a memory hog in a new cgroup with
// memory.max 48M and no swap, and returns its pid after it was killed.
func oomVictim() (int, error) {
	cg := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("sosv-ebpf-test-%d", os.Getpid()))
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
	err = cmd.Wait()
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		return cmd.Process.Pid, fmt.Errorf("the hog was not OOM-killed: %v", err)
	}
	return cmd.Process.Pid, nil
}

// oomHog touches memory until the cgroup limit kills it.
func oomHog() {
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
