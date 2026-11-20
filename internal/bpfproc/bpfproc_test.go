package bpfproc

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"clifr/internal/procfs"
)

// TestLiveEvents loads the programs (as root) with every fallback
// combination and checks a short process's fork, exec and exit events.
func TestLiveEvents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (CAP_BPF, CAP_PERFMON)")
	}
	for _, o := range []Options{{}, {ForceClassicFork: true}, {ForcePerf: true}, {ForcePerf: true, ForceClassicFork: true}} {
		s, err := Open(o)
		if err != nil {
			t.Fatalf("%+v: %v", o, err)
		}
		cmd := exec.Command("/bin/sh", "-c", "exit 3", "clifr-bpf-test", "arg two")
		cmd.Start()
		pid := cmd.Process.Pid
		cmd.Wait()
		got := map[Kind]Event{}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && len(got) < 3 {
			e, err := s.Read(200 * time.Millisecond)
			if err != nil {
				continue
			}
			if e.PID == pid {
				got[e.Kind] = e
			}
		}
		name := s.Buffer + "+" + s.Fork
		ex, ok := got[Exec]
		if !ok || ex.Filename != "/bin/sh" || !strings.Contains(ex.Cmdline, "exit 3 clifr-bpf-test arg two") || ex.StartNS == 0 {
			t.Errorf("%s: exec event %+v", name, ex)
		}
		if code, sig := got[Exit].ExitStatus(); got[Exit].Kind != Exit || code != 3 || sig != 0 || got[Exit].StartNS != ex.StartNS {
			t.Errorf("%s: exit event %+v (code %d signal %d)", name, got[Exit], code, sig)
		}
		if f, ok := got[Fork]; !ok || f.PPID != os.Getpid() {
			t.Errorf("%s: fork event %+v", name, f)
		}
		t.Logf("%s: fork, exec (%q), exit code 3: ok; oom attached: %v; drops %v", name, ex.Cmdline, s.OOM, s.Drops())
		s.Close()
	}
}

// The start time from the event must equal /proc/<pid>/stat's, tick for
// tick: it is half of the key that identifies a process across sources.
func TestStartTicksMatchProc(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	s, err := Open(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fs := procfs.New("/proc")
	for i := 0; i < 20; i++ {
		cmd := exec.Command("/bin/sleep", "5")
		cmd.Start()
		pid := cmd.Process.Pid
		st, err := fs.ReadStat(pid)
		var ev Event
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			e, rerr := s.Read(200 * time.Millisecond)
			if rerr == nil && e.PID == pid && e.Kind == Exec {
				ev = e
				break
			}
		}
		cmd.Process.Kill()
		cmd.Wait()
		if err != nil || ev.Kind != Exec || ev.StartTicks() != st.StartTime {
			t.Fatalf("pid %d: event start %d ticks, /proc %d (%v)", pid, ev.StartTicks(), st.StartTime, err)
		}
	}
}

// TestKillers checks the sender of the signal that killed a process: another
// process, the process itself, a handler that re-raises (the first sender
// stays) and the kernel (SIGXCPU from a CPU time limit).
func TestKillers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (CAP_BPF, CAP_PERFMON)")
	}
	s, err := Open(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.Killers {
		t.Skip("signal_generate not attached (no tp_btf)")
	}
	exitOf := func(pid int) Event {
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			if e, err := s.Read(200 * time.Millisecond); err == nil && e.PID == pid && e.Kind == Exit {
				return e
			}
		}
		t.Fatalf("no exit event for %d", pid)
		return Event{}
	}
	me, _ := os.ReadFile("/proc/self/comm")
	for _, c := range []struct {
		name, script string
		term         bool // the test sends SIGTERM
		sig          int
		self, kernel bool
	}{
		{"other", "sleep 30", true, 15, false, false},
		{"self", "kill -TERM $$", false, 15, true, false},
		{"re-raise", `trap 'trap - TERM; kill -TERM $$' TERM; sleep 30 & wait`, true, 15, false, false},
		{"kernel", "ulimit -S -t 1; while :; do :; done", false, 24, false, true},
	} {
		cmd := exec.Command("/bin/sh", "-c", c.script)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pid := cmd.Process.Pid
		if c.term {
			time.Sleep(300 * time.Millisecond)
			cmd.Process.Signal(syscall.SIGTERM)
		}
		cmd.Wait()
		e := exitOf(pid)
		_, sig := e.ExitStatus()
		want := os.Getpid()
		comm := strings.TrimSpace(string(me))
		if c.self {
			want, comm = pid, "sh"
		}
		switch {
		case sig != c.sig || !e.HaveKiller:
			t.Errorf("%s: signal %d (want %d), sender known %v", c.name, sig, c.sig, e.HaveKiller)
		case c.kernel && (!e.KillerKernel || e.KillerPID != 0):
			t.Errorf("%s: sender %d %q, want the kernel", c.name, e.KillerPID, e.KillerComm)
		case !c.kernel && (e.KillerKernel || e.KillerPID != want || e.KillerComm != comm || e.KillerUID != 0):
			t.Errorf("%s: sender %d %q uid %d kernel %v, want %d %q", c.name, e.KillerPID, e.KillerComm, e.KillerUID, e.KillerKernel, want, comm)
		default:
			t.Logf("%s: signal %d from %d %q (kernel %v)", c.name, sig, e.KillerPID, e.KillerComm, e.KillerKernel)
		}
	}
}
