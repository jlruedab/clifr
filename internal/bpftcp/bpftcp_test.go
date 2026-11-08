package bpftcp

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestLiveTCP (root): a connection accepted and closed normally, one closed
// with RST, and a connect to a closed port, with every fallback combination.
func TestLiveTCP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (CAP_BPF, CAP_PERFMON)")
	}
	for _, o := range []Options{{}, {ForceKprobes: true}, {ForcePerf: true}, {ForcePerf: true, ForceKprobes: true}} {
		s, err := Open(o)
		if err != nil {
			t.Fatalf("%+v: %v", o, err)
		}
		name := s.Buffer + "+" + s.Probes
		ln, _ := net.Listen("tcp4", "127.0.0.1:0")
		port := ln.Addr().(*net.TCPAddr).Port
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Read(make([]byte, 10))
				c.Close()
			}
		}()
		// Normal: client writes and closes; server reads and closes.
		c, _ := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		normalPort := c.LocalAddr().(*net.TCPAddr).Port
		c.Write([]byte("hi"))
		time.Sleep(50 * time.Millisecond)
		c.Close()
		// Abortive close: SO_LINGER 0 sends RST.
		c2, _ := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		rstPort := c2.LocalAddr().(*net.TCPAddr).Port
		c2.(*net.TCPConn).SetLinger(0)
		c2.Close()
		// Refused: nobody listens.
		dead, _ := net.Listen("tcp4", "127.0.0.1:0")
		deadPort := dead.Addr().(*net.TCPAddr).Port
		dead.Close()
		net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", deadPort), time.Second)
		time.Sleep(200 * time.Millisecond)
		ln.Close()

		var evs []Event
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			e, err := s.Read(200 * time.Millisecond)
			if err == nil {
				evs = append(evs, e)
			}
		}
		involved := func(e Event, p int) bool { return e.SPort == p || e.DPort == p }
		sks := map[uint64]bool{}
		var rstSK uint64
		for _, e := range evs {
			if e.Kind == State && (involved(e, port) || involved(e, deadPort)) {
				sks[e.SK] = true
			}
			if e.Kind == State && e.SPort == rstPort {
				rstSK = e.SK
			}
		}
		var sawListen, sawAcceptFD, sawClientOwner, sawRSTSent, sawRSTRecv, sawAppClose, sawTW bool
		for _, e := range evs {
			if !sks[e.SK] {
				continue
			}
			if testing.Verbose() && o == (Options{}) {
				t.Logf("%-9s sk %x %d->%d %v:%d -> %v:%d owner %+v counters %d/%d/%d", e.Kind, e.SK&0xffff, e.Old, e.New,
					e.SAddr, e.SPort, e.DAddr, e.DPort, e.Owner, e.Retransmits, e.ResetsSent, e.ResetsReceived)
			}
			switch {
			case e.Kind == State && e.New == Listen && e.Owner.PID == os.Getpid() && e.Owner.FD > 0 && e.Owner.Inode != 0:
				sawListen = true
			case e.Kind == AcceptFD && e.Owner.PID == os.Getpid() && e.Owner.FD > 0 && e.Owner.Inode != 0:
				sawAcceptFD = true
			case e.Kind == State && e.New == SynSent && e.Owner.PID == os.Getpid() && e.Owner.FD > 0:
				sawClientOwner = true
			case e.Kind == AppClose:
				sawAppClose = true
			case e.Kind == TimeWaitStart && (e.New == TimeWait || e.New == FinWait2):
				sawTW = true
			}
			if e.Kind == ActiveReset && e.SK == rstSK {
				sawRSTSent = true
			}
			if e.Kind == State && e.New == Close && e.DPort == deadPort && e.ResetsReceived > 0 {
				sawRSTRecv = true
			}
		}
		_ = normalPort
		if !(sawListen && sawAcceptFD && sawClientOwner && sawRSTSent && sawRSTRecv && sawAppClose && sawTW) {
			t.Errorf("%s: listen %v accept-fd %v connect-owner %v rst-sent %v rst-received %v app-close %v time-wait %v",
				name, sawListen, sawAcceptFD, sawClientOwner, sawRSTSent, sawRSTRecv, sawAppClose, sawTW)
		}
		var own syscall.Stat_t
		syscall.Stat("/proc/self/ns/net", &own)
		for _, e := range evs {
			if sks[e.SK] && e.NetNS != uint32(own.Ino) {
				t.Errorf("%s: %s event of sk %x: netns %d, want ours %d", name, e.Kind, e.SK&0xffff, e.NetNS, own.Ino)
				break
			}
		}
		t.Logf("%s: %d events; missing hooks %v; drops %v; resets without socket %d", name, len(evs), s.Missing, s.Drops(), s.NoSocketResets())
		s.Close()
	}
	_ = syscall.SIGTERM
}

// TestLiveTCPNetNS (root): a connection inside another network namespace
// carries that namespace's number, not ours (containers and pods reuse the
// same addresses, 127.0.0.1 in each).
func TestLiveTCPNetNS(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, c := range []string{"unshare", "ip", "python3"} {
		if _, err := exec.LookPath(c); err != nil {
			t.Skip("needs " + c)
		}
	}
	s, err := Open(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const script = `import os, socket
print(os.stat('/proc/self/ns/net').st_ino, flush=True)
l = socket.socket(); l.bind(('127.0.0.1', 47123)); l.listen()
c = socket.create_connection(('127.0.0.1', 47123)); a, _ = l.accept()
c.close(); a.close(); l.close()`
	out, err := exec.Command("unshare", "-n", "sh", "-c", "ip link set lo up && exec python3 -c \"$0\"", script).Output()
	if err != nil {
		t.Fatalf("unshare: %v", err)
	}
	var ns uint64
	fmt.Sscan(string(out), &ns)
	var own syscall.Stat_t
	syscall.Stat("/proc/self/ns/net", &own)
	if ns == 0 || ns == own.Ino {
		t.Fatalf("namespace of the script: %q (ours %d)", out, own.Ino)
	}
	n := 0
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		e, err := s.Read(200 * time.Millisecond)
		if err != nil || e.Kind != State || (e.SPort != 47123 && e.DPort != 47123) {
			continue
		}
		n++
		if e.NetNS != uint32(ns) {
			t.Errorf("state %d->%d %v:%d -> %v:%d: netns %d, want the script's %d", e.Old, e.New, e.SAddr, e.SPort, e.DAddr, e.DPort, e.NetNS, ns)
		}
	}
	if n < 4 {
		t.Errorf("only %d state events of the connection in the other namespace", n)
	}
	t.Logf("%d state events in namespace %d (ours %d)", n, ns, own.Ino)
}
