package bpftcp

import (
	"fmt"
	"net"
	"os"
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
		t.Logf("%s: %d events; missing hooks %v; drops %v; resets without socket %d", name, len(evs), s.Missing, s.Drops(), s.NoSocketResets())
		s.Close()
	}
	_ = syscall.SIGTERM
}
