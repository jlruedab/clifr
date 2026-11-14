package main

import (
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Every temporary directory clifr makes (DuckDB's schema files, an unpacked
// bundle) goes into one run directory, removed at exit, on SIGINT, SIGTERM
// and SIGHUP, and when the reader of its output goes away (| head): before,
// a clifr killed mid-query left them in /tmp, a whole unpacked bundle
// included. One killed with SIGKILL leaves its run directory, which the next
// clifr of the same user removes (runPrefix + the dead PID).

const runPrefix = "clifr-run-"

// restoreTerm, while the pager has the terminal in raw mode, puts it back.
var (
	termMu      sync.Mutex
	restoreTerm func()
)

func setRestoreTerm(f func()) {
	termMu.Lock()
	restoreTerm = f
	termMu.Unlock()
}

// setupTemp makes the run directory, points TMPDIR at it and installs the
// signal handler; the returned function removes it (and --host's query
// directories) and may be called more than once.
func setupTemp() func() {
	base := os.TempDir()
	sweepStale(base)
	d, err := os.MkdirTemp(base, runPrefix+strconv.Itoa(os.Getpid())+"-")
	if err != nil {
		return cleanupRemote // clifr still works, as before
	}
	os.Setenv("TMPDIR", d)
	var once sync.Once
	clean := func() {
		once.Do(func() {
			cleanupRemote()
			os.RemoveAll(d)
		})
	}
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGPIPE)
	go func() {
		for s := range ch {
			// With SIGPIPE notified, a write to any broken pipe or socket
			// raises it (a --host connection too): only stdout's ends clifr.
			if s == syscall.SIGPIPE && !stdoutBroken() {
				continue
			}
			termMu.Lock()
			if restoreTerm != nil {
				restoreTerm()
			}
			termMu.Unlock()
			clean()
			os.Exit(128 + int(s.(syscall.Signal)))
		}
	}()
	return clean
}

// stdoutBroken: stdout is a pipe or socket whose reader has gone.
func stdoutBroken() bool {
	fds := []unix.PollFd{{Fd: 1, Events: unix.POLLOUT}}
	n, err := unix.Poll(fds, 0)
	return err == nil && n > 0 && fds[0].Revents&(unix.POLLERR|unix.POLLHUP) != 0
}

// sweepStale removes run directories of this user's clifr processes that no
// longer exist (killed with SIGKILL, or a crash).
func sweepStale(base string) {
	entries, _ := os.ReadDir(base)
	uid := os.Getuid()
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !strings.HasPrefix(name, runPrefix) {
			continue
		}
		pidText, _, ok := strings.Cut(strings.TrimPrefix(name, runPrefix), "-")
		pid, err := strconv.Atoi(pidText)
		if !ok || err != nil || pid <= 0 {
			continue
		}
		var st unix.Stat_t
		if unix.Lstat(filepath.Join(base, name), &st) != nil || int(st.Uid) != uid {
			continue
		}
		if err := unix.Kill(pid, 0); errors.Is(err, unix.ESRCH) {
			os.RemoveAll(filepath.Join(base, name))
		}
	}
}
