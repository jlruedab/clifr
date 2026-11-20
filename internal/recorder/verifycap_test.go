package recorder

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A verify command that fails without output (RHEL's nfsstat where NFS is
// not in use) is skipped with one warning per run, giving its stderr, not an
// error at every checkpoint; a working one is still captured.
func TestVerifySkipOnce(t *testing.T) {
	old := verifyCommands
	defer func() { verifyCommands = old }()
	verifyCommands = [][]string{
		{"sh", "-c", "echo 'Error: No Client Stats (/proc/net/rpc/nfs: No such file or directory).' >&2; exit 2"},
		{"no-such-tool-clifr-test"},
		{"echo", "hello"},
	}
	var logs bytes.Buffer
	r := &Recorder{log: NewLogger(log.New(&logs, "", 0), LevelInfo)}
	r.captureVerify(1)
	r.captureVerify(2)

	out := logs.String()
	if strings.Contains(out, "error:") {
		t.Errorf("logged as an error:\n%s", out)
	}
	if n := strings.Count(out, "warning: verify: sh -c"); n != 1 {
		t.Errorf("failing tool reported %d times, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "exit status 2: Error: No Client Stats") {
		t.Errorf("warning lacks the exit status and stderr:\n%s", out)
	}
	if n := strings.Count(out, "no-such-tool-clifr-test: not found"); n != 1 {
		t.Errorf("missing tool reported %d times, want 1:\n%s", n, out)
	}
	if len(r.pending.Verify) != 2 || r.pending.Verify[0].Cmd != "echo hello" || r.pending.Verify[0].Output != "hello\n" {
		t.Errorf("captured %+v, want echo hello twice", r.pending.Verify)
	}
}

// TestLookSystem: the real tools come from the system directories only, not
// from the PATH clifrd was started with.
func TestLookSystem(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "uptime")
	os.WriteFile(fake, []byte("#!/bin/sh\necho planted\n"), 0o755)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	p, err := lookSystem("uptime")
	if err != nil || p == fake || !strings.HasPrefix(p, "/") {
		t.Errorf("uptime: %q %v (planted %s)", p, err, fake)
	}
	if _, err := lookSystem("clifr-no-such-tool"); err == nil {
		t.Error("a missing tool was found")
	}
}

// TestMountViews: every command skipped in another mount namespace is one
// of the verify commands (a typo would compare the sandbox's mounts again).
func TestMountViews(t *testing.T) {
	cmds := map[string]bool{}
	for _, argv := range verifyCommands {
		cmds[strings.Join(argv, " ")] = true
	}
	for c := range mountViews {
		if !cmds[c] {
			t.Errorf("mountViews: %q is not a verify command", c)
		}
	}
}
