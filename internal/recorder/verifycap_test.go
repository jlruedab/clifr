package recorder

import (
	"bytes"
	"log"
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
