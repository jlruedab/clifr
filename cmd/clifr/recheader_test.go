package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// captureErr runs clifr with args and returns its standard error (the
// "# ..." header lines).
func captureErr(t *testing.T, args ...string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	_, _ = capture(t, args...)
	w.Close()
	os.Stderr = old
	return <-done
}

// Local queries name the recorded host; a range that ends after the
// recording does is flagged (the test recording's samples: at-65s, at-35s).
func TestRecordingHeaders(t *testing.T) {
	dir, at := testRecording(t)
	f := func(t time.Time) string { return t.Format("2006-01-02 15:04:05") }
	e := captureErr(t, "--data-dir", dir, "--plain", "--at", f(at), "ps aux")
	if !strings.Contains(e, "# host: web01 (machine-id 01234567)") {
		t.Errorf("no host line:\n%s", e)
	}
	if strings.Contains(e, "warning:") {
		t.Errorf("a moment within the recording warned:\n%s", e)
	}
	e = captureErr(t, "--data-dir", dir, "--plain", "--since", f(at.Add(-2*time.Minute)), "--until", f(at.Add(10*time.Minute)), "ps aux")
	if !strings.Contains(e, "# warning: the recording ends at") {
		t.Errorf("a range past the end did not warn:\n%s", e)
	}
	e = captureErr(t, "--data-dir", dir, "--plain", "--since", f(at.Add(-2*time.Minute)), "--until", f(at), "ps aux")
	if strings.Contains(e, "warning:") {
		t.Errorf("a range ending within a sample interval of the end warned:\n%s", e)
	}
}
