package query

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// The events table: fixed columns, the command line or text last; SENT BY
// as wide as its widest value, or left out.
func TestPrintEvents(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.UTC
	life := int64(36_900)
	code := int64(0)
	evs := []Event{
		{TS: 1_790_000_000_000, Kind: "start", Exact: true, PID: 454399, PPID: 19790, User: "averylongname", Command: "bwrap --unshare-all"},
		{TS: 1_790_000_036_900, Kind: "exit", Exact: true, PID: 454399, PPID: 19790, User: "alice", Status: "SIGKILL",
			Signal: "SIGKILL", LifeMS: &life, SentBy: "19793 (gnome-terminal-, alice)", Command: "bwrap --unshare-all"},
		{TS: 1_790_000_040_000, Kind: "exit", PID: 7, PPID: 1, User: "root", Status: "0", ExitCode: &code, LifeMS: &life, Command: "sleep 30"},
		{TS: 1_790_000_050_000, Kind: "gap", Exact: true, Detail: "no samples for 52m2s, until 2026-09-21 15:45:00"},
	}
	var b bytes.Buffer
	PrintEvents(&b, evs)
	want := `TIME                     EVENT       PID    PPID USER     STATUS       LIFE SENT BY                        COMMAND / DETAIL
2026-09-21 14:13:20.000  start    454399   19790 averylo+                                                  bwrap --unshare-all
2026-09-21 14:13:56.900  exit     454399   19790 alice    SIGKILL     36.9s 19793 (gnome-terminal-, alice) bwrap --unshare-all
~2026-09-21 14:14:00.000 exit          7       1 root     0          >36.9s                                sleep 30
2026-09-21 14:14:10.000  gap           -       - -                                                         no samples for 52m2s, until 2026-09-21 15:45:00
`
	if got := strings.ReplaceAll(b.String(), " \n", "\n"); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	b.Reset()
	PrintEvents(&b, evs[3:])
	if l := strings.SplitN(b.String(), "\n", 2)[0]; strings.Contains(l, "SENT BY") {
		t.Errorf("no sender, yet a SENT BY column: %q", l)
	}
}

// events --signal: exits by a signal; a list by name or number.
func TestSignalFilter(t *testing.T) {
	kill := Event{Kind: "exit", Signal: "SIGKILL"}
	term := Event{Kind: "exit", Signal: "SIGTERM"}
	clean := Event{Kind: "exit", Status: "0"}
	start := Event{Kind: "start"}
	for spec, want := range map[string][4]bool{
		"":           {true, true, false, false},
		"KILL":       {true, false, false, false},
		"sigterm, 9": {true, true, false, false},
	} {
		f, err := SignalFilter(spec)
		if err != nil {
			t.Fatalf("%q: %v", spec, err)
		}
		if got := [4]bool{f(kill), f(term), f(clean), f(start)}; got != want {
			t.Errorf("%q: %v, want %v", spec, got, want)
		}
	}
	if _, err := SignalFilter("NOPE"); err == nil {
		t.Error("NOPE: no error")
	}
}
