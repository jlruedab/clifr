package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func TestTermSafe(t *testing.T) {
	for in, want := range map[string]string{
		"ps aux\tok\n":                 "ps aux\tok\n",
		"café 名前":                      "café 名前",
		"\x1b]0;owned\a[kworker]":      "?]0;owned?[kworker]",
		"a\rb\x7fc":                    "a?b?c",
		"\xc2\x9b2J \x9b2J":            "?2J ?2J",
		"file‮gnp.exe":            "file?gnp.exe",
		"⁦x⁩ ​zero-wid": "?x? ​zero-wid",
	} {
		if got := termSafe(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	// Split anywhere, the writer gives the same.
	in := "\x1b[2Jcafé 名前‮\n"
	for cut := 0; cut <= len(in); cut++ {
		var b strings.Builder
		w := &termWriter{w: &b}
		w.Write([]byte(in[:cut]))
		w.Write([]byte(in[cut:]))
		w.Flush()
		if b.String() != termSafe(in) {
			t.Errorf("cut %d: %q", cut, b.String())
		}
	}
}

// TestOutputFilteredInPipes: the text views and stderr are filtered also when
// they go to a pipe or file ("clifr ... | grep" reaches the terminal); data
// for programs (--json, export) keeps the recorded bytes there.
func TestOutputFilteredInPipes(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = saved }()
	evil := "c\x1b[2Jm\n"
	w, done := stdout()
	io.WriteString(w, evil)
	done()
	w, done = dataOut()
	io.WriteString(w, evil)
	done()
	var e strings.Builder
	fmt.Fprint(lineSafe{&e}, "# host: x\x1b]0;t\a\n")
	b, _ := os.ReadFile(f.Name())
	if string(b) != "c?[2Jm\n"+evil || e.String() != "# host: x?]0;t?\n" {
		t.Errorf("stdout+data %q, stderr %q", b, e.String())
	}
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{
		"=HYPERLINK(\"x\")": "'=HYPERLINK(\"x\")", "+1": "'+1", "-bash": "'-bash", "@SUM(A1)": "'@SUM(A1)",
		"\tx": "'\tx", "\rx": "'\rx", "/bin/sh -c x": "/bin/sh -c x", "": "", "a=b": "a=b",
	} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}
