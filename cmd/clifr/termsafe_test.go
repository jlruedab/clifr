package main

import (
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
