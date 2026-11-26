package main

import (
	"os"
	"strings"
	"testing"
)

// TestSplash: the logo fits the width asked for, is plain ASCII without
// colour, and a small terminal still gets the tagline and the status line.
func TestSplash(t *testing.T) {
	for _, cols := range []int{20, 76, 100} {
		art := splashArt(cols, false, false)
		if len(art) == 0 {
			t.Fatalf("%d columns: no logo", cols)
		}
		for _, l := range art {
			if len(l) > cols || strings.ContainsFunc(l, func(r rune) bool { return r > '~' || r < ' ' }) {
				t.Errorf("%d columns: line %q", cols, l)
			}
		}
		if want := int(float64(cols)*122/480/2 + 0.5); len(art) != want {
			t.Errorf("%d columns: %d lines, want %d", cols, len(art), want)
		}
	}
	if os.Getenv("SPLASH_SHOW") != "" {
		os.Stdout.WriteString(splashScreen(150, 40, true, true, "loading") + "\n")
		os.Stdout.WriteString(splashScreen(80, 24, true, false, "loading") + "\n")
	}
	s := splashScreen(40, 8, true, false, "loading x")
	if !strings.Contains(s, "COMMAND LINE FLIGHT RECORDER") || !strings.Contains(s, "loading x") {
		t.Errorf("40x8: %q", s)
	}
}
