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
		os.Stdout.WriteString(splashScreen(150, 40, true, true, "0.2.0", "loading") + "\n")
		os.Stdout.WriteString(splashScreen(80, 24, true, false, "0.2.0", "loading") + "\n")
	}
	for _, wh := range [][2]int{{40, 8}, {80, 24}, {150, 40}} {
		s := splashScreen(wh[0], wh[1], true, false, "0.2.0", "loading x")
		flat := strings.ReplaceAll(s, " ", "") // a wide terminal spaces the tagline's letters
		if !strings.Contains(flat, "COMMANDLINEFLIGHTRECORDER") || !strings.Contains(s, "clifr 0.2.0") || !strings.Contains(s, "loading x") {
			t.Errorf("%dx%d: %q", wh[0], wh[1], s)
		}
		if n := strings.Count(s, "\r\n") + 1; n > wh[1] {
			t.Errorf("%dx%d: %d lines, higher than the terminal", wh[0], wh[1], n)
		}
	}
}
