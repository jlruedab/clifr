package main

import (
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// termUnsafe reports whether a character would make a terminal do more than
// show it: control characters other than newline and tab (an escape
// sequence can clear the screen, retitle the window or hide lines), C1
// controls and bytes that are not UTF-8 (0x9b is a CSI to some terminals),
// and the bidirectional overrides and isolates, which reorder what is shown.
// Process names, command lines, file names and labels are any user's to
// choose.
func termUnsafe(r rune, size int) bool {
	switch {
	case r == utf8.RuneError && size == 1:
		return true
	case r == '\n' || r == '\t':
		return false
	case r < 0x20 || r >= 0x7f && r <= 0x9f:
		return true
	case r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// termSafe replaces each such character with '?', as procps shows control
// characters in command lines.
func termSafe(s string) string {
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if termUnsafe(r, n) {
			var b strings.Builder
			b.WriteString(s[:i])
			for i < len(s) {
				r, n := utf8.DecodeRuneInString(s[i:])
				if termUnsafe(r, n) {
					b.WriteByte('?')
				} else {
					b.WriteString(s[i : i+n])
				}
				i += n
			}
			return b.String()
		}
		i += n
	}
	return s
}

// termWriter writes through termSafe. A character split between two writes
// is held until the rest of it arrives.
type termWriter struct {
	w    io.Writer
	rest []byte
}

func (t *termWriter) Write(b []byte) (int, error) {
	n := len(b)
	buf := append(t.rest, b...)
	cut := len(buf)
	for i := len(buf) - 1; i >= 0 && i >= len(buf)-utf8.UTFMax+1; i-- {
		if utf8.RuneStart(buf[i]) {
			if !utf8.FullRune(buf[i:]) {
				cut = i
			}
			break
		}
	}
	t.rest = append([]byte(nil), buf[cut:]...)
	_, err := io.WriteString(t.w, termSafe(string(buf[:cut])))
	return n, err
}

// Flush writes what is held (an incomplete character: '?').
func (t *termWriter) Flush() error {
	if len(t.rest) == 0 {
		return nil
	}
	_, err := io.WriteString(t.w, termSafe(string(t.rest)))
	t.rest = nil
	return err
}

// stdout is where output goes: os.Stdout, through a termWriter when it is a
// terminal (a pipe or a file gets the output as the real tools print it).
// Call done before returning.
func stdout() (w io.Writer, done func()) {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return os.Stdout, func() {}
	}
	t := &termWriter{w: os.Stdout}
	return t, func() { t.Flush() }
}
