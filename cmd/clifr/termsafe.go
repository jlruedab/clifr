package main

import (
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"

	"clifr/internal/query"
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

// outOverride, when set, takes the place of os.Stdout for stdout and
// dataOut: clifr tui renders a pane into a buffer.
var outOverride io.Writer

// stdout is where the text views go: os.Stdout through a termWriter, also
// into a pipe or a file (procps and lsof escape these characters always, and
// "clifr ... | grep x" hands its output to the terminal). Call done before
// returning.
func stdout() (w io.Writer, done func()) {
	if outOverride != nil {
		t := &termWriter{w: outOverride}
		return t, func() { t.Flush() }
	}
	t := &termWriter{w: os.Stdout}
	return t, func() { t.Flush() }
}

// dataOut is where data for programs goes (--json, export's CSV): filtered on
// a terminal, as it is into a pipe or file (JSON escapes control characters
// itself; a CSV export keeps the recorded bytes).
func dataOut() (w io.Writer, done func()) {
	if outOverride != nil {
		return stdout()
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return os.Stdout, func() {}
	}
	return stdout()
}

// lineSafe writes each message through termSafe: for stderr, whose headers,
// notes and errors quote recorded values (a host name, a file name). A nil w
// is os.Stderr as it is at the time of the write.
type lineSafe struct{ w io.Writer }

func (l lineSafe) Write(b []byte) (int, error) {
	w := l.w
	if w == nil {
		w = os.Stderr
	}
	if _, err := io.WriteString(w, termSafe(string(b))); err != nil {
		return 0, err
	}
	return len(b), nil
}

// stderr is os.Stderr through termSafe.
var stderr io.Writer = lineSafe{}

func init() { query.HeaderOut = stderr }
