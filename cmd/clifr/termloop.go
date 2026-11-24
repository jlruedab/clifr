package main

import (
	"os"
	"os/signal"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// termLoop runs a full-screen view (the pager, clifr tui) on the alternate
// screen in raw mode: it draws, then waits for keys or a resize, until key
// says to quit. draw gets the terminal's size and returns the screen; key
// gets each key's name (keyName). The terminal is restored on return and on
// a signal's exit.
func termLoop(draw func(w, h int) string, key func(string) bool) error {
	out, in := int(os.Stdout.Fd()), int(os.Stdin.Fd())
	state, err := term.MakeRaw(in)
	if err != nil {
		return err
	}
	defer term.Restore(in, state)
	os.Stdout.WriteString("\x1b[?1049h\x1b[?25l") // alternate screen, no cursor
	defer os.Stdout.WriteString("\x1b[?25h\x1b[?1049l")
	setRestoreTerm(func() { // a signal's exit skips the deferred calls
		os.Stdout.WriteString("\x1b[?25h\x1b[?1049l")
		term.Restore(in, state)
	})
	defer setRestoreTerm(nil)
	// Keys come from a reader goroutine so that a resize (SIGWINCH) redraws
	// the screen while no key is pressed.
	keys := make(chan []byte)
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				close(keys)
				return
			}
			keys <- append([]byte(nil), buf[:n]...)
		}
	}()
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, unix.SIGWINCH)
	defer signal.Stop(winch)
	w, h := 80, 24
	for {
		if cw, ch, err := term.GetSize(out); err == nil {
			w, h = cw, ch
		}
		os.Stdout.WriteString("\x1b[H" + draw(w, h))
		select {
		case <-winch:
			os.Stdout.WriteString("\x1b[2J") // the old layout's leftovers
		case b, ok := <-keys:
			if !ok {
				return nil
			}
			for _, k := range splitKeys(b) {
				if key(keyName(k)) {
					return nil
				}
			}
		}
	}
}

// splitKeys splits one read into keys: several arrive together when a key
// is held or typed faster than a screen is drawn. An escape sequence is
// ESC [ parameters and a final byte, or ESC O and one byte; anything else
// is one character.
func splitKeys(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		n := 1
		switch {
		case b[0] == 0x1b && len(b) > 2 && b[1] == '[':
			n = 2
			for n < len(b) && (b[n] < 0x40 || b[n] > 0x7e) {
				n++
			}
			n = min(n+1, len(b))
		case b[0] == 0x1b && len(b) > 2 && b[1] == 'O':
			n = 3
		case b[0] >= 0x80:
			_, n = utf8.DecodeRune(b)
		}
		out = append(out, b[:n])
		b = b[n:]
	}
	return out
}
