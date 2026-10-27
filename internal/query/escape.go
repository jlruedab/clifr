package query

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Each tool shows the characters of names (any user's to choose: process
// names, command lines, file names) that are not printable in its own way;
// these do it as the tool does. clifr's own output to a terminal also goes
// through cmd/clifr's termSafe, which covers the tools that print them as
// they are (ss, pidstat).

// procpsSafe is procps (ps, top): each control character and each byte that
// is not UTF-8 as '?'.
func procpsSafe(s string) string {
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r < 0x20 || r == 0x7f || r == utf8.RuneError && n == 1 {
			var b strings.Builder
			b.WriteString(s[:i])
			for i < len(s) {
				r, n := utf8.DecodeRuneInString(s[i:])
				if r < 0x20 || r == 0x7f || r == utf8.RuneError && n == 1 {
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

// psmiscSafe is psmisc's pstree: each byte below 0x20 or from 0x7f up as
// \ooo (UTF-8 too).
func psmiscSafe(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x7f {
			fmt.Fprintf(&b, "\\%03o", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// LsofSafe is lsof's safestrprt: \b \f \n \r \t, other control characters
// as ^X, DEL as \x7f. (lsof re-encodes bytes from 0x80 up in a way not
// copied here: they are left as they are.)
func LsofSafe(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20:
			b.WriteByte('^')
			b.WriteByte(c + '@')
		case c == 0x7f:
			b.WriteString(`\x7f`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// scolsEncode is libsmartcols' mbs_safe_encode, which it applies to every
// cell: each byte of a character that is not printable (glibc's iswprint:
// letters, marks, numbers, punctuation, symbols and spaces; here format
// characters such as a zero-width space are not) or not valid UTF-8
// as \xNN, and a backslash before an 'x' too (so the output cannot be
// mistaken for an escape). File and process names may hold any of them.
func scolsEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 || !unicode.IsGraphic(r) || r == '\\' && strings.HasPrefix(s[i+1:], "x") {
			for _, c := range []byte(s[i : i+n]) {
				fmt.Fprintf(&b, `\x%02x`, c)
			}
		} else {
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}
