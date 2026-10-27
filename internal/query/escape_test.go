package query

import "testing"

// The expected outputs are what the real tools printed for these names
// (procps-ng 4.0.4, psmisc 23.7, lsof 4.99.4) on 2026-10-27.
func TestToolEscapes(t *testing.T) {
	for _, c := range []struct {
		name string
		f    func(string) string
		in   string
		want string
	}{
		{"ps comm", procpsSafe, "\x1b[2J\x1b]0;PW\a", "?[2J?]0;PW?"},
		{"ps comm", procpsSafe, "a\tb\x7fcéd", "a?b?céd"},
		{"ps bad UTF-8", procpsSafe, "x\xffy", "x?y"},
		{"pstree", psmiscSafe, "\x1b[2J\x1b]0;PW\a", `\033[2J\033]0;PW\007`},
		{"pstree", psmiscSafe, "a\tb\x7fcéd", `a\011b\177c\303\251d`},
		{"lsof", LsofSafe, "n\ta\x7fb\ac\rd\be\ff\x01gh", `n\ta\x7fb^Gc\rd\be\ff^Agh`},
		{"lsof", LsofSafe, "evil\x1b[31mred\nline", `evil^[[31mred\nline`},
		{"lsof command", lsofCommand, "\x1b[2J\x1b]0;PW\a", `^[[2J^[]0`},
	} {
		if got := c.f(c.in); got != c.want {
			t.Errorf("%s %q: %q, want %q", c.name, c.in, got, c.want)
		}
	}
}
