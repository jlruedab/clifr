package recorder

import (
	"fmt"
	"regexp"
)

// mask replaces what a redaction pattern matched.
const mask = "***"

// Redactor masks secrets in command lines before they are stored. A pattern
// with capture groups masks only what the groups matched (the option name
// stays readable), one without masks the whole match.
type Redactor []*regexp.Regexp

// NewRedactor compiles the patterns.
func NewRedactor(patterns []string) (Redactor, error) {
	var r Redactor
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("redact %q: %w", p, err)
		}
		r = append(r, re)
	}
	return r, nil
}

// Text masks every match in s.
func (r Redactor) Text(s string) string {
	for _, re := range r {
		if re.NumSubexp() == 0 {
			s = re.ReplaceAllString(s, mask)
			continue
		}
		var out []byte
		last := 0
		for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
			for g := 1; g < len(m)/2; g++ {
				a, b := m[2*g], m[2*g+1]
				if a < last || a < 0 { // unmatched group, or inside an earlier one
					continue
				}
				out = append(append(out, s[last:a]...), mask...)
				last = b
			}
		}
		if out != nil {
			s = string(append(out, s[last:]...))
		}
	}
	return s
}

// Cmdline masks a command line and returns the length of argv[0] in the
// result. argv[0] and the arguments are masked apart, so the boundary stays
// where it was.
func (r Redactor) Cmdline(cmd string, argv0 int) (string, int) {
	if len(r) == 0 {
		return cmd, argv0
	}
	if argv0 <= 0 || argv0 > len(cmd) {
		return r.Text(cmd), 0
	}
	a := r.Text(cmd[:argv0])
	return a + r.Text(cmd[argv0:]), len(a)
}

// readCmdline is procfs ReadCmdline with the command line redacted.
func (r *Recorder) readCmdline(pid int) (string, int, error) {
	cmd, argv0, err := r.fs.ReadCmdline(pid)
	if err != nil {
		return cmd, argv0, err
	}
	cmd, argv0 = r.redact.Cmdline(cmd, argv0)
	return cmd, argv0, nil
}
