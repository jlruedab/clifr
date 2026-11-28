package recorder

import (
	"fmt"
	"regexp"
	"strings"
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

// builtinSecrets are clifr's own secrets, masked whatever the configured
// patterns (none by default): a sealing verification key (clifr verify
// --seal-key cs1-...) recorded on the host it protects would let root forge
// every seal, and a --serve token (clifr --token clifr_...) would give the
// recording to whoever reads it.
var builtinSecrets = regexp.MustCompile(`\bcs1-[0-9a-fA-F]{64}|\bclifr_[A-Za-z0-9_-]{43}`)

func maskBuiltin(s string) string {
	if !strings.Contains(s, "cs1-") && !strings.Contains(s, "clifr_") {
		return s
	}
	return builtinSecrets.ReplaceAllString(s, mask)
}

// Text masks clifr's own secrets and every match of the patterns in s.
func (r Redactor) Text(s string) string {
	s = maskBuiltin(s)
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
	if argv0 <= 0 || argv0 > len(cmd) {
		return r.Text(cmd), 0
	}
	a := r.Text(cmd[:argv0])
	return a + r.Text(cmd[argv0:]), len(a)
}

// readCmdline is procfs ReadCmdline with the command line redacted.
func (r *Recorder) readCmdline(pid int) (string, int, error) {
	cmd, argv0, _, err := r.readCmdlinePad(pid)
	return cmd, argv0, err
}

// readCmdlinePad also returns the trailing NULs (procfs.ReadCmdlinePad).
// Command lines are cut at --max-cmdline (less while the memory guard
// sheds): any user can give processes megabytes of arguments, which would
// otherwise be kept in memory and rewritten at every flush.
func (r *Recorder) readCmdlinePad(pid int) (string, int, int, error) {
	cmd, argv0, pad, cut, err := r.fs.ReadCmdlinePad(pid, r.maxCmdline())
	if err != nil {
		return cmd, argv0, pad, err
	}
	if cut {
		r.cmdlineCut.Add(1)
	}
	cmd, argv0 = r.redact.Cmdline(cmd, argv0)
	return cmd, argv0, pad, nil
}
