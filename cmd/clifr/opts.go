package main

import (
	"errors"
	"fmt"
	"strings"
)

// opt is one option a recorded command supports, in the real tool's syntax.
type opt struct {
	short byte   // letter after "-", or 0
	long  string // name after "--", or ""
	arg   string // name of its argument, "" for a switch
	help  string
}

func (o opt) key() string {
	if o.long != "" {
		return o.long
	}
	return string(o.short)
}

// parsed is a command line split by a tool's options.
type parsed struct {
	set map[string]string   // by opt.key(); "" for switches; the last value
	all map[string][]string // every value, in order (options given more than once)
	pos []string
}

func (p parsed) add(k, v string) {
	p.set[k] = v
	p.all[k] = append(p.all[k], v)
}

func (p parsed) has(k string) bool { _, ok := p.set[k]; return ok }

// parseOpts splits args like getopt: clustered switches ("-tanp"), an
// argument attached or separate ("-p1" or "-p 1"), "--long" and
// "--long=value", "--" ends options. Anything not in opts is rejected.
func parseOpts(tool string, opts []opt, args []string) (parsed, error) {
	p := parsed{set: map[string]string{}, all: map[string][]string{}}
	unsupported := func(o string) error {
		return fmt.Errorf("%s: option %s is not supported for recorded data (see: clifr help %s)", tool, o, tool)
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			p.pos = append(p.pos, args[i+1:]...)
			return p, nil
		case strings.HasPrefix(a, "--"):
			name, val, hasVal := strings.Cut(a[2:], "=")
			o, ok := findLong(opts, name)
			if !ok {
				return p, unsupported("--" + name)
			}
			switch {
			case o.arg == "" && hasVal:
				return p, fmt.Errorf("%s: --%s takes no argument", tool, name)
			case o.arg != "" && !hasVal:
				if i+1 == len(args) {
					return p, fmt.Errorf("%s: --%s needs %s", tool, name, o.arg)
				}
				i++
				val = args[i]
			}
			p.add(o.key(), val)
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				o, ok := findShort(opts, a[j])
				if !ok {
					return p, unsupported("-" + string(a[j]))
				}
				if o.arg == "" {
					p.add(o.key(), "")
					continue
				}
				val := a[j+1:]
				if val == "" {
					if i+1 == len(args) {
						return p, fmt.Errorf("%s: -%c needs %s", tool, a[j], o.arg)
					}
					i++
					val = args[i]
				}
				p.add(o.key(), val)
				break
			}
		default:
			p.pos = append(p.pos, a)
		}
	}
	return p, nil
}

func findLong(opts []opt, name string) (opt, bool) {
	for _, o := range opts {
		if o.long != "" && o.long == name {
			return o, true
		}
	}
	return opt{}, false
}

func findShort(opts []opt, c byte) (opt, bool) {
	for _, o := range opts {
		if o.short != 0 && o.short == c {
			return o, true
		}
	}
	return opt{}, false
}

// splitWords splits a quoted command like a POSIX shell would for plain
// words: whitespace separates, single quotes are literal, double quotes and
// backslashes escape. No variables, globs or substitutions.
func splitWords(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return nil, errors.New("unterminated ' in command")
			}
			cur.WriteString(s[i+1 : i+1+end])
			i += end + 1
			inWord = true
		case c == '"':
			i++
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && strings.IndexByte(`"\$`+"`", s[i+1]) >= 0 {
					i++
				}
				cur.WriteByte(s[i])
			}
			if i == len(s) {
				return nil, errors.New(`unterminated " in command`)
			}
			inWord = true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			inWord = true
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}
