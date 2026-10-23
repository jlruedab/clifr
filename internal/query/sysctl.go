package query

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"clifr/internal/store"
)

// SysctlLine is one line sysctl prints: a kernel parameter and one line of
// its value (a parameter whose file has several lines has several).
type SysctlLine struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SysctlAt returns sysctl -a's lines as clifrd last read /proc/sys at or
// before t (every minute), in sysctl's order.
func SysctlAt(db *store.DB, t int64) ([]SysctlLine, error) {
	lines, _, ok, err := FileAt(db, "sysctl", t)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("sysctl: not recorded at %s (recorded since schema 9)", FormatMS(t))
	}
	out := make([]SysctlLine, 0, len(lines))
	for _, l := range lines {
		name, value, _ := strings.Cut(l, " = ")
		out = append(out, SysctlLine{Name: name, Value: value})
	}
	return out, nil
}

// SysctlOptions: the parameters asked for (nil: -a), -n (values only), -N
// (names only), -r (names matching), -e (no error for unknown names).
type SysctlOptions struct {
	Keys          []string
	Values, Names bool
	Pattern       *regexp.Regexp
	IgnoreUnknown bool
}

// SelectSysctl keeps the lines asked for, in sysctl's order for -a and in
// the order of the keys given otherwise; a key that is a directory gives
// everything below it.
func SelectSysctl(all []SysctlLine, o SysctlOptions) ([]SysctlLine, error) {
	keep := func(l SysctlLine) bool { return o.Pattern == nil || o.Pattern.MatchString(l.Name) }
	if o.Keys == nil {
		var out []SysctlLine
		for _, l := range all {
			if keep(l) {
				out = append(out, l)
			}
		}
		return out, nil
	}
	var out []SysctlLine
	for _, k := range o.Keys {
		k = strings.Trim(k, ".")
		if strings.Contains(k, "/") && !strings.Contains(k, ".") {
			k = strings.ReplaceAll(k, "/", ".") // sysctl accepts net/ipv4/ip_forward
		}
		found := false
		for _, l := range all {
			if l.Name == k || strings.HasPrefix(l.Name, k+".") {
				found = true
				if keep(l) {
					out = append(out, l)
				}
			}
		}
		if !found && !o.IgnoreUnknown {
			return out, fmt.Errorf("sysctl: cannot stat /proc/sys/%s: No such file or directory", strings.ReplaceAll(k, ".", "/"))
		}
	}
	return out, nil
}

// PrintSysctl prints the lines as sysctl does.
func PrintSysctl(w io.Writer, lines []SysctlLine, o SysctlOptions) {
	last := ""
	for _, l := range lines {
		switch {
		case o.Names:
			if l.Name != last { // one name per parameter
				fmt.Fprintln(w, l.Name)
			}
		case o.Values:
			fmt.Fprintln(w, l.Value)
		default:
			fmt.Fprintf(w, "%s = %s\n", l.Name, l.Value)
		}
		last = l.Name
	}
}
