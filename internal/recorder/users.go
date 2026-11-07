package recorder

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"clifr/internal/procfs"
)

// passwdPath is the file user names are read from (a var for tests).
var passwdPath = "/etc/passwd"

// readPasswd is the snapshots source "passwd": the host's uid -> name pairs,
// so that a recording read on another machine (clifr --host, a bundle, a
// sosreport) names its users as the host does (2026-11-08: clifr used the
// passwd of the machine it ran on). Only "uid name" per line, keyed by the
// uid: no home directory, shell or full name. The first entry of a uid wins,
// as getpwuid's. Users known only to NSS (LDAP, sssd) are not in it: clifrd
// is static Go without NSS, so those stay numbers.
func readPasswd() ([]procfs.SnapLine, error) {
	f, err := os.Open(passwdPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []procfs.SnapLine
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' || line[0] == '+' || line[0] == '-' { // NIS compat entries
			continue
		}
		fields := strings.SplitN(line, ":", 4)
		if len(fields) < 3 || fields[0] == "" {
			continue
		}
		uid := fields[2]
		if _, err := strconv.ParseUint(uid, 10, 32); err != nil || seen[uid] {
			continue
		}
		seen[uid] = true
		out = append(out, procfs.SnapLine{Key: uid, Line: uid + " " + fields[0]})
	}
	return out, sc.Err()
}
