package recorder

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"clifr/internal/procfs"
)

// passwdPath and groupPath are the files user and group names are read
// from (vars for tests).
var passwdPath, groupPath = "/etc/passwd", "/etc/group"

// readPasswd is the snapshots source "passwd": the host's uid -> name pairs,
// so that a recording read on another machine (clifr --host, a bundle, a
// sosreport) names its users as the host does (2026-11-08: clifr used the
// passwd of the machine it ran on). Only "uid name" per line, keyed by the
// uid: no home directory, shell or full name. The first entry of a uid wins,
// as getpwuid's. Users known only to NSS (LDAP, sssd) are not in it: clifrd
// is static Go without NSS, so those stay numbers.
func readPasswd() ([]procfs.SnapLine, error) { return readIDNames(passwdPath) }

// readGroup is the snapshots source "group" (schema 12, for atop -v's RGID):
// the host's gid -> name pairs, as "gid name", the first entry of a gid
// winning, as getgrgid's. Never the members or the password field.
func readGroup() ([]procfs.SnapLine, error) { return readIDNames(groupPath) }

// readIDNames reads the "name:x:id:..." lines of passwd or group.
func readIDNames(path string) ([]procfs.SnapLine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []procfs.SnapLine
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024) // group lines list members
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' || line[0] == '+' || line[0] == '-' { // NIS compat entries
			continue
		}
		fields := strings.SplitN(line, ":", 4)
		if len(fields) < 3 || fields[0] == "" {
			continue
		}
		id := fields[2]
		if _, err := strconv.ParseUint(id, 10, 32); err != nil || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, procfs.SnapLine{Key: id, Line: id + " " + fields[0]})
	}
	return out, sc.Err()
}
