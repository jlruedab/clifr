package query

import (
	"strings"
	"testing"
)

// TestLsnsTree: namespaces in inode order, each under the line of its
// process's parent (2.39+, with COMMAND); flat before 2.39 and without COMMAND.
func TestLsnsTree(t *testing.T) {
	p1 := &lsnsProc{pid: 1, cmd: "init", ns: map[string]uint32{"mnt": 10, "uts": 11}}
	p2 := &lsnsProc{pid: 50, ppid: 1, cmd: "daemon", ns: map[string]uint32{"mnt": 20, "uts": 11}}
	p3 := &lsnsProc{pid: 60, ppid: 50, cmd: "worker", ns: map[string]uint32{"mnt": 30, "uts": 11}}
	p4 := &lsnsProc{pid: 2, cmd: "kthreadd", ns: map[string]uint32{"mnt": 10, "uts": 11}}
	p5 := &lsnsProc{pid: 151, ppid: 2, cmd: "kdevtmpfs", ns: map[string]uint32{"mnt": 15, "uts": 11}}
	l := &Lsns{procs: []*lsnsProc{p1, p4, p2, p3, p5}}
	for _, p := range l.procs {
		for _, q := range l.procs {
			if q.pid == p.ppid {
				p.parent = q
			}
		}
	}
	lines := func(o LsnsOpts) []string {
		for _, p := range l.procs {
			p.outline = nil
		}
		_, rows := l.Rows(o)
		var out []string
		for _, r := range rows {
			out = append(out, r[0]+" "+r[len(r)-1])
		}
		return out
	}
	// 15 (kdevtmpfs) has no parent line: kthreadd shows no namespace.
	want := "10 init|11 init|20 `-daemon|30   `-worker|15 kdevtmpfs"
	if got := strings.Join(lines(LsnsOpts{ASCII: true}), "|"); got != want {
		t.Errorf("tree: %s\nwant %s", got, want)
	}
	if got := strings.Join(lines(LsnsOpts{Version: "2.37"}), "|"); got != "10 init|11 init|15 kdevtmpfs|20 daemon|30 worker" {
		t.Errorf("2.37: %s", got)
	}
	if got := strings.Join(lines(LsnsOpts{Cols: []string{"NS", "PID"}}), "|"); got != "10 1|11 1|15 151|20 50|30 60" {
		t.Errorf("without COMMAND: %s", got)
	}
}
