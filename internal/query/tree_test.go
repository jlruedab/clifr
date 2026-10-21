package query

import (
	"strings"
	"testing"
)

// A small machine: kthreadd with two workers, systemd with a few services,
// a three-level chain and a shell session; the expected text is laid out as
// pstree -lpT and ps auxf print it (taken from the real tools' output).
func treeRows() []PSRow {
	p := func(pid, ppid int, comm string) PSRow {
		return PSRow{PID: pid, PPID: ppid, CommName: comm, Command: comm}
	}
	return []PSRow{
		p(1, 0, "systemd"), p(2, 0, "kthreadd"), p(3, 2, "kworker/0:0"), p(4, 2, "rcu_gp"),
		p(2938, 1, "ModemManager"), p(2870, 1, "NetworkManager"), p(2502, 1, "avahi-daemon"), p(2754, 2502, "avahi-daemon"),
		p(2505, 1, "chronyd-starter"), p(2822, 2505, "chronyd"), p(2831, 2822, "chronyd"),
		p(3143, 1, "postgres"), p(3181, 3143, "postgres"), p(3180, 3143, "postgres"),
		p(500, 1, "sshd"), p(600, 500, "sshd"), p(601, 600, "bash"), p(602, 601, "vim"), p(700, 500, "sshd"),
	}
}

func TestPstree(t *testing.T) {
	lines, ok := Pstree(treeRows(), PstreeFormat{Root: 1, Long: true})
	want := `systemd(1)-+-ModemManager(2938)
           |-NetworkManager(2870)
           |-avahi-daemon(2502)---avahi-daemon(2754)
           |-chronyd-starter(2505)---chronyd(2822)---chronyd(2831)
           |-postgres(3143)-+-postgres(3180)
           |                ` + "`" + `-postgres(3181)
           ` + "`" + `-sshd(500)-+-sshd(600)---bash(601)---vim(602)
                       ` + "`" + `-sshd(700)`
	if got := strings.Join(lines, "\n"); !ok || got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	lines, _ = Pstree(treeRows(), PstreeFormat{Root: 500, Unicode: true})
	want = "sshd(500)─┬─sshd(600)───bash(601)───vim(602)\n          └─sshd(700)"
	if got := strings.Join(lines, "\n"); got != want {
		t.Errorf("unicode: got\n%s\nwant\n%s", got, want)
	}
	if _, ok := Pstree(treeRows(), PstreeFormat{Root: 99}); ok {
		t.Error("a missing root was found")
	}
	long := []PSRow{{PID: 1, CommName: "systemd"}, {PID: 2, PPID: 1, CommName: strings.Repeat("x", 15)}}
	for i := 3; i < 20; i++ {
		long = append(long, PSRow{PID: i, PPID: i - 1, CommName: strings.Repeat("x", 15)})
	}
	if lines, _ := Pstree(long, PstreeFormat{Root: 1}); len(lines[0]) != 132 || !strings.HasSuffix(lines[0], "+") {
		t.Errorf("cut line: %d %q", len(lines[0]), lines[0])
	}
}

func TestPSForest(t *testing.T) {
	var got []string
	for _, r := range PSForest(treeRows()) {
		got = append(got, r.forest+r.Command)
	}
	want := []string{"kthreadd", ` \_ kworker/0:0`, ` \_ rcu_gp`, "systemd",
		"sshd", ` \_ sshd`, ` |   \_ bash`, ` |       \_ vim`, ` \_ sshd`,
		"avahi-daemon", ` \_ avahi-daemon`, "chronyd-starter", ` \_ chronyd`, `     \_ chronyd`,
		"NetworkManager", "ModemManager", "postgres", ` \_ postgres`, ` \_ postgres`}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
