package query

import (
	"strings"
	"testing"
)

func TestCglsCommand(t *testing.T) {
	long := "/usr/bin/Xwayland :0 -rootless -noreset -accessx -core -auth /run/user/1000/.mutter"
	for _, c := range []struct {
		cmd  string
		pad  int
		room int
		want string
	}{
		{"/usr/libexec/glycin-loaders/2+/glycin-image-rs --dbus-fd 12", 1, 60, "/usr/libexec/glycin-loaders/2+/glycin-image-rs --dbus-fd 12"}, // 59 fits
		{"/usr/libexec/glycin-loaders/2+/glycin-image-rs --dbus-fd 120", 1, 60, "/usr/libexec/glycin-loaders/2+/glycin-image-rs --dbus-fd ..."},
		{long, 1, 60, long[:57] + "..."},
		{long, 1, -1, long},
		// postgres rewrote its arguments, padded with NULs: cut although
		// the text fits; -l strips the trailing space.
		{"postgres: 18/main: walwriter ", 93, 60, "postgres: 18/main: walwriter..."},
		{"postgres: 18/main: walwriter ", 93, -1, "postgres: 18/main: walwriter"},
		{"bash -c a\tb\\c\nd", 1, -1, `bash -c a\x09b\c\x0ad`},
	} {
		if got := cglsCommand(CglsProc{Command: c.cmd, pad: c.pad}, c.room, true); got != c.want {
			t.Errorf("%q pad %d room %d: %q, want %q", c.cmd, c.pad, c.room, got, c.want)
		}
	}
}

func TestKernfsHashOrder(t *testing.T) {
	// The order /sys/fs/cgroup listed these in on Linux 7.0 (amd64).
	want := []string{"org.gnome.Shell@ubuntu.service", "gvfs-goa-volume-monitor.service",
		"org.gnome.SettingsDaemon.MediaKeys.service", "org.gnome.SettingsDaemon.Smartcard.service",
		"xdg-permission-store.service", "org.gnome.SettingsDaemon.Datetime.service"}
	for i := 1; i < len(want); i++ {
		if kernfsHash(want[i-1]) >= kernfsHash(want[i]) {
			t.Errorf("%s before %s: hashes %d, %d", want[i-1], want[i], kernfsHash(want[i-1]), kernfsHash(want[i]))
		}
	}
}

func TestPrintCgls(t *testing.T) {
	procs := []CglsProc{
		{PID: 1, Cgroup: "/init.scope", Command: "/sbin/init", pad: 1},
		{PID: 812, Cgroup: "/system.slice/ssh.service", Command: "sshd: /usr/sbin/sshd -D", pad: 1},
		{PID: 2, Cgroup: "/", Command: "[kthreadd]", Kernel: true, pad: 1},
		{PID: 4000, Cgroup: "/user.slice/user-1000.slice/user@1000.service/init.scope", Command: "/lib/systemd/systemd --user", pad: 1},
		{PID: 99, Cgroup: "/system.slice/ssh.service", Command: "sshd", pad: 1},
	}
	var b strings.Builder
	PrintCgls(&b, procs, map[string]CgroupInfo{"/user.slice/user-1000.slice/user@1000.service": {Delegate: true}}, CglsOptions{ASCII: true, Columns: 80})
	got := b.String()
	for _, l := range []string{"CGroup /:\n-.slice\n", "user@1000.service ...\n", "    |- 99 sshd\n", "    `-812 sshd: /usr/sbin/sshd -D\n"} {
		if !strings.Contains(got, l) {
			t.Errorf("no %q in:\n%s", l, got)
		}
	}
	if strings.Contains(got, "kthreadd") {
		t.Errorf("kernel thread without -k:\n%s", got)
	}
}

func TestPrintCglsStyles(t *testing.T) {
	procs := []CglsProc{{PID: 736, Cgroup: "/user.slice/user-1000.slice/user@1000.service/init.scope", Command: "/lib/systemd/systemd --user", pad: 1}}
	info := map[string]CgroupInfo{
		"/user.slice": {ID: 1396, Xattrs: "user.invocation_id=409e\ntrusted.invocation_id=40\\0759e\n"}, // stored escaped: '='
		"/user.slice/user-1000.slice/user@1000.service": {Delegate: true, ID: 5432},
	}
	for style, want := range map[string]string{
		"239": "Control group /:\n-.slice\n`-user.slice\n  `-user-1000.slice\n    `-user@1000.service\n",
		"249": "Control group /:\n-.slice\n`-user.slice \n  `-user-1000.slice \n    `-user@1000.service ...\n",
		"252": "Control group /:\n-.slice\n`-user.slice (#1396)\n  -> user.invocation_id: 409e\n  -> trusted.invocation_id: 40=9e\n" +
			"  `-user-1000.slice\n    `-user@1000.service ... (#5432)\n",
		"": "CGroup /:\n-.slice\n`-user.slice\n  `-user-1000.slice\n    `-user@1000.service ...\n",
	} {
		var b strings.Builder
		PrintCgls(&b, procs, info, CglsOptions{ASCII: true, Columns: 80, Style: style})
		if !strings.HasPrefix(b.String(), want) {
			t.Errorf("style %q:\n%s\nwant prefix:\n%s", style, b.String(), want)
		}
	}
}

func TestCglsCommand239(t *testing.T) {
	for _, c := range []struct {
		cmd  string
		room int
		want string
	}{
		{"/usr/sbin/rngd -f --fill-watermark=0 -x pkcs11 -x nist -x qrypt -D jitter", 70, "/usr/sbin/rngd -f --fill-watermark=0 -x pkcs11 -x nist -x qrypt -D..."},
		{"sshd: tester [priv]", 60, "sshd: tester [priv]"},
		{"/sbin/agetty -o -p -- \\u --noclear tty1 linux", -1, "/sbin/agetty -o -p -- \\u --noclear tty1 linux"},
		{"bash -c echo a;\n\t\tsudo b\n", -1, "bash -c echo a; sudo b"},
	} {
		if got := cglsCommand239(c.cmd, c.room); got != c.want {
			t.Errorf("%q room %d: %q, want %q", c.cmd, c.room, got, c.want)
		}
	}
}

func TestInCgroupProcs(t *testing.T) {
	for _, c := range []struct {
		state   string
		threads int64
		want    bool
	}{
		{"S", 1, true},
		{"R", 4, true},
		{"Z", 1, false}, // exited, not reaped: gone from cgroup.procs
		{"Z", 0, false},
		{"Z", 3, true}, // leader exited, other threads still running
	} {
		if got := inCgroupProcs(c.state, c.threads); got != c.want {
			t.Errorf("state %s threads %d: %v, want %v", c.state, c.threads, got, c.want)
		}
	}
}

// TestDeriveTrusted: under the unit clifrd records only the user.* copies of
// systemd's mirrored attributes; the trusted.* copies are added back after
// them, except below a delegated cgroup, and only when no trusted.* name was
// recorded anywhere.
func TestDeriveTrusted(t *testing.T) {
	unreadable := func() map[string]CgroupInfo {
		return map[string]CgroupInfo{
			"/":             {},
			"/system.slice": {Xattrs: "user.invocation_id=aa\n"},
			"/system.slice/d.service": {Delegate: true,
				Xattrs: "user.invocation_id=bb\nuser.delegate=1\n"},
			"/system.slice/d.service/payload": {Xattrs: "user.invocation_id=cc\n"}, // set by the delegate
			"/user.slice/user-1000.slice/user@1000.service": {Delegate: true,
				Xattrs: "user.invocation_id=dd\nuser.delegate=1\n"},
			"/user.slice/user-1000.slice/user@1000.service/app.slice": {Xattrs: "user.xdg.inactive-since=5\n"},
		}
	}
	info := unreadable()
	deriveTrusted(info)
	want := map[string]string{
		"/system.slice":                                           "user.invocation_id=aa\ntrusted.invocation_id=aa\n",
		"/system.slice/d.service":                                 "user.invocation_id=bb\nuser.delegate=1\ntrusted.invocation_id=bb\ntrusted.delegate=1\n",
		"/system.slice/d.service/payload":                         "user.invocation_id=cc\n",
		"/user.slice/user-1000.slice/user@1000.service":           "user.invocation_id=dd\nuser.delegate=1\ntrusted.invocation_id=dd\ntrusted.delegate=1\n",
		"/user.slice/user-1000.slice/user@1000.service/app.slice": "user.xdg.inactive-since=5\n",
	}
	for p, x := range want {
		if info[p].Xattrs != x {
			t.Errorf("%s: %q, want %q", p, info[p].Xattrs, x)
		}
	}
	if !TrustedDerived(info) || info["/system.slice/d.service/payload"].TrustedDerived {
		t.Errorf("TrustedDerived flags wrong: %+v", info)
	}

	// Recorded with CAP_SYS_ADMIN: trusted.* names present, nothing added.
	info = unreadable()
	ci := info["/system.slice"]
	ci.Xattrs = "user.invocation_id=aa\ntrusted.invocation_id=aa\n"
	info["/system.slice"] = ci
	deriveTrusted(info)
	if TrustedDerived(info) || info["/system.slice/d.service"].Xattrs != "user.invocation_id=bb\nuser.delegate=1\n" {
		t.Errorf("readable recording changed: %+v", info)
	}

	// No user.* copies (systemd before 248): nothing to derive.
	info = map[string]CgroupInfo{"/system.slice/x.service": {Xattrs: "user.delegate=1\n"}}
	deriveTrusted(info)
	if TrustedDerived(info) {
		t.Errorf("derived without systemd's user.invocation_id: %+v", info)
	}
}
