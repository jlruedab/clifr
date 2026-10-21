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
		{"bash -c a\tb\\c\nd", 1, -1, `bash -c a\x09b\x5cc\x0ad`},
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
	PrintCgls(&b, procs, map[string]bool{"/user.slice/user-1000.slice/user@1000.service": true}, CglsOptions{ASCII: true, Columns: 80})
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
