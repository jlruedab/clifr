package query

import (
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

func TestStyle(t *testing.T) {
	for _, c := range []struct{ id, version, like, want string }{
		{"rocky", "8.10", "rhel centos fedora", "rhel-8"},
		{"almalinux", "9.8", "rhel centos fedora", "rhel-9"},
		{"rhel", "9.4", "fedora", "rhel-9"},
		{"centos", "7", "rhel fedora", ""}, // not in the table: current
		{"ubuntu", "22.04", "debian", "ubuntu-22.04"},
		{"ubuntu", "26.04", "debian", ""},
		{"", "", "", ""},
	} {
		if got := StyleName(c.id, c.version, c.like); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.id, c.version, got, c.want)
		}
	}
	for in, want := range map[string]string{
		"/run/x type=STREAM (CONNECTED)": "/run/x type=STREAM", "type=DGRAM (UNCONNECTED)": "type=DGRAM",
		"/run/dbus/system_bus_socket type=STREAM (LISTEN)": "/run/dbus/system_bus_socket type=STREAM",
		"/srv/odd (CONNECTED)":                             "/srv/odd (CONNECTED)", // a path, not lsof's state
	} {
		if got := unixState(in); got != want {
			t.Errorf("unixState(%q) = %q, want %q", in, got, want)
		}
	}

	// free on a recorded RHEL 8 host: used = total - free - buff/cache.
	base := int64(1_790_000_000_000)
	db := testrec.Open(t, []string{"os_id", "rocky", "os_version_id", "8.10", "os_id_like", "rhel centos fedora", "os_pretty_name", "Rocky Linux 8.10"},
		&store.Batch{Sample: store.Sample{TS: base}, Sys: []store.SysSample{{TS: base, UptimeMS: 1000,
			MemTotal: 8000, MemFree: 1000, MemAvailable: 6000, Buffers: 500, Cached: 2000, SReclaimable: 500}}})
	// testrec stamps meta when it writes it, after base: choose by override.
	StyleOverride = "rhel-8"
	defer func() { StyleOverride = "" }()
	rows, err := Free(db, []Span{{To: base}})
	if err != nil || rows[0].Used != 8000-1000-500-2500 {
		t.Errorf("free used (rhel-8): %+v %v", rows, err)
	}
	StyleOverride = "current"
	if rows, _ := Free(db, []Span{{To: base}}); rows[0].Used != 2000 {
		t.Errorf("free used (current): %d", rows[0].Used)
	}
}

// TestUname: uutils (Ubuntu 25.10 and later) prints "unknown" for -p and -i
// and leaves them out of -a; RHEL's and Debian's coreutils print the machine.
func TestUname(t *testing.T) {
	for _, c := range []struct {
		id, version string
		want        bool
	}{{"ubuntu", "26.04", true}, {"ubuntu", "25.10", true}, {"ubuntu", "25.04", false}, {"ubuntu", "24.04", false},
		{"debian", "13", false}, {"rhel", "9.6", false}, {"ubuntu", "", false}} {
		if got := uutils(c.id, c.version); got != c.want {
			t.Errorf("uutils(%q, %q) = %v", c.id, c.version, got)
		}
	}
	vals := map[string]string{"kernel-name": "Linux", "nodename": "h", "kernel-release": "7.0", "kernel-version": "#1 SMP",
		"machine": "x86_64", "processor": "unknown", "hardware-platform": "unknown", "operating-system": "GNU/Linux"}
	if got, want := UnameLine(vals, UnameKeys, true), "Linux h 7.0 #1 SMP x86_64 GNU/Linux"; got != want {
		t.Errorf("-a = %q, want %q", got, want)
	}
	if got := UnameLine(vals, []string{"processor"}, false); got != "unknown" {
		t.Errorf("-p = %q", got)
	}
	vals["processor"], vals["hardware-platform"] = "x86_64", "x86_64"
	if got, want := UnameLine(vals, UnameKeys, true), "Linux h 7.0 #1 SMP x86_64 x86_64 x86_64 GNU/Linux"; got != want {
		t.Errorf("-a = %q, want %q", got, want)
	}
}
