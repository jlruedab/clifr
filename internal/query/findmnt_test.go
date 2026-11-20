package query

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"clifr/internal/duck"
	"clifr/internal/pqstore"
	"clifr/internal/store"
	"clifr/internal/testrec"
)

// Mounts in mountinfo order as on the test machine: /run before /, a bind
// mount with a root, a stack of two mounts on one point, a read-only
// superblock, a network file system and a dummy one.
func mountDB(t *testing.T) *store.DB {
	t.Helper()
	base := int64(1_790_000_000_000)
	m := func(seq, id int, point, src, fstype, opts, super, root string) store.MountEvent {
		return store.MountEvent{TS: base, Action: "present", MountID: id, Point: point, Source: src, FSType: fstype,
			Options: opts, SuperOptions: super, Dev: "0:" + point, Root: root, Seq: seq}
	}
	fs := func(id int, blocks int64) store.FSSample {
		return store.FSSample{TS: base, MountID: id, FrSize: 4096, Blocks: blocks, BFree: blocks / 2, BAvail: blocks / 2, Files: 100, FFree: 50}
	}
	return testrec.Open(t, []string{"hostname", "web1.example.com"},
		&store.Batch{Sample: store.Sample{TS: base},
			Mounts: []store.MountEvent{
				m(1, 34, "/run", "tmpfs", "tmpfs", "rw,nosuid", "rw,size=10k", "/"),
				m(2, 45, "/", "/dev/sda1", "ext4", "rw,relatime", "rw", "/"),
				m(3, 47, "/sys", "sysfs", "sysfs", "rw", "rw", "/"),
				m(4, 29, "/run/cred", "none", "tmpfs", "rw,nosuid", "ro,size=1024k", "/"),
				m(5, 60, "/run/snapd/ns", "tmpfs", "tmpfs", "rw", "rw", "/snapd/ns"),
				m(6, 70, "/srv", "nas:/export", "nfs4", "rw", "rw,vers=4.2", "/"),
				m(7, 71, "/srv", "/dev/sdb1", "xfs", "rw", "rw", "/"),
			},
			FSSamples: []store.FSSample{fs(34, 100), fs(45, 1000), fs(29, 10), fs(60, 100), fs(70, 5000), fs(71, 2000)}})
}

func TestFindmnt(t *testing.T) {
	db := mountDB(t)
	rows, err := Findmnt(db, 1_790_000_000_000, false)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	PrintFindmnt(&sb, rows)
	want := "TARGET            SOURCE           FSTYPE OPTIONS\n" +
		"/                 /dev/sda1        ext4   rw,relatime\n" +
		"|-/run            tmpfs            tmpfs  rw,nosuid,size=10k\n" +
		"| |-/run/cred     none             tmpfs  ro,nosuid,size=1024k\n" +
		"| `-/run/snapd/ns tmpfs[/snapd/ns] tmpfs  rw\n" +
		"|-/sys            sysfs            sysfs  rw\n" +
		"`-/srv            nas:/export      nfs4   rw,vers=4.2\n" +
		"  `-/srv          /dev/sdb1        xfs    rw\n"
	if sb.String() != want {
		t.Errorf("got\n%s\nwant\n%s", sb.String(), want)
	}
	list, _ := Findmnt(db, 1_790_000_000_000, true)
	if list[0].Target != "/run" || list[0].tree != "" || list[0].Parent != 45 {
		t.Errorf("list: %+v", list[0])
	}

	all, _ := DF(db, 1_790_000_000_000, DFSelect{All: true})
	local, _ := DF(db, 1_790_000_000_000, DFSelect{All: true, Local: true, Exclude: []string{"tmpfs"}})
	only, _ := DF(db, 1_790_000_000_000, DFSelect{Only: []string{"xfs", "ext4"}})
	points := func(rows []DFRow) string {
		var p []string
		for _, r := range rows {
			p = append(p, r.Point)
		}
		return strings.Join(p, " ")
	}
	if got := points(all); got != "/run / /sys /run/cred /run/snapd/ns /srv /srv" {
		t.Errorf("df -a: %s", got)
	}
	if got := points(local); got != "/ /sys /srv" {
		t.Errorf("df -al -x tmpfs: %s", got)
	}
	if got := points(only); got != "/ /srv" {
		t.Errorf("df -t xfs -t ext4: %s", got)
	}
	// testrec stamps meta with the time it writes it (clifrd: its start).
	later := time.Now().Add(time.Hour).UnixMilli()
	if MetaAt(db, "hostname", later) != "web1.example.com" || MetaAt(db, "nothing", later) != "" {
		t.Error("MetaAt")
	}
}

// Retention removes a long run's oldest hours, its first meta and mount
// snapshot with them: the hourly copies stand in.
func TestMetaAndMountsAfterRetention(t *testing.T) {
	dir := t.TempDir()
	s, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Truncate(time.Second).UnixMilli() // the run's name
	time.Sleep(5 * time.Millisecond)
	s.SetMeta("os_id", "rhel")
	copyTS := time.Now().UnixMilli()
	m := func(ts int64, action string, id int, point string, seq int) store.MountEvent {
		return store.MountEvent{TS: ts, Action: action, MountID: id, Point: point, Source: "src", FSType: "ext4", Options: "rw", Seq: seq}
	}
	// The first snapshot expired; an hourly one at copyTS, with a mount at
	// the same moment that it does not hold yet.
	s.Write(&store.Batch{Sample: store.Sample{TS: copyTS}, Mounts: []store.MountEvent{
		m(copyTS, "mount", 9, "/srv", 2),
		m(copyTS, "present", 1, "/", 0), m(copyTS, "present", 2, "/home", 1)}})
	s.Close()
	db, err := duck.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if v := MetaAt(db, "os_id", start); v != "rhel" {
		t.Errorf("MetaAt before the run's first remaining copy: %q", v)
	}
	if v := MetaAt(db, "os_id", start-1000); v != "" {
		t.Errorf("MetaAt before the run: %q", v)
	}
	rows, err := MountsAt(db, copyTS)
	var points []string
	for _, r := range rows {
		points = append(points, r.Point)
	}
	if err != nil || strings.Join(points, " ") != "/ /home /srv" {
		t.Errorf("mounts %v %v", points, err)
	}
}

// Two clifrd runs in two boots: last reboot lists both, the newer still
// running, the older ending at its last sample.
func TestLastReboot(t *testing.T) {
	dir := t.TempDir()
	boot1 := time.Date(2026, 10, 19, 9, 0, 0, 0, time.Local).UnixMilli()
	boot2 := time.Date(2026, 10, 20, 10, 51, 30, 0, time.Local).UnixMilli()
	run := func(id string, boot int64, kernel string, samples ...int64) {
		s, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range map[string]string{"boot_id": id, "boot_ms": strconv.FormatInt(boot, 10), "uname_release": kernel} {
			s.SetMeta(k, v)
		}
		for _, ts := range samples {
			s.Write(&store.Batch{Sample: store.Sample{TS: ts}})
		}
		s.Close()
	}
	run("aaa", boot1, "5.14.0-427.13.1.el9_4.x86_64", boot1+20_000, boot1+90_061_000)
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second))) // runs are named by their start second
	run("bbb", boot2, "5.14.0-503.11.1.el9_5.x86_64", boot2+20_000)
	db, err := duck.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// testrec-style meta times are "now": ask about a moment after them.
	boots, err := Boots(db, time.Now().Add(time.Hour).UnixMilli())
	if err != nil || len(boots) != 2 || boots[0].LastMS != boot1+90_061_000 || boots[1].Kernel != "5.14.0-503.11.1.el9_5.x86_64" {
		t.Fatalf("boots %+v %v", boots, err)
	}
	var sb strings.Builder
	PrintLastReboot(&sb, boots, boot1+20_000, true)
	want := "reboot   system boot  5.14.0-503.11.1. Tue Oct 20 10:51:30 2026   still running\n" +
		"reboot   system boot  5.14.0-427.13.1. Mon Oct 19 09:00:00 2026 - Tue Oct 20 10:01:01 2026 (1+01:01)\n" +
		"\nwtmp begins Mon Oct 19 09:00:20 2026\n"
	if sb.String() != want {
		t.Errorf("got\n%s\nwant\n%s", sb.String(), want)
	}
	sb.Reset()
	PrintLastReboot(&sb, boots[:1], boot1, false)
	if !strings.HasPrefix(sb.String(), "reboot   system boot  5.14.0-427.13.1. Mon Oct 19 09:00   still running\n") {
		t.Errorf("short: %q", sb.String())
	}
}

// TestLastRebootCrash: a boot whose last clifrd run ended without a clean
// stop ends in "crash" with its length up to the last sample on disk.
// util-linux runs such a boot on to the next shutdown record instead (it
// prints "crash" only for the logins open then); clifr knows the crash and
// says it (the user's choice, 2026-11-20).
func TestLastRebootCrash(t *testing.T) {
	dir := t.TempDir()
	boot1 := time.Date(2026, 10, 19, 9, 0, 0, 0, time.Local).UnixMilli()
	boot2 := time.Date(2026, 10, 20, 10, 51, 30, 0, time.Local).UnixMilli()
	run := func(id string, boot int64, clean bool, samples ...int64) {
		s, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		s.SetMeta("boot_id", id)
		s.SetMeta("boot_ms", strconv.FormatInt(boot, 10))
		for _, ts := range samples {
			s.Write(&store.Batch{Sample: store.Sample{TS: ts}})
		}
		if clean {
			s.Close()
		} else {
			s.Flush() // the machine went down: no Close
		}
	}
	run("aaa", boot1, false, boot1+20_000, boot1+3_600_000)
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second))) // runs are named by their start second
	run("bbb", boot2, true, boot2+20_000)
	db, err := duck.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	boots, err := Boots(db, time.Now().Add(time.Hour).UnixMilli())
	if err != nil || len(boots) != 2 || !boots[0].Crashed || boots[1].Crashed {
		t.Fatalf("boots %+v %v", boots, err)
	}
	var sb strings.Builder
	PrintLastReboot(&sb, boots, boot1+20_000, false)
	if want := "reboot   system boot  -                Mon Oct 19 09:00 - crash  (01:00)\n"; !strings.Contains(sb.String(), want) {
		t.Errorf("got\n%s\nwant a line\n%s", sb.String(), want)
	}
}
