package query

import (
	"strings"
	"testing"
	"time"

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
