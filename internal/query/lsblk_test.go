package query

import (
	"strings"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

func TestLsblk(t *testing.T) {
	devs := []store.BlockDevRow{
		{Name: "nvme0n1", Maj: 259, Min: 0, Size: 1024209543168, RO: 0, RM: 0, SCSIType: -1},
		{Name: "nvme0n1p1", Parent: "nvme0n1", Maj: 259, Min: 1, Size: 1127219200, RM: -1, SCSIType: -1,
			FSType: "vfat", FSVer: "FAT32", UUID: "13AD-6D5A"},
		{Name: "nvme0n1p3", Parent: "nvme0n1", Maj: 259, Min: 3, Size: 1020932390912, RM: -1, SCSIType: -1, Holders: "dm-0",
			FSType: "LVM2_member", FSVer: "LVM2 001", UUID: "hAkhp8"},
		{Name: "dm-0", Maj: 252, Min: 0, Size: 1020931342336, RM: 0, SCSIType: -1, DMName: "vg-root", DMUUID: "LVM-XQRw",
			Slaves: "nvme0n1p3", FSType: "ext4", FSVer: "1.0", Label: `my\x20root`, UUID: "ca58"},
		{Name: "loop0", Maj: 7, Min: 0, RO: 0, RM: 0, SCSIType: -1},                                                      // unused: left out
		{Name: "loop1", Maj: 7, Min: 1, Size: 4096, RO: 1, RM: 0, SCSIType: -1, LoopFile: "/x.snap", FSType: "squashfs"}, // mounted twice
		{Name: "ram0", Maj: 1, Min: 0, Size: 4194304, SCSIType: -1},                                                      // left out
		{Name: "sr0", Maj: 11, Min: 0, Size: 1073741312, RM: 1, SCSIType: 5},
	}
	for i := range devs {
		devs[i].TS = 1000
	}
	mounts := []store.MountEvent{
		{TS: 1000, Action: "present", MountID: 1, Point: "/", Source: "/dev/mapper/vg-root", FSType: "ext4", Dev: "252:0", Root: "/", Seq: 1},
		{TS: 1000, Action: "present", MountID: 2, Point: "/boot/efi", Source: "/dev/nvme0n1p1", FSType: "vfat", Dev: "259:1", Root: "/", Seq: 2},
		{TS: 1000, Action: "present", MountID: 3, Point: "/snap/x/1", Source: "/dev/loop1", FSType: "squashfs", Dev: "7:1", Root: "/", Seq: 3},
		{TS: 1000, Action: "present", MountID: 4, Point: "/snap/x/2", Source: "/dev/loop1", FSType: "squashfs", Dev: "7:1", Root: "/", Seq: 4},
	}
	fs := []store.FSSample{
		{TS: 1000, MountID: 1, FrSize: 4096, Blocks: 1000, BFree: 460, BAvail: 400},
		{TS: 1000, MountID: 2, FrSize: 4096, Blocks: 1000, BFree: 970, BAvail: 970},
		{TS: 1000, MountID: 4, FrSize: 4096, Blocks: 1, BFree: 0, BAvail: 0},
	}
	db := testrec.Open(t, nil, &store.Batch{Sample: store.Sample{TS: 1000}, BlockDevs: devs, Mounts: mounts, FSSamples: fs})
	roots, err := LsblkAt(db, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		o    LsblkOptions
		want string
	}{
		{LsblkOptions{ASCII: true}, "" +
			"NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS\n" +
			"loop1         7:1    0     4K  1 loop /snap/x/2\n" +
			"                                      /snap/x/1\n" +
			"sr0          11:0    1  1024M  0 rom  \n" +
			"nvme0n1     259:0    0 953.9G  0 disk \n" +
			"|-nvme0n1p1 259:1    0     1G  0 part /boot/efi\n" +
			"`-nvme0n1p3 259:3    0 950.8G  0 part \n" +
			"  `-vg-root 252:0    0 950.8G  0 lvm  /\n"},
		{LsblkOptions{ASCII: true, V232: true}, "" +
			"NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT\n" +
			"loop1         7:1    0     4K  1 loop /snap/x/2\n" +
			"sr0          11:0    1  1024M  0 rom  \n" +
			"nvme0n1     259:0    0 953.9G  0 disk \n" +
			"|-nvme0n1p1 259:1    0     1G  0 part /boot/efi\n" +
			"`-nvme0n1p3 259:3    0 950.8G  0 part \n" +
			"  `-vg-root 252:0    0 950.8G  0 lvm  /\n"},
		{LsblkOptions{FS: true}, "" +
			"NAME        FSTYPE      FSVER    LABEL   UUID                                 FSAVAIL FSUSE% MOUNTPOINTS\n" +
			"loop1       squashfs                                                                0   100% /snap/x/2\n" +
			"                                                                                             /snap/x/1\n" +
			"sr0                                                                                          \n" +
			"nvme0n1                                                                                      \n" +
			"├─nvme0n1p1 vfat        FAT32            13AD-6D5A                               3.8M     3% /boot/efi\n" +
			"└─nvme0n1p3 LVM2_member LVM2 001         hAkhp8                                              \n" +
			"  └─vg-root ext4        1.0      my root ca58                                    1.6M    54% /\n"},
	} {
		var b strings.Builder
		PrintLsblk(&b, roots, c.o)
		if b.String() != c.want {
			t.Errorf("%+v: got\n%s\nwant\n%s", c.o, b.String(), c.want)
		}
	}
}

func TestMakedev(t *testing.T) {
	// glibc: a minor number above 255 sorts after the next major number.
	if !(makedev(7, 255) < makedev(8, 0) && makedev(8, 0) < makedev(7, 256)) {
		t.Errorf("makedev order: %x %x %x", makedev(7, 255), makedev(8, 0), makedev(7, 256))
	}
}
