package query

import (
	"strings"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

func TestLocksAndIPCS(t *testing.T) {
	snap := func(src string, lines ...string) []store.SnapshotRow {
		var out []store.SnapshotRow
		for i, l := range lines {
			out = append(out, store.SnapshotRow{TS: 1000, Source: src, Key: strings.Fields(l)[0] + l, Pos: i, Full: true, Line: l})
		}
		return out
	}
	var rows []store.SnapshotRow
	rows = append(rows, snap("locks",
		"POSIX  ADVISORY  WRITE 4242 fd:00:131 0 EOF\t/var/lib/app/db\t5000\t\t",
		"OFDLCK ADVISORY  READ -1 fd:00:132 200 200\t/var/lib/images/a.img\t10485760\t77\tqemu-kvm",
		"FLOCK  ADVISORY  WRITE 999 fd:00:133 0 EOF\t\t\t\t")...)
	rows = append(rows, snap("sysvipc/shm",
		"       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap",
		"   4736938     131082  1600                  8192   100   200      2     0     0     0     0          0          0          0                  4096                     0")...)
	rows = append(rows, snap("sysvipc/sem", "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime",
		"         0          5   600          3     0     0     0     0          0          0")...)
	rows = append(rows, snap("sysvipc/msg", "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime")...)
	b := &store.Batch{Sample: store.Sample{TS: 1000}, Snapshots: rows,
		ProcInserts: []store.ProcRow{{ID: 1, PID: 4242, Comm: "app", FirstSeen: 1000}},
		ProcSamples: []store.ProcSample{{ProcID: 1, TS: 1000, State: "S"}},
		Mounts:      []store.MountEvent{{TS: 1000, Action: "present", MountID: 1, Point: "/var", Source: "/dev/dm-0", FSType: "xfs", Dev: "253:0", Seq: 1}}}
	db := testrec.Open(t, []string{"page_kb", "4"}, b)
	for _, c := range []struct {
		old  bool
		want string
	}{
		{false, "" +
			"COMMAND           PID   TYPE SIZE MODE  M START        END PATH\n" +
			"(unknown)         999  FLOCK      WRITE 0     0          0 /var...\n" +
			"qemu-kvm           77 OFDLCK  10M READ  0   200        200 /var/lib/images/a.img\n" +
			"app              4242  POSIX 4.9K WRITE 0     0          0 /var/lib/app/db\n"},
		{true, "" +
			"COMMAND           PID   TYPE SIZE MODE  M START        END PATH\n" +
			"(unknown)         999  FLOCK      WRITE 0     0          0 /var...\n" +
			"(undefined)        -1 OFDLCK      READ  0   200        200 /var...\n" +
			"app              4242  POSIX 4.9K WRITE 0     0          0 /var/lib/app/db\n"},
	} {
		locks, err := LocksAt(db, 1000, c.old)
		if err != nil {
			t.Fatal(err)
		}
		var sb strings.Builder
		PrintLslocks(&sb, locks, false, false, false)
		if sb.String() != c.want {
			t.Errorf("old %v: got\n%s\nwant\n%s", c.old, sb.String(), c.want)
		}
	}
	ipc, err := IPCAt(db, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	PrintIPCS(&sb, ipc, IPCSOptions{Shm: true, Sem: true})
	want := "\n------ Shared Memory Segments --------\n" +
		"key        shmid      owner      perms      bytes      nattch     status      \n" +
		"0x004847aa 131082     root       600        8192       2          dest         \n\n" +
		"------ Semaphore Arrays --------\n" +
		"key        semid      owner      perms      nsems     \n" +
		"0x00000000 5          root       600        3         \n\n"
	if sb.String() != want {
		t.Errorf("ipcs: got\n%q\nwant\n%q", sb.String(), want)
	}
	sb.Reset()
	PrintIPCS(&sb, ipc, IPCSOptions{Summary: true})
	want = "\n------ Messages Status --------\nallocated queues = 0\nused headers = 0\nused space = 0 bytes\n\n" +
		"------ Shared Memory Status --------\nsegments allocated 1\npages allocated 2\npages resident  1\npages swapped   0\n" +
		"Swap performance: 0 attempts\t 0 successes\n\n" +
		"------ Semaphore Status --------\nused arrays = 1\nallocated semaphores = 3\n\n"
	if sb.String() != want {
		t.Errorf("ipcs -u: got\n%q\nwant\n%q", sb.String(), want)
	}
}
