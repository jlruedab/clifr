package query

import (
	"strings"
	"testing"
	"time"

	"clifr/internal/duck"
	"clifr/internal/pqstore"
	"clifr/internal/store"
)

// TestPstoreRecords: the pstore rows read back as one record per file and
// boot, lines in order, with the panic line found; a range keeps the records
// saved in it; dmesg's own records are not among them.
func TestPstoreRecords(t *testing.T) {
	dir := t.TempDir()
	s, err := pqstore.Open(dir, pqstore.Options{FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t1 := time.Date(2026, 11, 4, 20, 31, 0, 0, time.Local).UnixMilli()
	t2 := time.Date(2026, 11, 9, 8, 0, 0, 0, time.Local).UnixMilli()
	var rows []store.KmsgRow
	for i, l := range []string{"<6>[ 101.0] sysrq: Trigger a crash", "<0>[ 101.1] Kernel panic - not syncing: sysrq triggered crash", "<4>[ 101.2] RIP: 0010:x"} {
		rows = append(rows, store.KmsgRow{TS: t1, BootID: "aaaaaaaa-1111", Kind: "pstore", Seq: int64(i + 1), Caller: "dmesg-efi-1", Msg: l})
	}
	rows = append(rows, store.KmsgRow{TS: t2, BootID: "bbbbbbbb-2222", Kind: "pstore", Seq: 1, Caller: "1730000/dmesg.txt", Msg: "<1>BUG: unable to handle page fault"})
	rows = append(rows, store.KmsgRow{TS: t1, BootID: "aaaaaaaa-1111", Kind: "msg", Seq: 1, Msg: "an ordinary message"})
	s.Write(&store.Batch{Sample: store.Sample{TS: t2}, Kmsg: rows})
	s.Close()
	db, err := duck.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	recs, err := PstoreRecords(db, 0, 0)
	if err != nil || len(recs) != 2 {
		t.Fatalf("records %+v %v", recs, err)
	}
	if r := recs[0]; r.File != "dmesg-efi-1" || len(r.Lines) != 3 || r.Lines[1] != "<0>[ 101.1] Kernel panic - not syncing: sysrq triggered crash" ||
		r.Reason != "Kernel panic - not syncing: sysrq triggered crash" || r.SavedMS != t1 {
		t.Errorf("first %+v", r)
	}
	if recs[1].Reason != "BUG: unable to handle page fault" {
		t.Errorf("second reason %q", recs[1].Reason)
	}
	recs, _ = PstoreRecords(db, t2-1000, t2+1000)
	if len(recs) != 1 || recs[0].BootID != "bbbbbbbb-2222" {
		t.Errorf("range: %+v", recs)
	}
	var sb strings.Builder
	PrintPstore(&sb, recs)
	if !strings.HasPrefix(sb.String(), "== 1730000/dmesg.txt, boot bbbbbbbb, saved 2026-11-09 08:00:00: BUG: unable to handle page fault\n<1>BUG:") {
		t.Errorf("printed:\n%s", sb.String())
	}
}

// TestEFIPartsInOrder: the kernel numbers an EFI dump's parts from the end of
// the log, so part 1 (…01001) is listed last, also when the dump's time ticked
// between parts; other records keep their place.
func TestEFIPartsInOrder(t *testing.T) {
	var parts []PstoreRecord
	// One dump whose time ticked after part 2 (two directories), listed by name.
	for _, n := range []string{"1794899691/001/dmesg-efi_pstore-179489969101001", "1794899691/001/dmesg-efi_pstore-179489969102001",
		"1794899692/001/dmesg-efi_pstore-179489969204001", "1794899692/001/dmesg-efi_pstore-179489969203001", "1794899691/001/dmesg.txt"} {
		parts = append(parts, PstoreRecord{BootID: "c", File: n})
	}
	efiPartsInOrder(parts)
	var got []string
	for _, r := range parts {
		got = append(got, r.File[len(r.File)-5:])
	}
	if strings.Join(got, " ") != "04001 03001 02001 01001 g.txt" {
		t.Errorf("EFI parts in order %v", got)
	}
}
