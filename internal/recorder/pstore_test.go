package recorder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const panicText = `<6>[  101.000000] sysrq: Trigger a crash
<0>[  101.000100] Kernel panic - not syncing: sysrq triggered crash
<4>[  101.000200] CPU: 1 PID: 2412 Comm: bash Not tainted 5.14.0
<4>[  101.000300] RIP: 0010:sysrq_handle_crash+0x16/0x20
`

func writeAt(t *testing.T, path, text string, at time.Time) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o700)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(path, at, at)
}

// TestPstore: the records since the previous run started are read once (a
// copy systemd-pstore made is the same record), an older crash's copy is
// left out, a binary record is named but not stored, and the guard event
// quotes the panic line.
func TestPstore(t *testing.T) {
	root := t.TempDir()
	d := pstoreDirs{sys: filepath.Join(root, "sys"), systemd: filepath.Join(root, "systemd")}
	prevRun := time.Now().Add(-2 * time.Hour)
	crash := prevRun.Add(time.Hour)
	writeAt(t, filepath.Join(d.sys, "dmesg-efi-173100000001001"), panicText, crash)
	writeAt(t, filepath.Join(d.systemd, "173100000001", "dmesg.txt"), panicText, time.Now()) // the same, copied
	writeAt(t, filepath.Join(d.systemd, "172000000001", "dmesg.txt"), "<0>Kernel panic - not syncing: old\n", prevRun.Add(-time.Minute))
	writeAt(t, filepath.Join(d.sys, "dmesg-efi-173100000002001.enc.z"), "x\x00\x01compressed", crash)

	rows, g, ok := pstoreAtStart(d, "boot-A", prevRun.UnixMilli(), 0, time.Now())
	if !ok || g.Kind != "pstore" {
		t.Fatalf("no event: %v %+v", ok, g)
	}
	if len(rows) != 4 || rows[0].Kind != "pstore" || rows[0].BootID != "boot-A" || rows[1].Seq != 2 ||
		rows[1].Msg != "<0>[  101.000100] Kernel panic - not syncing: sysrq triggered crash" || rows[0].TS != crash.UnixMilli() {
		t.Errorf("rows %+v", rows)
	}
	for _, want := range []string{"2 files", "Kernel panic - not syncing: sysrq triggered crash", "not stored (binary, likely compressed): dmesg-efi-173100000002001.enc.z", "4 lines stored (clifr pstore)"} {
		if !strings.Contains(g.Detail, want) {
			t.Errorf("detail lacks %q: %s", want, g.Detail)
		}
	}
	if strings.Contains(g.Detail, ": old") {
		t.Errorf("an older crash's record came back: %s", g.Detail)
	}
	// Nothing new: no event.
	if _, g, ok := pstoreAtStart(d, "boot-A", time.Now().Add(time.Second).UnixMilli(), 0, time.Now()); ok {
		t.Errorf("an event without new records: %s", g.Detail)
	}
	// No pstore at all (directories missing).
	if _, _, ok := pstoreAtStart(pstoreDirs{sys: filepath.Join(root, "none")}, "", 0, time.Now().UnixMilli(), time.Now()); ok {
		t.Error("an event without pstore")
	}
}
