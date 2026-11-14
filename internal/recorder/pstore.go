package recorder

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"clifr/internal/store"
)

// The kernel's crash records (pstore: a panic or oops message kept in
// reserved RAM or UEFI variables across the reboot) of the boot before this
// one, read at the first clifrd start of a boot: /sys/fs/pstore, and
// /var/lib/systemd/pstore, where systemd-pstore.service moves them early in
// the boot. Stored as kmsg rows of kind "pstore" under the crashed boot's id,
// with a "pstore" guard event that quotes the panic line.

type pstoreDirs struct{ sys, systemd string }

var defaultPstore = pstoreDirs{sys: "/sys/fs/pstore", systemd: "/var/lib/systemd/pstore"}

const (
	pstoreFileMax  = 1 << 20 // bytes read of one record
	pstoreTotalMax = 4 << 20 // of all records at one start
)

type pstoreFile struct {
	name    string // relative to its directory ("dmesg-efi-17312...", "17312.../dmesg.txt")
	mtimeMS int64
	text    string // "" for a binary (compressed) record
}

// readPstore lists the records modified at or after since (Unix ms), oldest
// first; a record in both places (copied by systemd-pstore) is read once.
func readPstore(d pstoreDirs, since int64) []pstoreFile {
	var out []pstoreFile
	seen := map[[32]byte]bool{}
	total := 0
	for _, root := range []string{d.sys, d.systemd} {
		if root == "" {
			continue
		}
		filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err != nil || !e.Type().IsRegular() {
				return nil
			}
			info, err := e.Info()
			if err != nil || info.ModTime().UnixMilli() < since || total >= pstoreTotalMax {
				return nil
			}
			f, err := os.Open(p)
			if err != nil {
				return nil
			}
			b, _ := io.ReadAll(io.LimitReader(f, pstoreFileMax))
			f.Close()
			sum := sha256.Sum256(b)
			if len(b) == 0 || seen[sum] {
				return nil
			}
			seen[sum] = true
			total += len(b)
			rel, _ := filepath.Rel(root, p)
			r := pstoreFile{name: rel, mtimeMS: info.ModTime().UnixMilli()}
			if !bytes.ContainsRune(b, 0) && utf8.Valid(b) {
				r.text = string(b)
			}
			out = append(out, r)
			return nil
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].mtimeMS != out[j].mtimeMS {
			return out[i].mtimeMS < out[j].mtimeMS
		}
		return out[i].name < out[j].name
	})
	return out
}

// panicRe finds the line that says why the kernel died, most telling first.
var panicRe = []*regexp.Regexp{
	regexp.MustCompile(`Kernel panic - not syncing:.*`),
	regexp.MustCompile(`(BUG: .*|Oops: .*|general protection fault.*|kernel BUG at .*|watchdog: .*lockup.*|Machine check.*|\[Hardware Error\].*|sysrq: Trigger a crash.*)`),
	regexp.MustCompile(`RIP: .*`),
}

// pstoreRecords turns the records into kmsg rows (bootID: the crashed boot)
// and one guard event at ts; ok = false when there are none.
func pstoreRecords(files []pstoreFile, bootID string, ts int64) ([]store.KmsgRow, store.GuardEvent, bool) {
	if len(files) == 0 {
		return nil, store.GuardEvent{}, false
	}
	var rows []store.KmsgRow
	var names, binary []string
	reason := ""
	seq := int64(0)
	for _, f := range files {
		names = append(names, f.name)
		if f.text == "" {
			binary = append(binary, f.name)
			continue
		}
		for _, line := range strings.Split(strings.TrimRight(f.text, "\n"), "\n") {
			seq++
			rows = append(rows, store.KmsgRow{TS: f.mtimeMS, BootID: bootID, Kind: "pstore", Seq: seq, Caller: f.name, Msg: line})
		}
	}
	for _, re := range panicRe {
		for _, r := range rows {
			if m := re.FindString(r.Msg); m != "" {
				reason = strings.TrimSpace(m)
				break
			}
		}
		if reason != "" {
			break
		}
	}
	d := fmt.Sprintf("kernel crash records of the previous boot (pstore, %d files: %s)", len(files), strings.Join(names, ", "))
	if reason != "" {
		d += ": " + reason
	}
	if len(binary) > 0 {
		d += fmt.Sprintf("; not stored (binary, likely compressed): %s", strings.Join(binary, ", "))
	}
	if len(rows) > 0 {
		d += fmt.Sprintf("; %d lines stored (clifr export kmsg, kind pstore)", len(rows))
	}
	return rows, store.GuardEvent{TS: ts, Kind: "pstore", Detail: d}, true
}

// pstoreAtStart reads the crash records at the first run of a boot: those
// written since the previous clifrd run started (the crash that ended its
// boot came later; a record systemd-pstore copied early in that boot, of an
// older crash, came before it), or since 10 minutes before this boot without
// a previous run.
func pstoreAtStart(d pstoreDirs, prevBootID string, prevRunMS, bootMS int64, now time.Time) ([]store.KmsgRow, store.GuardEvent, bool) {
	since := prevRunMS
	if since == 0 {
		since = bootMS - (10 * time.Minute).Milliseconds()
	}
	return pstoreRecords(readPstore(d, since), prevBootID, now.UnixMilli())
}
