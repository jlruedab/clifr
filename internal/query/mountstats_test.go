package query

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// mountstatsRows turns a mountstats file into the rows clifrd records: the
// NFS sections only, each line trimmed, keyed "MOUNTPOINT N"
// (recorder.readMountstats).
func mountstatsRows(ts int64, text string) []store.SnapshotRow {
	var out []store.SnapshotRow
	mp, keep, i := "", false, 0
	for _, l := range strings.Split(text, "\n") {
		w := strings.Fields(l)
		if len(w) == 0 {
			continue
		}
		if w[0] == "device" && len(w) >= 8 {
			mp, i = w[4], 0
			keep = w[7] == "nfs" || w[7] == "nfs4"
		}
		if !keep {
			continue
		}
		out = append(out, store.SnapshotRow{TS: ts, Source: "mountstats", Key: mp + " " + strconv.Itoa(i), Pos: len(out),
			Full: true, Line: strings.TrimSpace(l)})
		i++
	}
	if len(out) == 0 {
		out = append(out, store.SnapshotRow{TS: ts, Source: "mountstats", Pos: -1, Full: true})
	}
	return out
}

type mountstatsCase struct {
	input, opts string
	rc          int
	stdout      string
}

// readMountstatsGolden reads a golden file: "=== INPUT NAME | OPTS ...",
// "--- rc N", "--- stdout", the output, "--- stderr", the errors.
func readMountstatsGolden(t *testing.T, path string) []mountstatsCase {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []mountstatsCase
	for _, part := range strings.Split(string(b), "=== INPUT ")[1:] {
		head, body, _ := strings.Cut(part, "\n")
		name, opts, _ := strings.Cut(head, " | OPTS")
		c := mountstatsCase{input: name, opts: strings.TrimSpace(opts)}
		rcLine, rest, _ := strings.Cut(body, "\n")
		c.rc, err = strconv.Atoi(strings.TrimPrefix(rcLine, "--- rc "))
		if err != nil {
			t.Fatalf("%s: %q", head, rcLine)
		}
		rest = strings.TrimPrefix(rest, "--- stdout\n")
		stdout, stderr, ok := strings.Cut(rest, "--- stderr\n")
		if !ok || stderr != "" {
			t.Fatalf("%s: no stderr marker or stderr not empty", head)
		}
		c.stdout = stdout
		out = append(out, c)
	}
	return out
}

func TestMountstatsGolden(t *testing.T) {
	dir := filepath.Join("testdata", "mountstats")
	dbs := map[string]*store.DB{}
	n := 0
	for _, g := range []struct {
		file string
		v233 bool
	}{{"golden-2.3.3.txt", true}, {"golden-2.5.4.txt", false}} {
		for _, c := range readMountstatsGolden(t, filepath.Join(dir, g.file)) {
			db := dbs[c.input]
			if db == nil {
				in, err := os.ReadFile(filepath.Join(dir, "input-"+c.input))
				if err != nil {
					t.Fatal(err)
				}
				db = testrec.Open(t, nil, &store.Batch{Sample: store.Sample{TS: 1000}, Snapshots: mountstatsRows(1000, string(in))})
				dbs[c.input] = db
			}
			mounts, err := MountstatsAt(db, 2000)
			if err != nil {
				t.Fatal(err)
			}
			o := MountstatsOptions{V233: g.v233}
			for _, a := range strings.Fields(c.opts) {
				switch a {
				case "-n":
					o.NFS = true
				case "-r":
					o.RPC = true
				case "-x":
					o.Xprt = true
				case "-R":
					o.Raw = true
				default:
					o.MountPoints = append(o.MountPoints, a)
				}
			}
			var b strings.Builder
			ok := PrintMountstats(&b, mounts, o)
			if got := b.String(); got != c.stdout || ok != (c.rc == 0) {
				t.Errorf("%s %s %q: ok %v, rc %d; got\n%s\nwant\n%s", g.file, c.input, c.opts, ok, c.rc, got, c.stdout)
				continue
			}
			n++
		}
	}
	if n != 108 {
		t.Errorf("%d golden cases passed, want 108", n)
	}
}

func TestMountstatsNotRecorded(t *testing.T) {
	db := testrec.Open(t, nil, &store.Batch{Sample: store.Sample{TS: 1000}})
	if _, err := MountstatsAt(db, 2000); err == nil || !strings.Contains(err.Error(), "not recorded") {
		t.Errorf("got %v, want not recorded", err)
	}
}

func TestMountAge(t *testing.T) {
	for s, want := range map[int64]string{0: "0:00:00", 59: "0:00:59", 36000: "10:00:00", 86461: "1 day, 0:01:01",
		266405: "3 days, 2:00:05"} {
		if got := mountAge(s); got != want {
			t.Errorf("%d: %q, want %q", s, got, want)
		}
	}
}
