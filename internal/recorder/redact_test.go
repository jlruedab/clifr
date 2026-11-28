package recorder

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clifr/internal/duck"
)

func TestRedactor(t *testing.T) {
	r, err := NewRedactor([]string{`(?i)--?(?:password|token)[= ](\S+)`, `://[^/\s:@]+:([^@\s]+)@`, `hunter2`})
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"mysql --password=s3cr3t -h db":       "mysql --password=*** -h db",
		"app --TOKEN abc --token=def x":       "app --TOKEN *** --token=*** x",
		"curl https://bob:pa55@example.com/x": "curl https://bob:***@example.com/x",
		"echo hunter2 and hunter2":            "echo *** and ***",
		"nothing to see":                      "nothing to see",
	} {
		if got := r.Text(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if cmd, n := r.Cmdline("/bin/hunter2 --password=x", len("/bin/hunter2")); cmd != "/bin/*** --password=***" || n != len("/bin/***") {
		t.Errorf("argv[0] boundary: %q %d", cmd, n)
	}
	if _, err := NewRedactor([]string{"("}); err == nil {
		t.Error("bad pattern accepted")
	}
}

// clifr's own secrets are masked without any configured pattern.
func TestRedactBuiltin(t *testing.T) {
	key := "cs1-" + strings.Repeat("0a", 32)
	tok := "clifr_" + strings.Repeat("aZ9_-", 8) + "xyz"
	for _, r := range []Redactor{nil, mustRedactor(t, `hunter2`)} {
		for in, want := range map[string]string{
			"clifr verify --integrity --seal-key " + key:         "clifr verify --integrity --seal-key ***",
			"clifr --seal-key=" + key + " verify":                "clifr --seal-key=*** verify",
			"clifr --host db1 --token " + tok + " ps":            "clifr --host db1 --token *** ps",
			"cs1-" + strings.Repeat("0", 63):                     "cs1-" + strings.Repeat("0", 63), // too short
			"ls clifr_demo.mp4 clifr_" + strings.Repeat("x", 10): "ls clifr_demo.mp4 clifr_" + strings.Repeat("x", 10),
		} {
			if got := r.Text(in); got != want {
				t.Errorf("%q: %q, want %q", in, got, want)
			}
		}
		if cmd, n := r.Cmdline("clifr --token "+tok, len("clifr")); cmd != "clifr --token ***" || n != len("clifr") {
			t.Errorf("Cmdline: %q %d", cmd, n)
		}
	}
}

func mustRedactor(t *testing.T, p ...string) Redactor {
	r, err := NewRedactor(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A secret in a command line never reaches the database.
func TestRedactedCmdline(t *testing.T) {
	fp := newFakeProc(t)
	fp.set(50, "db", 100, 1)
	os.WriteFile(filepath.Join(fp.root, "50", "cmdline"), []byte("/bin/db\x00--password=s3cr3t\x00-v\x00"), 0o644)
	dataDir := t.TempDir()
	r, err := New(Config{DataDir: dataDir, Interval: time.Second, FDInterval: time.Minute, ProcRoot: fp.root,
		Redact: []string{`--password=(\S+)`}}, NewLogger(log.New(io.Discard, "", 0), LevelInfo))
	must(t, err)
	must(t, r.sample(time.Now(), true))
	must(t, r.shutdown())
	r.db.Close()
	db, err := duck.Open(dataDir)
	must(t, err)
	defer db.Close()
	var cmd string
	var argv0 int
	must(t, db.QueryRow(`SELECT cmdline, argv0_len FROM processes WHERE pid = 50`).Scan(&cmd, &argv0))
	if cmd != "/bin/db --password=*** -v" || argv0 != len("/bin/db") {
		t.Errorf("stored %q (argv[0] %d)", cmd, argv0)
	}
}
