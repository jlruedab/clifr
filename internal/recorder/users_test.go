package recorder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadPasswd(t *testing.T) {
	p := filepath.Join(t.TempDir(), "passwd")
	os.WriteFile(p, []byte("# comment\nroot:x:0:0:root:/root:/bin/bash\n_rpc:x:558:65534::/run/rpcbind:/usr/sbin/nologin\n"+
		"+nisuser::::::\nbad line\nalice:x:1000:1000:Alice Liddell,,,:/home/alice:/bin/zsh\ndup:x:1000:1000::/x:/y\n"), 0o644)
	old := passwdPath
	passwdPath = p
	defer func() { passwdPath = old }()
	lines, err := readPasswd()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range lines {
		got = append(got, l.Key+"="+l.Line)
	}
	if want := "0=0 root,558=558 _rpc,1000=1000 alice"; strings.Join(got, ",") != want {
		t.Errorf("got %v, want %s", got, want)
	}
	for _, l := range lines {
		if strings.Contains(l.Line, "/") || strings.Contains(l.Line, "Liddell") {
			t.Errorf("more than uid and name stored: %q", l.Line)
		}
	}
}

// TestReadGroup: "gid name" only, never the members.
func TestReadGroup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "group")
	os.WriteFile(p, []byte("root:x:0:\nadm:x:4:syslog,alice\nclifr:x:988:alice,bob\n+nis::::\nwheel:x:988:carol\n"), 0o644)
	old := groupPath
	groupPath = p
	defer func() { groupPath = old }()
	lines, err := readGroup()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range lines {
		got = append(got, l.Key+"="+l.Line)
	}
	if want := "0=0 root,4=4 adm,988=988 clifr"; strings.Join(got, ",") != want {
		t.Errorf("got %v, want %s", got, want)
	}
}
