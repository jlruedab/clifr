package main

import (
	"flag"
	"io"
	"os"
	"regexp"
	"slices"
	"testing"
)

// The bash completion lists every option and command clifr has (but the
// hidden --db), and nothing else.
func TestCompletion(t *testing.T) {
	b, err := os.ReadFile("../../packaging/completion/clifr.bash")
	if err != nil {
		t.Fatal(err)
	}
	words := func(name string) []string {
		m := regexp.MustCompile(`(?s)local ` + name + `="([^"]*)"`).FindSubmatch(b)
		if m == nil {
			t.Fatalf("no %s in the completion", name)
		}
		return regexp.MustCompile(`\S+`).FindAllString(string(m[1]), -1)
	}
	opts, cmds := words("opts"), words("cmds")
	var g globals
	var want []string
	newFlags(&g, io.Discard).VisitAll(func(f *flag.Flag) {
		if len(f.Name) == 1 {
			want = append(want, "-"+f.Name)
		} else {
			want = append(want, "--"+f.Name)
		}
	})
	slices.Sort(want)
	if got := slices.Sorted(slices.Values(opts)); !slices.Equal(got, want) {
		t.Errorf("options:\n got %v\nwant %v", got, want)
	}
	want = append([]string{}, toolOrder...)
	for s := range subcommands {
		if s != "stats" && s != "list" && s != "license" { // stats: info's old name; not in this release
			want = append(want, s)
		}
	}
	slices.Sort(want)
	if got := slices.Sorted(slices.Values(cmds)); !slices.Equal(got, want) {
		t.Errorf("commands:\n got %v\nwant %v", got, want)
	}
}
