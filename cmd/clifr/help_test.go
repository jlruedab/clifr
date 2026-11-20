package main

import (
	"sort"
	"strings"
	"testing"
)

// clifr help diff and diff's error name exactly the tools that take diff
// (diff: true); the page's per-command notes are checked by eye.
func TestDiffHelp(t *testing.T) {
	var names []string
	for _, tl := range tools {
		if tl.diff {
			names = append(names, tl.name)
		}
	}
	listed := strings.Split(diffCommands, ", ")
	sort.Strings(names)
	sort.Strings(listed)
	if strings.Join(names, ",") != strings.Join(listed, ",") {
		t.Errorf("diffCommands = %v; tools with diff: %v", listed, names)
	}
	if err := helpTool("diff"); err != nil {
		t.Errorf("help diff: %v", err)
	}
}

// TestMainHelpCommands: clifr --help's "Supported commands" names every
// command (who and w were missing from it once).
func TestMainHelpCommands(t *testing.T) {
	_, list, _ := strings.Cut(mainHelp, "Supported commands:")
	list, _, _ = strings.Cut(list, "Run \"clifr help COMMAND\"")
	listed := map[string]bool{}
	for _, f := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '(' }) {
		listed[f] = true
	}
	for name := range tools {
		if !listed[name] {
			t.Errorf("clifr --help does not list %q", name)
		}
	}
}
