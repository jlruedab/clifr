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
