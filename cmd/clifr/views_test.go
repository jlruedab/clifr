package main

import (
	"fmt"
	"testing"
)

type kv struct{ k, v string }

func TestCompare(t *testing.T) {
	v := view[kv]{key: func(r *kv) string { return r.k }, same: func(a, b *kv) bool { return a.v == b.v }}
	a := []kv{{"a", "1"}, {"b", "1"}, {"c", "1"}}
	b := []kv{{"b", "1"}, {"c", "2"}, {"d", "1"}}
	got := ""
	for _, x := range compare(v, a, b) {
		got += fmt.Sprintf("%s%s ", x.kind, x.row.k)
	}
	if got != "~c +d -a " {
		t.Errorf("got %q", got)
	}
	if len(compare(v, a, a)) != 0 {
		t.Error("changes between equal snapshots")
	}
}
