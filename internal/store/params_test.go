package store

import (
	"fmt"
	"testing"
)

func TestPositional(t *testing.T) {
	q, a := positional(`a = ?1 AND b <= ?3 AND c = ?1 AND d = ?4`, []any{"s", "sfd", "end", 7})
	if q != `a = ? AND b <= ? AND c = ? AND d = ?` || fmt.Sprint(a) != "[s end s 7]" {
		t.Errorf("got %q %v", q, a)
	}
	if q, a := positional(`x = ?`, []any{1}); q != `x = ?` || len(a) != 1 {
		t.Errorf("plain ? changed: %q %v", q, a)
	}
}
