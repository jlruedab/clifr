package main

import "testing"

func TestGCPercentFor(t *testing.T) {
	const M = 1 << 20
	for _, c := range []struct {
		live uint64
		want int
	}{
		{0, 100}, {100 * M, 100}, {192 * M, 100}, {256 * M, 50}, {240 * M, 60}, {1000 * M, 50},
	} {
		if got := gcPercentFor(c.live, 384*M); got != c.want {
			t.Errorf("live %d MiB: GOGC %d, want %d", c.live/M, got, c.want)
		}
	}
}
