package query

import (
	"testing"
	"time"
)

func TestParseWhen(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.FixedZone("ACDT", 37800)
	now := time.Date(2026, 10, 19, 14, 30, 15, 0, time.Local)
	for _, c := range []struct{ in, want string }{
		{"2026-10-02 02:00:05", "2026-10-02 02:00:05"},
		{"2026-10-02 02:00", "2026-10-02 02:00:00"},
		{"2026-10-02", "2026-10-02 00:00:00"},
		{"02:45", "2026-10-19 02:45:00"},
		{"02:45:30", "2026-10-19 02:45:30"},
		{"now", "2026-10-19 14:30:15"},
		{"today", "2026-10-19 00:00:00"},
		{"Yesterday", "2026-10-18 00:00:00"},
		{"-30m", "2026-10-19 14:00:15"},
		{"-1h30m", "2026-10-19 13:00:15"},
		{"-2d", "2026-10-17 14:30:15"},
		{"2 hours ago", "2026-10-19 12:30:15"},
		{"1 day ago", "2026-10-18 14:30:15"},
		{"90s ago", "2026-10-19 14:28:45"},
		{"10 minutes ago", "2026-10-19 14:20:15"},
	} {
		got, err := ParseWhen(c.in, now)
		if err != nil || got.Format(TimeLayout) != c.want {
			t.Errorf("%q: got %s, %v; want %s", c.in, got.Format(TimeLayout), err, c.want)
		}
	}
	for _, bad := range []string{"", "soon", "25:00", "-", "-x", "2 fortnights ago", "2026-13-01"} {
		if _, err := ParseWhen(bad, now); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"1m": time.Minute, "90s": 90 * time.Second, "1d12h": 36 * time.Hour, "2w": 14 * 24 * time.Hour} {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("%q: %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "x", "1x", "1d2"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}
