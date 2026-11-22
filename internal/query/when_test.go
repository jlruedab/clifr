package query

import (
	"testing"
	"time"

	"clifr/internal/store"
	"clifr/internal/testrec"
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

// TestHostZone: the recorded zone name, else the recorded offset, else nil.
func TestHostZone(t *testing.T) {
	at := time.Now().Add(time.Hour).UnixMilli() // testrec stamps meta when it writes it
	for _, c := range []struct {
		meta []string
		want string // the zone's name and offset at a fixed time
	}{
		{[]string{"timezone", "Etc/UTC", "tz_offset_s", "0"}, "Etc/UTC +0000"},
		{[]string{"timezone", "Australia/Adelaide", "tz_offset_s", "37800"}, "Australia/Adelaide +1030"},
		{[]string{"timezone", "", "tz_offset_s", "-16200"}, "UTC-04:30 -0430"},
		{[]string{"timezone", "No/Such_Zone", "tz_offset_s", "3600"}, "UTC+01:00 +0100"},
		{[]string{"hostname", "h"}, ""},
	} {
		got := ""
		if loc := HostZone(testrec.Open(t, c.meta, &store.Batch{Sample: store.Sample{TS: at}}), at); loc != nil {
			got = loc.String() + " " + time.Date(2026, 11, 22, 0, 0, 0, 0, loc).Format("-0700")
		}
		if got != c.want {
			t.Errorf("%v: %q, want %q", c.meta, got, c.want)
		}
	}
}
