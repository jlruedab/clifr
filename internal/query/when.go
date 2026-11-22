package query

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"clifr/internal/store"
)

// ParseWhen parses a CLI time relative to now, in time.Local:
// "YYYY-MM-DD HH:MM:SS", "YYYY-MM-DD HH:MM", "YYYY-MM-DD" (midnight),
// "HH:MM[:SS]" (today), "now", "today", "yesterday" (midnight), and
// relative times: "-30m", "-1h30m", "-2d", "2 hours ago", "90s ago".
func ParseWhen(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	now = now.In(time.Local)
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	switch strings.ToLower(s) {
	case "now":
		return now, nil
	case "today":
		return midnight, nil
	case "yesterday":
		return midnight.AddDate(0, 0, -1), nil
	}
	for _, layout := range []string{TimeLayout, "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	for _, layout := range []string{"15:04:05", "15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local), nil
		}
	}
	if d, ok := relative(s); ok {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf(`bad time %q: want "YYYY-MM-DD HH:MM[:SS]", "HH:MM", "today", "yesterday", "-30m" or "2 hours ago"`, s)
}

var agoRe = regexp.MustCompile(`^(\d+)\s*([a-z]+)\s+ago$`)

// relative parses "-DURATION" or "N UNIT ago" into a positive duration.
func relative(s string) (time.Duration, bool) {
	s = strings.ToLower(s)
	if rest, ok := strings.CutPrefix(s, "-"); ok {
		d, err := ParseDuration(rest)
		return d, err == nil && d > 0
	}
	if m := agoRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		if u, ok := unitOf(m[2]); ok {
			return time.Duration(n) * u, true
		}
	}
	return 0, false
}

func unitOf(w string) (time.Duration, bool) {
	if w == "ms" {
		return 0, false
	}
	switch strings.TrimSuffix(w, "s") {
	case "", "sec", "second":
		if w == "" {
			return 0, false
		}
		return time.Second, true
	case "m", "min", "minute":
		return time.Minute, true
	case "h", "hr", "hour":
		return time.Hour, true
	case "d", "day":
		return 24 * time.Hour, true
	case "w", "week":
		return 7 * 24 * time.Hour, true
	}
	return 0, false
}

var durPartRe = regexp.MustCompile(`(\d+)([a-z]+)`)

// ParseDuration is time.ParseDuration plus days and weeks ("1d12h", "2w").
func ParseDuration(s string) (time.Duration, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	parts := durPartRe.FindAllStringSubmatch(s, -1)
	var d time.Duration
	n := 0
	for _, p := range parts {
		v, _ := strconv.Atoi(p[1])
		u, ok := unitOf(p[2])
		if !ok {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		d += time.Duration(v) * u
		n += len(p[0])
	}
	if len(parts) == 0 || n != len(s) {
		return 0, fmt.Errorf("bad duration %q", s)
	}
	return d, nil
}

// ZoneLabel names time.Local for the resolved-time line: its abbreviation at
// t and the offset, plus the location name when it is not just "Local".
func ZoneLabel(t time.Time) string {
	t = t.In(time.Local)
	abbr, _ := t.Zone()
	l := abbr + " (UTC" + t.Format("-07:00") + ")"
	if n := time.Local.String(); n != "Local" && n != abbr {
		l = n + ", " + l
	}
	return l
}

// HostZone is the recorded host's time zone at t: the run's meta timezone
// (an IANA name), else a fixed zone from tz_offset_s; nil when neither is
// recorded or the name is unknown here and no offset was recorded.
func HostZone(db *store.DB, t int64) *time.Location {
	if name := MetaAt(db, "timezone", t); name != "" {
		if loc, err := time.LoadLocation(name); err == nil {
			return loc
		}
	}
	if off, err := strconv.Atoi(MetaAt(db, "tz_offset_s", t)); err == nil {
		m := off / 60
		sign := '+'
		if m < 0 {
			sign, m = '-', -m
		}
		return time.FixedZone(fmt.Sprintf("UTC%c%02d:%02d", sign, m/60, m%60), off)
	}
	return nil
}
