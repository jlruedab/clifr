package main

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func testPages(n, lines int) []page {
	var pages []page
	base := time.Date(2026, 10, 20, 10, 0, 0, 0, time.Local).UnixMilli()
	for i := 0; i < n; i++ {
		pages = append(pages, page{title: fmt.Sprintf("p%d", i), ts: base + int64(i)*60_000, body: func(w io.Writer) error {
			for j := 0; j < lines; j++ {
				fmt.Fprintf(w, "page %d line %d %s\n", i, j, strings.Repeat("x", 30))
			}
			return nil
		}})
	}
	return pages
}

func TestPager(t *testing.T) {
	// The pages are on 2026-10-20 from 10:00; "10:01" is that day's.
	now := func() time.Time { return time.Date(2026, 10, 20, 12, 0, 0, 0, time.Local) }
	p := &pager{pages: testPages(3, 50), cache: map[int][]string{}, width: 20, height: 11, now: now}
	press := func(keys ...string) {
		for _, k := range keys {
			if p.key(k) {
				t.Fatalf("quit on %q", k)
			}
		}
	}
	press("n", "n", "n")
	if p.cur != 2 {
		t.Errorf("n past the end: page %d", p.cur)
	}
	press("Home", "Down", "Down", " ")
	if p.cur != 0 || p.top != 11 {
		t.Errorf("scroll: page %d top %d, want 0 and 11", p.cur, p.top)
	}
	press("End", "PgUp")
	if p.cur != 1 || p.top != 0 {
		t.Errorf("End, PgUp: page %d top %d", p.cur, p.top)
	}
	press("End")
	for i := 0; i < 100; i++ {
		p.key("Down")
	}
	if p.top != 51-10 { // title + 50 lines, 10 visible
		t.Errorf("scroll past the end: top %d", p.top)
	}
	press("g", "1", "0", ":", "0", "1", "Enter")
	if p.cur != 1 {
		t.Errorf("g 10:01: page %d, want 1", p.cur)
	}
	press("g", "x", "Enter")
	if p.msg == "" {
		t.Error("g with a bad time: no message")
	}
	press("Right")
	scr := p.screen()
	if lines := strings.Split(scr, "\r\n"); len(lines) != 11 || !strings.HasPrefix(lines[1], "ine 0 xxxx") {
		t.Errorf("screen: %d lines, second %q", len(lines), lines[1])
	}
	if !p.key("q") {
		t.Error("q does not quit")
	}
}

func TestKeyName(t *testing.T) {
	for in, want := range map[string]string{"\x1b[6~": "PgDn", "\x1b[5~": "PgUp", "\x1b[H": "Home", "\x1b[F": "End",
		"\x1b[A": "Up", "\r": "Enter", "\x7f": "Backspace", "n": "n"} {
		if got := keyName([]byte(in)); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
