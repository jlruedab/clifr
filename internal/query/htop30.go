// htop 3.0.5's screen (Ubuntu 22.04). htop 3.0.5 is GPL-2.0-only: this file
// is written from its output only (testdata/htop/SPEC-3.0.5.md, from the
// captures in bench/results/htop-captures-20261122), never from its code.
// Everything else on its screen is drawn as htop 3.2.1 draws it (htop.go).

package query

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// htop30Column is a header column's start and width: two columns of (COLS
// - 4) / 2 from column 2, the extra column of an odd width unused.
func htop30Column(cols, c int) (x, w int) {
	cw := (cols - 4) / 2
	// A meter is given cw - 2 columns (and draws one less: htop30Draw).
	return 2 + c*cw, cw - 2
}

// htop30Draw: a meter given w columns draws in w - 1.
func htop30Draw(w int) int { return w - 1 }

// htop30Mem: the Mem bar's used (with shared memory) and cache parts, KiB.
func htop30Mem(sc HtopScreen) (used, cache float64) {
	c := sc.Cached + sc.SReclaimable - sc.Shmem
	return float64(sc.MemTotal - sc.MemFree - sc.Buffers - c), float64(c)
}

// htop30Tasks is the Tasks meter's text with user and kernel threads hidden.
func htop30Tasks(tasks, running int) string {
	return fmt.Sprintf("%d; %d running", tasks, running)
}

const (
	htop30UserTitle = "USER      "
	htop30CPUTitle  = "CPU% "
)

// htop30User: the user name cut to 9 columns, then a space.
func htop30User(p *HtopProc) string {
	u := p.User
	if u == "" {
		u = fmt.Sprint(p.UID)
	}
	if utf8.RuneCountInString(u) > 9 {
		u = string([]rune(u)[:9])
	}
	return u + strings.Repeat(" ", 10-utf8.RuneCountInString(u))
}

// htop30CPU: one decimal in 4 columns, a longer number cut to 4 ("200.").
func htop30CPU(v float32) string {
	s := fmt.Sprintf("%4.1f", v)
	return s[:4] + " "
}
