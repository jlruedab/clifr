// Parts of this file follow atop's various.c and showsys.c (GPL-2.0-or-later),
// used under the GPL-3.0: see LICENSING.md and packaging/notices/atop.txt.

package query

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// atop's value formats (various.c), shared by its system lines and process
// columns. Values are atop's count_t (int64).

// atopVal is val2valstr: value in width positions; a value that does not fit
// becomes "NNNeE" (as short as possible). avg with nsecs: a per-second
// average with "/s".
func atopVal(value int64, width int, avg bool, nsecs int64) string {
	suffix := ""
	if avg && nsecs > 0 {
		value = (value + nsecs/2) / nsecs
		width -= 2
		suffix = "/s"
	}
	if value < 0 {
		return fmt.Sprintf("%*s%s", width, "?", suffix)
	}
	maxval := int64(math.Pow(10, float64(width))) - 1
	if value < maxval {
		return fmt.Sprintf("%*d%s", width, value, suffix)
	}
	if width < 3 {
		return fmt.Sprintf("%d%s", value, suffix)
	}
	width -= 2
	maxval = int64(math.Pow(10, float64(width))) - 1
	var exp, remain int64
	for value > maxval {
		exp++
		remain = value % 10
		value /= 10
	}
	if remain >= 5 && value < maxval {
		value++
	}
	return fmt.Sprintf("%*de%d%s", width%100, value, exp%100, suffix)
}

// atopElapsed is val2elapstr: seconds as NdNhNmNs, leading zero units left out.
func atopElapsed(s int64) string {
	var b strings.Builder
	if s >= 86400 {
		fmt.Fprintf(&b, "%dd", s/86400)
	}
	if s >= 3600 {
		fmt.Fprintf(&b, "%dh", s%86400/3600)
	}
	if s >= 60 {
		fmt.Fprintf(&b, "%dm", s%3600/60)
	}
	fmt.Fprintf(&b, "%ds", s%60)
	return b.String()
}

// atopCPU is val2cpustr: milliseconds in 6 positions: "SS.HHs", "MMmSSs",
// "HHhMMm" or "DDdHHh", each unit rounded.
func atopCPU(ms int64) string {
	if ms < 100000 {
		return fmt.Sprintf("%2d.%02ds", ms/1000%100, ms%1000/10)
	}
	s := (ms + 500) / 1000
	if s < 6000 {
		return fmt.Sprintf("%2dm%02ds", s/60%100, s%60)
	}
	m := (s + 30) / 60
	if m < 6000 {
		return fmt.Sprintf("%2dh%02dm", m/60%100, m%60)
	}
	h := (m + 30) / 60
	return fmt.Sprintf("%2dd%02dh", h/24%100, h%24)
}

// atop's memory formats (atop.h): the smallest one a value may take.
const (
	atopB = iota
	atopKB
	atopKBInt
	atopMB
	atopMBInt
	atopGB
	atopGBInt
	atopTB
	atopTBInt
	atopPB
	atopPBInt
	atopEB
	atopEBInt
	atopOverflow
)

// atopMem is val2memstr: bytes in 6 positions with a unit ("61.0G", " 0.0M");
// pformat: the smallest format wanted; avg with nsecs: per second ("/s"; 4
// positions and integer formats from 10 units up).
func atopMem(value int64, pformat int, avg bool, nsecs int64) string {
	const (
		kb = int64(1024)
		mb = kb * 1024
		gb = mb * 1024
		tb = gb * 1024
		pb = tb * 1024
		eb = pb * 1024
	)
	verify := value
	if value < 0 {
		verify = -value * 10
	}
	suffix, base := "", 6
	var f int
	if avg && nsecs > 0 {
		value = int64(math.Round(float64(value) / float64(nsecs)))
		verify = int64(math.Round(float64(verify) / float64(nsecs)))
		base -= 2
		suffix = "/s"
		switch {
		case verify <= 999:
			f = atopB
		case verify <= kb*9:
			f = atopKB
		case verify <= kb*999:
			f = atopKBInt
		case verify <= mb*9:
			f = atopMB
		case verify <= mb*999:
			f = atopMBInt
		case verify <= gb*9:
			f = atopGB
		case verify <= gb*999:
			f = atopGBInt
		case verify <= tb*9:
			f = atopTB
		case verify <= tb*999:
			f = atopTBInt
		case verify <= pb*9:
			f = atopPB
		case verify <= pb*999:
			f = atopPBInt
		case verify <= eb*7+(eb-1):
			f = atopEB
		default:
			f = atopOverflow
		}
	} else {
		switch {
		case verify <= 999:
			f = atopB
		case verify <= kb*999:
			f = atopKB
		case verify <= mb*999:
			f = atopMB
		case verify <= gb*999:
			f = atopGB
		case verify <= tb*999:
			f = atopTB
		case verify <= pb*999:
			f = atopPB
		default:
			f = atopEB
		}
	}
	f = max(f, pformat)
	w := base - 1
	frac := func(div int64, unit string) string {
		return fmt.Sprintf("%*.1f%s%s", w, float64(value)/float64(div), unit, suffix)
	}
	whole := func(div int64, unit string) string {
		return fmt.Sprintf("%*d%s%s", w, int64(math.Round(float64(value)/float64(div))), unit, suffix)
	}
	var s string
	switch f {
	case atopB:
		s = fmt.Sprintf("%*dB%s", w, value, suffix)
	case atopKB:
		s = frac(kb, "K")
	case atopKBInt:
		s = whole(kb, "K")
	case atopMB:
		s = frac(mb, "M")
	case atopMBInt:
		s = whole(mb, "M")
	case atopGB:
		s = frac(gb, "G")
	case atopGBInt:
		s = whole(gb, "G")
	case atopTB:
		s = frac(tb, "T")
	case atopTBInt:
		s = whole(tb, "T")
	case atopPB:
		s = frac(pb, "P")
	case atopPBInt:
		s = whole(pb, "P")
	case atopEB:
		s = frac(eb, "E")
	default:
		return "OVFLOW"
	}
	// snprintf into 7 bytes: at most 6 characters; the 6th must be a unit
	// (or the 's' of "/s"), else the value did not fit.
	if len(s) > 6 {
		s = s[:6]
	}
	if len(s) < 6 || !strings.ContainsRune("sBKMGTPE", rune(s[5])) {
		return "OVFLOW"
	}
	return s
}

// atopItem is one 12-character box of a system line and its priority.
type atopItem struct {
	text string
	prio int
}

// atopBlank is BLANKBOX.
var atopBlank = atopItem{text: "            "}

// atopSysLine is showsysline into a pipe of width columns: the label, then
// as many boxes as fit ((width-5)/15), the lowest priority ones removed first
// (the first of equal ones), the room left spread as blank boxes and spaces.
func atopSysLine(label string, items []atopItem, width int) string {
	avail := (width - 5) / 15
	items = append([]atopItem(nil), items...)
	for len(items) > avail {
		low := 0
		for i := range items {
			if items[i].prio < items[low].prio {
				low = i
			}
		}
		items = append(items[:low], items[low+1:]...)
	}
	var slackItems float64
	if len(items) > 1 {
		slackItems = float64(avail-len(items)) / float64(len(items))
	} else {
		slackItems = float64((avail - len(items)) / 2) // integer division in atop
	}
	charOver := float64((width-5)%15) / float64(avail*2)
	var charUsed, itemUsed float64
	var b strings.Builder
	b.WriteString(label)
	blanks := func() {
		charUsed += charOver
		for charUsed > 0.5 {
			b.WriteByte(' ')
			charUsed--
		}
	}
	for _, it := range items {
		b.WriteString(" | ")
		blanks()
		b.WriteString(it.text)
		itemUsed += slackItems
		for itemUsed > 0.5 {
			blanks()
			b.WriteString(" | ")
			b.WriteString(atopBlank.text)
			blanks()
			itemUsed--
		}
		blanks()
	}
	b.WriteString(" |")
	return b.String()
}

// atopDefs parses a line definition ("PRCSYS:8 PRCUSER:8 BLANKBOX:0 ..."):
// names and priorities, as atop's makeargv (a priority may run into the
// next name: "CPLNUMCPU:7BLANKBOX:0").
func atopDefs(s string) (names []string, prios []int) {
	for len(s) > 0 {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			break
		}
		name, rest, _ := strings.Cut(s, ":")
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		p, _ := strconv.Atoi(rest[:i])
		names, prios = append(names, name), append(prios, p)
		s = rest[i:]
	}
	return names, prios
}
