package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"image"
	"image/png"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"clifr/internal/query"
)

// clifr tui's splash screen while the first window loads: the logo
// (clifr-logo.png without the tagline, cropped and scaled to 480 pixels
// wide; the background transparent) drawn as ASCII characters, each in its
// cell's colour, at the terminal's width, then the tagline as text.

//go:embed splash.png
var splashPNG []byte

var splashImg = sync.OnceValue(func() *image.NRGBA {
	img, err := png.Decode(bytes.NewReader(splashPNG))
	if err != nil {
		return nil
	}
	n, _ := img.(*image.NRGBA)
	return n
})

// splashRamp: characters from the lightest coverage to the fullest.
const splashRamp = " .:-=+*#%@"

// splashArt is the logo in cols columns (a cell is twice as high as wide).
// With color, each run of cells of one colour is preceded by its SGR
// (24-bit with truecolor, else the 256-colour cube) and the lines end with
// a reset.
func splashArt(cols int, color, truecolor bool) []string {
	img := splashImg()
	if img == nil || cols < 8 {
		return nil
	}
	b := img.Bounds()
	cw := float64(b.Dx()) / float64(cols)
	rows := max(1, int(float64(b.Dy())/(2*cw)+0.5))
	ch := float64(b.Dy()) / float64(rows)
	lines := make([]string, rows)
	for j := range rows {
		var sb strings.Builder
		last := ""
		for i := range cols {
			var k, n float64
			var cls [len(splashPalette)][4]float64 // weight, r, g, b
			for y := int(float64(j) * ch); y < max(int(float64(j)*ch)+1, int(float64(j+1)*ch)); y++ {
				for x := int(float64(i) * cw); x < max(int(float64(i)*cw)+1, int(float64(i+1)*cw)); x++ {
					p := img.NRGBAAt(b.Min.X+x, b.Min.Y+y)
					a := float64(p.A) / 255
					k += a
					n++
					if a > 0 {
						c := &cls[splashClass(p.R, p.G, p.B)]
						c[0] += a
						c[1] += a * float64(p.R)
						c[2] += a * float64(p.G)
						c[3] += a * float64(p.B)
					}
				}
			}
			best := 0
			for c := range cls {
				if cls[c][0] > cls[best][0] {
					best = c
				}
			}
			bc := cls[best]
			r, g, bl := bc[1]/bc[0], bc[2]/bc[0], bc[3]/bc[0]
			cov := k / n
			c := splashRamp[min(len(splashRamp)-1, int(cov*float64(len(splashRamp))))]
			if c == ' ' || !color {
				sb.WriteByte(c)
				continue
			}
			sgr := splashSGR(r, g, bl, truecolor)
			if sgr != last {
				sb.WriteString(sgr)
				last = sgr
			}
			sb.WriteByte(c)
		}
		s := strings.TrimRight(sb.String(), " ")
		if last != "" {
			s += "\x1b[0m"
		}
		lines[j] = s
	}
	return lines
}

// splashPalette: the logo's colours (orange, black, grey, the dial's
// cream, the screws' light grey). A cell takes the colour most of its
// pixels are nearest to, not their mean (orange and black make brown).
var splashPalette = [...][3]int{{0xff, 0x66, 0x00}, {0x1a, 0x1a, 0x1a}, {0x8b, 0x94, 0x9e}, {0xff, 0xcc, 0x99}, {0xc8, 0xc8, 0xc8}}

func splashClass(r, g, b uint8) int {
	best, bd := 0, 1<<30
	for i, p := range splashPalette {
		dr, dg, db := int(r)-p[0], int(g)-p[1], int(b)-p[2]
		if d := dr*dr + dg*dg + db*db; d < bd {
			best, bd = i, d
		}
	}
	return best
}

// splashSGR is the foreground colour r, g, b; the logo's black (the box's
// face) is lifted to a dark grey so that it shows on a dark terminal.
func splashSGR(r, g, b float64, truecolor bool) string {
	if l := 0.299*r + 0.587*g + 0.114*b; l < 80 {
		r, g, b = r+80-l, g+80-l, b+80-l
	}
	if truecolor {
		return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", int(r), int(g), int(b))
	}
	q := func(v float64) int { return min(5, int(v/51+0.5)) }
	return fmt.Sprintf("\x1b[38;5;%dm", 16+36*q(r)+6*q(g)+q(b))
}

// splashScreen is the whole screen: the logo, the tagline and the status
// line, centred in w x h.
func splashScreen(w, h int, color, truecolor bool, status string) string {
	cols := min(w-4, 140)
	art := splashArt(cols, color, truecolor)
	for len(art) > max(1, h-6) && cols > 20 { // a low terminal: a smaller logo
		cols -= 4
		art = splashArt(cols, color, truecolor)
	}
	if len(art)+6 > h {
		art = nil
	}
	tag := "COMMAND LINE FLIGHT RECORDER"
	if w >= 2*len(tag)+4 {
		tag = strings.Join(strings.Split(tag, ""), " ")
	}
	rule := strings.Repeat("━", max(0, (len(tag)-4)/2-1))
	rule += " ╱╱╱╱ " + rule
	grey, orange, reset := "", "", ""
	if color {
		grey, orange, reset = splashSGR(0x8b, 0x94, 0x9e, truecolor), splashSGR(0xff, 0x66, 0x00, truecolor), "\x1b[0m"
	}
	var lines []string
	pad := strings.Repeat(" ", max(0, (w-cols)/2))
	for _, l := range art {
		lines = append(lines, pad+l)
	}
	centre := func(s, sgr string) string {
		n := utf8.RuneCountInString(s)
		if n > w {
			return ""
		}
		return strings.Repeat(" ", (w-n)/2) + sgr + s + reset
	}
	lines = append(lines, "", centre(tag, grey), centre(rule, orange), "", centre(status, ""))
	var sb strings.Builder
	sb.WriteString("\x1b[H")
	sb.WriteString(strings.Repeat("\r\n", max(0, (h-len(lines))/2)))
	sb.WriteString(strings.Join(lines, "\r\n"))
	return sb.String()
}

// showSplash puts the splash on the alternate screen while clifr tui loads
// [from, to]; the status line counts the seconds. The returned function
// stops it: ok keeps the alternate screen (blank) for the tui, otherwise
// the normal screen comes back (an error is printed there).
func showSplash(color bool, from, to int64) func(ok bool) {
	truecolor := strings.Contains(os.Getenv("COLORTERM"), "truecolor") || strings.Contains(os.Getenv("COLORTERM"), "24bit")
	leave := func() { os.Stdout.WriteString("\x1b[0m\x1b[?25h\x1b[?1049l") }
	os.Stdout.WriteString("\x1b[?1049h\x1b[?25l")
	setRestoreTerm(leave) // ^C while loading
	start := time.Now()
	spin := `|/-\`
	lw, lh := 0, 0
	draw := func(i int) {
		w, h := 80, 24
		if cw, ch, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			w, h = cw, ch
		}
		if w != lw || h != lh { // the first draw or a resize: from a blank screen
			os.Stdout.WriteString("\x1b[2J")
			lw, lh = w, h
		}
		status := fmt.Sprintf("%c loading %s .. %s  %ds", spin[i%len(spin)], query.FormatMS(from), query.FormatMS(to), int(time.Since(start).Seconds()))
		os.Stdout.WriteString(splashScreen(w, h, color, truecolor, status))
	}
	draw(0)
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(150 * time.Millisecond)
		defer t.Stop()
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			case <-t.C:
				draw(i)
			}
		}
	}()
	return func(ok bool) {
		close(stop)
		<-stopped
		setRestoreTerm(nil)
		if ok {
			os.Stdout.WriteString("\x1b[0m\x1b[H\x1b[2J")
		} else {
			leave()
		}
	}
}
