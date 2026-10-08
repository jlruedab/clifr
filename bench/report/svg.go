package main

import (
	"fmt"
	"html"
	"math"
	"strings"
)

// Plain inline-SVG charts. Colors are CSS custom properties defined in the
// page (--s1.. for series, --base for the baseline, --grid, --axis, ink
// classes), so light and dark themes come from the stylesheet. Every mark
// that carries a value has a data-tip attribute; a small script in the page
// shows it as a tooltip on hover and keyboard focus. Every chart is
// accompanied by a table with the same values.

type svg struct {
	strings.Builder
	w, h float64
}

func (s *svg) f(format string, a ...any) { fmt.Fprintf(&s.Builder, format, a...) }

func newSVG(w, h float64, label string) *svg {
	s := &svg{w: w, h: h}
	s.f(`<svg class="chart" viewBox="0 0 %g %g" width="%g" role="img" aria-label="%s">`, w, h, w, esc(label))
	return s
}

func (s *svg) end() string { s.f("</svg>"); return s.String() }

func esc(v string) string { return html.EscapeString(v) }

// tipAttr renders the tooltip attributes for a mark.
func tipAttr(tip string) string {
	if tip == "" {
		return ""
	}
	return fmt.Sprintf(` data-tip="%s" tabindex="0"`, esc(tip))
}

// linear scale [d0,d1] -> [r0,r1]
type scale struct {
	d0, d1, r0, r1 float64
	log            bool
}

func (sc scale) at(v float64) float64 {
	if sc.log {
		v, d0, d1 := math.Log10(v), math.Log10(sc.d0), math.Log10(sc.d1)
		return sc.r0 + (v-d0)/(d1-d0)*(sc.r1-sc.r0)
	}
	if sc.d1 == sc.d0 {
		return sc.r0
	}
	return sc.r0 + (v-sc.d0)/(sc.d1-sc.d0)*(sc.r1-sc.r0)
}

// niceTicks returns about n round tick values covering [lo, hi].
func niceTicks(lo, hi float64, n int) []float64 {
	if hi <= lo {
		hi = lo + 1
	}
	raw := (hi - lo) / float64(n)
	mag := math.Pow(10, math.Floor(math.Log10(raw)))
	step := mag
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		if m*mag >= raw {
			step = m * mag
			break
		}
	}
	var t []float64
	last := math.Ceil(hi/step-1e-9) * step // the last tick covers hi
	for v := math.Floor(lo/step) * step; v <= last+step*1e-9; v += step {
		t = append(t, math.Round(v/step)*step)
	}
	return t
}

// logTicks returns 1-2-5 ticks between lo and hi (both > 0).
func logTicks(lo, hi float64) []float64 {
	var t []float64
	for e := math.Floor(math.Log10(lo)); e <= math.Ceil(math.Log10(hi)); e++ {
		for _, m := range []float64{1, 2, 5} {
			v := m * math.Pow(10, e)
			if v >= lo*0.999 && v <= hi*1.001 {
				t = append(t, v)
			}
		}
	}
	return t
}

// tickText formats an axis value compactly (1,000 / 2.5 / 0.1).
func tickText(v float64) string {
	switch {
	case v == 0:
		return "0"
	case math.Abs(v) >= 1e6:
		return trimZero(fmt.Sprintf("%.1f", v/1e6)) + "M"
	case math.Abs(v) >= 1e4:
		return trimZero(fmt.Sprintf("%.1f", v/1e3)) + "k"
	case math.Abs(v) >= 1000:
		return commas(v)
	case math.Abs(v) >= 1:
		return trimZero(fmt.Sprintf("%.1f", v))
	}
	return trimZero(fmt.Sprintf("%.3f", v))
}

func trimZero(s string) string {
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	return s
}

// barPath draws a horizontal bar from x0 to x1 with a 4px rounded data end
// and a square end at the baseline.
func barPath(x0, x1, y, h float64) string {
	r := math.Min(4, math.Min(h/2, math.Abs(x1-x0)))
	if x1 < x0+0.5 {
		x1 = x0 + 0.5
	}
	return fmt.Sprintf("M%.1f,%.1fH%.1fA%g,%g 0 0 1 %.1f,%.1fV%.1fA%g,%g 0 0 1 %.1f,%.1fH%.1fZ",
		x0, y, x1-r, r, r, x1, y+r, y+h-r, r, r, x1-r, y+h, x0)
}

type barRow struct {
	Label, Color, Tip, ValueText string
	Value, Lo, Hi                float64 // Lo/Hi: CI whisker (NaN = none)
}

// hbars draws one horizontal bar per row from zero, with an optional CI
// whisker and an optional vertical reference line (ref > 0).
func hbars(label, xTitle string, rows []barRow, ref float64, refLabel string) string {
	const left, right, rowH, barH = 120.0, 80.0, 30.0, 16.0
	top := 8.0
	if ref > 0 {
		top = 24 // the reference label sits above the plot
	}
	w := 640.0
	h := top + rowH*float64(len(rows)) + 40
	maxV := ref
	for _, r := range rows {
		maxV = math.Max(maxV, math.Max(r.Value, nz(r.Hi)))
	}
	if maxV <= 0 || math.IsNaN(maxV) {
		maxV = 1
	}
	ticks := niceTicks(0, maxV, 5)
	sc := scale{0, ticks[len(ticks)-1], left, w - right, false}
	s := newSVG(w, h, label)
	base := top + rowH*float64(len(rows))
	for _, t := range ticks {
		x := sc.at(t)
		s.f(`<line class="grid" x1="%.1f" x2="%.1f" y1="%g" y2="%g"/>`, x, x, top, base)
		s.f(`<text class="ax" x="%.1f" y="%g" text-anchor="middle">%s</text>`, x, base+15, tickText(t))
	}
	s.f(`<text class="ax" x="%g" y="%g" text-anchor="middle">%s</text>`, (left+w-right)/2, base+33, esc(xTitle))
	for i, r := range rows {
		y := top + rowH*float64(i) + (rowH-barH)/2
		s.f(`<text class="lbl" x="%g" y="%.1f" text-anchor="end">%s</text>`, left-8, y+barH/2+4, esc(r.Label))
		if math.IsNaN(r.Value) {
			s.f(`<text class="ax" x="%g" y="%.1f">n/a</text>`, left+4, y+barH/2+4)
			continue
		}
		s.f(`<path d="%s" fill="var(%s)"%s/>`, barPath(sc.at(0), sc.at(r.Value), y, barH), r.Color, tipAttr(r.Tip))
		end := sc.at(r.Value)
		if !math.IsNaN(r.Lo) && !math.IsNaN(r.Hi) {
			lo, hi := sc.at(math.Max(0, r.Lo)), sc.at(r.Hi)
			yc := y + barH/2
			s.f(`<path class="whisker" d="M%.1f,%.1fH%.1fM%.1f,%.1fV%.1fM%.1f,%.1fV%.1f"/>`,
				lo, yc, hi, lo, yc-4, yc+4, hi, yc-4, yc+4)
			end = math.Max(end, hi)
		}
		s.f(`<text class="val" x="%.1f" y="%.1f">%s</text>`, end+6, y+barH/2+4, esc(r.ValueText))
	}
	s.f(`<line class="axis" x1="%g" x2="%g" y1="%g" y2="%g"/>`, left, left, top, base)
	if ref > 0 {
		x := sc.at(ref)
		s.f(`<line class="ref" x1="%.1f" x2="%.1f" y1="%g" y2="%g"/>`, x, x, top-6, base)
		s.f(`<text class="ax" x="%.1f" y="%g" text-anchor="middle">%s</text>`, x, top-10, esc(refLabel))
	}
	return s.end()
}

type forestRow struct {
	Label, Tip, ValueText string
	D, Lo, Hi             float64
}

// forest draws differences with 95% intervals around a zero line.
func forest(label, xTitle string, rows []forestRow) string {
	const left, right, top, rowH = 120.0, 110.0, 8.0, 28.0
	w := 640.0
	h := top + rowH*float64(len(rows)) + 40
	lo, hi := 0.0, 0.0
	for _, r := range rows {
		for _, v := range []float64{r.D, r.Lo, r.Hi} {
			if !math.IsNaN(v) {
				lo, hi = math.Min(lo, v), math.Max(hi, v)
			}
		}
	}
	if lo == hi {
		lo, hi = -1, 1
	}
	pad := (hi - lo) * 0.08
	ticks := niceTicks(lo-pad, hi+pad, 6)
	sc := scale{ticks[0], ticks[len(ticks)-1], left, w - right, false}
	s := newSVG(w, h, label)
	base := top + rowH*float64(len(rows))
	for _, t := range ticks {
		x := sc.at(t)
		cls := "grid"
		if t == 0 {
			cls = "axis"
		}
		s.f(`<line class="%s" x1="%.1f" x2="%.1f" y1="%g" y2="%g"/>`, cls, x, x, top, base)
		s.f(`<text class="ax" x="%.1f" y="%g" text-anchor="middle">%s</text>`, x, base+15, tickText(t))
	}
	s.f(`<text class="ax" x="%g" y="%g" text-anchor="middle">%s</text>`, (left+w-right)/2, base+33, esc(xTitle))
	for i, r := range rows {
		yc := top + rowH*float64(i) + rowH/2
		s.f(`<text class="lbl" x="%g" y="%.1f" text-anchor="end">%s</text>`, left-8, yc+4, esc(r.Label))
		if math.IsNaN(r.D) {
			continue
		}
		if !math.IsNaN(r.Lo) {
			s.f(`<path class="whisker" d="M%.1f,%.1fH%.1fM%.1f,%.1fV%.1fM%.1f,%.1fV%.1f"/>`,
				sc.at(r.Lo), yc, sc.at(r.Hi), sc.at(r.Lo), yc-5, yc+5, sc.at(r.Hi), yc-5, yc+5)
		}
		s.f(`<circle class="dot" cx="%.1f" cy="%.1f" r="5"%s/>`, sc.at(r.D), yc, tipAttr(r.Tip))
		s.f(`<text class="val" x="%g" y="%.1f">%s</text>`, w-right+16, yc+4, esc(r.ValueText))
	}
	return s.end()
}

type rangeRow struct {
	Label, Color, Tip  string
	P50, P95, P99, Max float64
}

// ranges draws, per row on a log axis, a bar from the smallest value to the
// p95, a whisker on to the p99, a tick at the maximum and a dot at the p50.
func ranges(label, xTitle string, rows []rangeRow) string {
	const left, right, top, rowH, barH = 150.0, 20.0, 8.0, 28.0, 10.0
	w := 640.0
	h := top + rowH*float64(len(rows)) + 40
	lo, hi := math.Inf(1), 0.0
	for _, r := range rows {
		for _, v := range []float64{r.P50, r.P95, r.P99, r.Max} {
			if v > 0 && !math.IsNaN(v) {
				lo, hi = math.Min(lo, v), math.Max(hi, v)
			}
		}
	}
	if hi == 0 {
		lo, hi = 1, 10
	}
	lo = math.Pow(10, math.Floor(math.Log10(lo)))
	hi = math.Pow(10, math.Ceil(math.Log10(hi)))
	sc := scale{lo, hi, left, w - right, true}
	s := newSVG(w, h, label)
	base := top + rowH*float64(len(rows))
	for _, t := range logTicks(lo, hi) {
		x := sc.at(t)
		s.f(`<line class="grid" x1="%.1f" x2="%.1f" y1="%g" y2="%g"/>`, x, x, top, base)
		s.f(`<text class="ax" x="%.1f" y="%g" text-anchor="middle">%s</text>`, x, base+15, tickText(t))
	}
	s.f(`<text class="ax" x="%g" y="%g" text-anchor="middle">%s</text>`, (left+w-right)/2, base+33, esc(xTitle))
	at := func(v float64) float64 { return sc.at(math.Max(v, lo)) }
	for i, r := range rows {
		y := top + rowH*float64(i) + (rowH-barH)/2
		yc := y + barH/2
		s.f(`<text class="lbl" x="%g" y="%.1f" text-anchor="end">%s</text>`, left-8, yc+4, esc(r.Label))
		if math.IsNaN(r.P50) {
			continue
		}
		s.f(`<g%s>`, tipAttr(r.Tip))
		s.f(`<rect x="%.1f" y="%.1f" width="%.1f" height="%g" rx="4" fill="var(%s)" opacity="0.35"/>`,
			at(r.P50), y, math.Max(1, at(r.P95)-at(r.P50)), barH, r.Color)
		s.f(`<path class="whisker" d="M%.1f,%.1fH%.1fM%.1f,%.1fV%.1f"/>`, at(r.P95), yc, at(r.P99), at(r.P99), yc-4, yc+4)
		s.f(`<path class="maxtick" d="M%.1f,%.1fV%.1f"/>`, at(r.Max), yc-6, yc+6)
		s.f(`<circle cx="%.1f" cy="%.1f" r="5" fill="var(%s)" class="ringed"/>`, at(r.P50), yc, r.Color)
		s.f(`<rect x="%.1f" y="%.1f" width="%.1f" height="%g" fill="transparent"/>`, at(r.P50)-6, y-6, at(r.Max)-at(r.P50)+12, barH+12)
		s.f(`</g>`)
	}
	return s.end()
}

type lineSeries struct {
	Name, Color string
	Pts         []XY
	Tips        []string
}

// lines draws line series with point markers. refY > 0 adds a horizontal
// reference line labelled refLabel. With two or more series a legend is
// drawn above the plot.
func lines(label, xTitle, yTitle string, series []lineSeries, refY float64, refLabel string, w, h float64) string {
	left, right, top, bottom := 48.0, 16.0, 12.0, 38.0
	if len(series) > 1 {
		top = 30
	}
	minX, maxX, maxY := math.Inf(1), math.Inf(-1), refY
	for _, se := range series {
		for _, p := range se.Pts {
			if math.IsNaN(p.Y) {
				continue
			}
			minX, maxX, maxY = math.Min(minX, p.X), math.Max(maxX, p.X), math.Max(maxY, p.Y)
		}
	}
	if math.IsInf(minX, 0) {
		minX, maxX = 0, 1
	}
	if maxY <= 0 {
		maxY = 1
	}
	yt := niceTicks(0, maxY*1.05, 4)
	xt := niceTicks(minX, maxX, 5)
	sx := scale{xt[0], xt[len(xt)-1], left, w - right, false}
	sy := scale{0, yt[len(yt)-1], h - bottom, top, false}
	s := newSVG(w, h, label)
	for _, t := range yt {
		y := sy.at(t)
		s.f(`<line class="grid" x1="%g" x2="%g" y1="%.1f" y2="%.1f"/>`, left, w-right, y, y)
		s.f(`<text class="ax" x="%g" y="%.1f" text-anchor="end">%s</text>`, left-6, y+4, tickText(t))
	}
	for _, t := range xt {
		s.f(`<text class="ax" x="%.1f" y="%g" text-anchor="middle">%s</text>`, sx.at(t), h-bottom+15, tickText(t))
	}
	s.f(`<line class="axis" x1="%g" x2="%g" y1="%g" y2="%g"/>`, left, w-right, h-bottom, h-bottom)
	s.f(`<text class="ax" x="%g" y="%g" text-anchor="middle">%s</text>`, (left+w-right)/2, h-4, esc(xTitle))
	s.f(`<text class="ax" x="%g" y="%g" transform="rotate(-90 %g %g)" text-anchor="middle">%s</text>`,
		12.0, (top+h-bottom)/2, 12.0, (top+h-bottom)/2, esc(yTitle))
	if refY > 0 {
		y := sy.at(refY)
		s.f(`<line class="ref" x1="%g" x2="%g" y1="%.1f" y2="%.1f"/>`, left, w-right, y, y)
		s.f(`<text class="ax" x="%g" y="%.1f" text-anchor="end">%s</text>`, w-right, y-4, esc(refLabel))
	}
	for _, se := range series {
		var d strings.Builder
		pen := false
		for _, p := range se.Pts {
			if math.IsNaN(p.Y) {
				pen = false
				continue
			}
			c := "L"
			if !pen {
				c = "M"
			}
			fmt.Fprintf(&d, "%s%.1f,%.1f", c, sx.at(p.X), sy.at(p.Y))
			pen = true
		}
		s.f(`<path class="line" d="%s" stroke="var(%s)"/>`, d.String(), se.Color)
		dots := len(se.Pts) <= 12
		for i, p := range se.Pts {
			if math.IsNaN(p.Y) {
				continue
			}
			tip := ""
			if i < len(se.Tips) {
				tip = se.Tips[i]
			}
			if dots {
				s.f(`<circle class="ringed" cx="%.1f" cy="%.1f" r="4" fill="var(%s)"/>`, sx.at(p.X), sy.at(p.Y), se.Color)
			}
			if tip != "" {
				s.f(`<circle cx="%.1f" cy="%.1f" r="12" fill="transparent"%s/>`, sx.at(p.X), sy.at(p.Y), tipAttr(tip))
			}
		}
	}
	if len(series) > 1 {
		x := left
		for _, se := range series {
			s.f(`<line x1="%g" x2="%g" y1="12" y2="12" stroke="var(%s)" stroke-width="2"/>`, x, x+16, se.Color)
			s.f(`<text class="lbl" x="%g" y="16">%s</text>`, x+21, esc(se.Name))
			x += 34 + 7.2*float64(len(se.Name))
		}
	}
	return s.end()
}

func nz(v float64) float64 {
	if math.IsNaN(v) {
		return 0
	}
	return v
}
