package main

import (
	"math"
	"sort"
)

// mean of the non-NaN values; NaN if there are none.
func mean(v []float64) float64 {
	var s float64
	n := 0
	for _, x := range v {
		if !math.IsNaN(x) {
			s += x
			n++
		}
	}
	if n == 0 {
		return nan
	}
	return s / float64(n)
}

func maxOf(v []float64) float64 {
	m := nan
	for _, x := range v {
		if !math.IsNaN(x) && (math.IsNaN(m) || x > m) {
			m = x
		}
	}
	return m
}

// percentile by nearest rank on a sorted copy (the same rule as clifr stats).
func percentile(v []float64, p float64) float64 {
	var s []float64
	for _, x := range v {
		if !math.IsNaN(x) {
			s = append(s, x)
		}
	}
	if len(s) == 0 {
		return nan
	}
	sort.Float64s(s)
	return s[int(p*float64(len(s)-1)+0.5)]
}

func variance(v []float64) float64 {
	if len(v) < 2 {
		return nan
	}
	m := mean(v)
	var s float64
	for _, x := range v {
		s += (x - m) * (x - m)
	}
	return s / float64(len(v)-1)
}

// meanCI returns the mean and the 95% confidence half-width
// t(0.975, n-1) * s / sqrt(n).
func meanCI(v []float64) Stat {
	st := Stat{Mean: mean(v), CI: nan, N: len(v), Vals: v}
	if len(v) >= 2 {
		st.CI = tcrit(float64(len(v)-1)) * math.Sqrt(variance(v)/float64(len(v)))
	}
	return st
}

// welch compares x with the baseline a: the difference of means with a
// Welch-Satterthwaite 95% interval, and the difference as % of a's mean.
func welch(x, a Stat) Diff {
	d := Diff{D: x.Mean - a.Mean, Lo: nan, Hi: nan, Pct: nan}
	if a.Mean != 0 {
		d.Pct = d.D / a.Mean * 100
	}
	if x.N < 2 || a.N < 2 {
		return d
	}
	vx, va := variance(x.Vals)/float64(x.N), variance(a.Vals)/float64(a.N)
	se := math.Sqrt(vx + va)
	if se == 0 {
		d.Lo, d.Hi, d.OK = d.D, d.D, true
		return d
	}
	df := (vx + va) * (vx + va) / (vx*vx/float64(x.N-1) + va*va/float64(a.N-1))
	h := tcrit(df) * se
	d.Lo, d.Hi, d.OK = d.D-h, d.D+h, true
	return d
}

// tcrit is the two-sided 95% critical value of Student's t; fractional
// degrees of freedom are rounded down (slightly conservative).
func tcrit(df float64) float64 {
	table := []float64{0, 12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
		2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
		2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042}
	n := int(math.Floor(df))
	switch {
	case n < 1:
		return table[1]
	case n <= 30:
		return table[n]
	case n <= 40:
		return 2.021
	case n <= 60:
		return 2.000
	case n <= 120:
		return 1.980
	}
	return 1.960
}

// slopePerHour fits a least-squares line to f(sample) over time and returns
// its slope per hour (NaN with fewer than 5 samples).
func slopePerHour(ss []Sample, f func(Sample) float64) float64 {
	var xs, ys []float64
	for _, s := range ss {
		if s.Skipped {
			continue
		}
		xs = append(xs, float64(s.TS))
		ys = append(ys, f(s))
	}
	if len(xs) < 5 { // fewer points give a meaningless trend
		return nan
	}
	mx, my := mean(xs), mean(ys)
	var num_, den float64
	for i := range xs {
		num_ += (xs[i] - mx) * (ys[i] - my)
		den += (xs[i] - mx) * (xs[i] - mx)
	}
	if den == 0 {
		return nan
	}
	return num_ / den * 3.6e6
}

// growth describes how a cost grows across three increasing load values:
// the marginal cost per unit on each segment and their ratio (about 1 when
// the cost is linear, above 1 when it grows faster than linear).
type growth struct {
	PerUnit float64 // marginal cost per unit, whole range
	Ratio   float64 // slope of the upper segment / slope of the lower one
	Flat    bool    // the cost changes by less than 10% over the whole range
}

func growthOf(xs, ys []float64) growth {
	g := growth{PerUnit: nan, Ratio: nan}
	n := len(xs)
	if n < 2 {
		return g
	}
	g.PerUnit = (ys[n-1] - ys[0]) / (xs[n-1] - xs[0])
	g.Flat = math.Abs(ys[n-1]-ys[0]) < 0.1*math.Abs(mean(ys))
	if n >= 3 {
		s1 := (ys[1] - ys[0]) / (xs[1] - xs[0])
		s2 := (ys[n-1] - ys[1]) / (xs[n-1] - xs[1])
		if s1 > 0 {
			g.Ratio = s2 / s1
		}
	}
	return g
}

func (g growth) label() string {
	switch {
	case g.Flat:
		return "flat (under 10% change)"
	case math.IsNaN(g.Ratio):
		return "n/a"
	case g.Ratio < 0.7:
		return "sub-linear"
	case g.Ratio <= 1.4:
		return "about linear"
	}
	return "faster than linear"
}
