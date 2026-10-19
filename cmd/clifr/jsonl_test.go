package main

import "testing"

func TestJSONLine(t *testing.T) {
	type row struct {
		TS   int64  `json:"ts_ms"`
		A    int    `json:"a"`
		B    string `json:"b,omitempty"`
		hide int
	}
	for _, c := range []struct {
		row  any
		m    rowMeta
		with bool
		want string
	}{
		{row{A: 1}, rowMeta{TS: 5, SampleTS: 4, Sampled: []string{"a", "b"}}, true,
			`{"sample_ts_ms":4,"ts_ms":0,"a":1,"sampled":["a"]}`}, // the row's own ts_ms wins; b is absent
		{row{TS: 7, A: 1, B: "x"}, rowMeta{From: 1, To: 2}, true, `{"from_ms":1,"to_ms":2,"ts_ms":7,"a":1,"b":"x","sampled":[]}`},
		{struct{}{}, rowMeta{TS: 3}, false, `{"ts_ms":3}`},
		{struct{}{}, rowMeta{}, true, `{"sampled":[]}`},
	} {
		b, err := jsonLine(c.row, c.m, c.with)
		if err != nil || string(b) != c.want {
			t.Errorf("%+v: %s %v, want %s", c.row, b, err, c.want)
		}
	}
	if k := jsonKeys(row{}, "ts_ms"); len(k) != 2 || k[0] != "a" || k[1] != "b" {
		t.Errorf("jsonKeys: %v", k)
	}
}
