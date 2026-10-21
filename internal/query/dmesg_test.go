package query

import (
	"strings"
	"testing"
	"time"
)

func TestPrintDmesg(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.UTC
	// Booted at 1000.6 s, suspended 2.7 s; the record at 5.5 s since boot.
	k := Kmsg{Prio: 12, MonoUS: 5_500_000, Msg: `two\x0alines \x5c\x01`, BootUS: 1_000_600_000, SuspUS: 2_700_000}
	recs := []Kmsg{k, {Msg: ""}, {MonoUS: 7, Caller: "T42", Msg: "x", BootUS: k.BootUS}}
	for _, c := range []struct {
		style string
		o     DmesgOptions
		want  string
	}{
		{"current", DmesgOptions{}, "[    5.500000] two\n               lines \\\\x01\n\n[    0.000007] [     T42] x\n"},
		{"rhel-9", DmesgOptions{}, "[    5.500000] two\n               lines \\\\x01\n\n[    0.000007] x\n"},
		// 2.41: 1000.6 + 2.7 + 5.5 = 1008.8; 2.37: 1000 + 2 + 5; 2.32: 1000 + 5.
		{"current", DmesgOptions{Ctime: true, Decode: true}, "user  :warn  : [Thu Jan  1 00:16:48 1970] two\n"},
		{"rhel-9", DmesgOptions{Ctime: true}, "[Thu Jan  1 00:16:47 1970] two\n"},
		{"rhel-8", DmesgOptions{Ctime: true}, "[Thu Jan  1 00:16:45 1970] two\n"},
	} {
		var sb strings.Builder
		PrintDmesg(&sb, recs, c.o, Styles[c.style])
		got := sb.String()
		if c.o.Ctime {
			got = got[:strings.Index(got, "\n")+1]
		}
		if got != c.want {
			t.Errorf("%s %+v:\n%q\nwant\n%q", c.style, c.o, got, c.want)
		}
	}
}
