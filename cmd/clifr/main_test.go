package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestSplitWords(t *testing.T) {
	for in, want := range map[string]string{
		`ps aux`:                                     `[ps aux]`,
		`  ss  -tanp   dport = :5432 `:               `[ss -tanp dport = :5432]`,
		`life --name 'backup|rsync'`:                 `[life --name backup|rsync]`,
		`life --name "a b\"c"`:                       `[life --name a b"c]`,
		`ss -tn dst 10.0.0.1\ and`:                   `[ss -tn dst 10.0.0.1 and]`,
		`ss -tanp 'dst 10.0.4.21 and dport = :5432'`: `[ss -tanp dst 10.0.4.21 and dport = :5432]`,
	} {
		got, err := splitWords(in)
		if err != nil || fmt.Sprint(got) != want {
			t.Errorf("%q: %v %v, want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{`ps 'aux`, `ps "aux`} {
		if _, err := splitWords(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestParseOpts(t *testing.T) {
	ss := tools["ss"].opts
	p, err := parseOpts("ss", ss, []string{"-tanp", "--ipv4", "dport", "=", ":22"})
	if err != nil || !p.has("tcp") || !p.has("all") || !p.has("numeric") || !p.has("processes") || !p.has("ipv4") ||
		fmt.Sprint(p.pos) != "[dport = :22]" {
		t.Errorf("ss: %+v %v", p, err)
	}
	lsof := tools["lsof"].opts
	for _, args := range [][]string{{"-p", "42"}, {"-p42"}, {"-nPp", "42"}, {"-nPp42"}} {
		if p, err := parseOpts("lsof", lsof, args); err != nil || p.set["p"] != "42" {
			t.Errorf("lsof %v: %+v %v", args, p, err)
		}
	}
	for _, c := range []struct {
		tool string
		args []string
		want string
	}{
		{"ss", []string{"-tx"}, "option -x is not supported"},
		{"ss", []string{"--extended"}, "option --extended is not supported"},
		{"lsof", []string{"-p"}, "-p needs PID"},
		{"ss", []string{"--tcp=1"}, "--tcp takes no argument"},
	} {
		_, err := parseOpts(c.tool, tools[c.tool].opts, c.args)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %v: %v, want %q", c.tool, c.args, err, c.want)
		}
	}
}

// Errors that must come before the recording is opened (no data dir here).
func TestRunErrors(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{}, "no command given"},
		{[]string{"--at", "now", "ps -efx"}, "option -x is not supported"},
		{[]string{"--at", "now", "sar"}, `"sar" is not a supported command`},
		{[]string{"ps", "aux", "--at", "now"}, "go before the command"},
		{[]string{"--at", "now", "ps aux", "extra"}, "unexpected \"extra\""},
		{[]string{"ps aux"}, "--at or --since is required"},
		{[]string{"--at", "now", "--since", "today", "ps aux"}, "either --at or --since"},
		{[]string{"--at", "soon", "ps aux"}, "bad time"},
		{[]string{"--since", "today", "--until", "yesterday", "ps aux"}, "is not after"},
		{[]string{"--at", "now", "--samples", "vmstat"}, "need a range"},
		{[]string{"--since", "-1h", "--changes", "vmstat"}, "--changes is not available for vmstat"},
		{[]string{"--at", "now", "vmstat 5"}, "an interval needs a range"},
		{[]string{"--at", "now", "--list", "netstat -nt"}, "need a range"},
		{[]string{"--since", "-1h", "--list", "--samples", "ss -tn"}, "use one of"},
		{[]string{"--since", "-1h", "--list", "ps aux"}, "--list is for ss and netstat"},
		{[]string{"--at", "now", "ss -an"}, "add -t and/or -u"},
		{[]string{"--host", "x", "--at", "now", "ps aux"}, "--host needs a token"}, // no production key: the gate is dormant
		{[]string{"--host", "x", "--token", "t", "--data-dir", "/tmp", "--at", "now", "ps aux"}, "--host and --data-dir: give one"},
		{[]string{"--tls-ca", "f", "--at", "now", "ps aux"}, "--tls-ca is for --host"},
		{[]string{"--host", "x", "--tls-ca", "f", "--tls-fingerprint", "SHA256:x", "--at", "now", "ps aux"}, "give one"},
		{[]string{"--tls-fingerprint", "SHA256:x", "--at", "now", "ps aux"}, "--tls-fingerprint is for --host"},
		{[]string{"--at", "now", "-T", "Nowhere/City", "ps aux"}, "--tz"},
		{[]string{"--at", "now", "mount /dev/sda1 /mnt"}, "only listing"},
		{[]string{"--at", "now", "df var"}, "absolute path"},
		{[]string{"--since", "-1h", "df"}, "add --samples"},
		{[]string{"--at", "now", "netstat -ta"}, "add -n"},
		{[]string{"--at", "now", "ps"}, "add -e, -p, -u or -C"},
		{[]string{"--at", "now", "ps -o pid,blocked -e"}, "unsupported output column"},
		{[]string{"--at", "now", "ps alxf"}, "BSD forms supported"},
		{[]string{"--at", "now", "free -s 5"}, "need a range"},
		{[]string{"--since", "-1h", "free"}, "add --samples"},
		{[]string{"--at", "now", "events"}, "needs a range"},
		{[]string{"list", "ps"}, "clifr help"},
		{[]string{"diff", "--at", "10:00", "--at", "11:00", "vmstat"}, "no rows to compare"},
		{[]string{"diff", "--at", "11:00", "--at", "10:00", "ps -e"}, "must be after"},
		{[]string{"diff", "--at", "10:00", "ps -e"}, "usage: clifr diff"},
		{[]string{"--at", "10:00", "--at", "11:00", "ps -e"}, "more than once"},
	} {
		err := run(c.args)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.args, err, c.want)
		}
	}
}
