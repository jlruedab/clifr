package query

import (
	"regexp"
	"strings"
	"testing"
)

func TestSysctlSelect(t *testing.T) {
	all := []SysctlLine{{"dev.cdrom.info", "CD-ROM information"}, {"dev.cdrom.info", ""}, {"net.ipv4.ip_forward", "1"},
		{"net.ipv4.conf.all.forwarding", "1"}, {"vm.swappiness", "60"}}
	for _, c := range []struct {
		o    SysctlOptions
		want string
		err  bool
	}{
		{SysctlOptions{}, "dev.cdrom.info = CD-ROM information\ndev.cdrom.info = \nnet.ipv4.ip_forward = 1\nnet.ipv4.conf.all.forwarding = 1\nvm.swappiness = 60\n", false},
		{SysctlOptions{Keys: []string{"vm.swappiness", "net/ipv4/ip_forward"}, Values: true}, "60\n1\n", false},
		{SysctlOptions{Keys: []string{"net.ipv4.conf"}}, "net.ipv4.conf.all.forwarding = 1\n", false},
		{SysctlOptions{Names: true, Pattern: regexp.MustCompile("cdrom")}, "dev.cdrom.info\n", false},
		{SysctlOptions{Keys: []string{"no.such"}}, "", true},
		{SysctlOptions{Keys: []string{"no.such", "vm.swappiness"}, IgnoreUnknown: true}, "vm.swappiness = 60\n", false},
	} {
		sel, err := SelectSysctl(all, c.o)
		var b strings.Builder
		PrintSysctl(&b, sel, c.o)
		if b.String() != c.want || (err != nil) != c.err {
			t.Errorf("%+v: %q %v, want %q (error %v)", c.o, b.String(), err, c.want, c.err)
		}
	}
}
