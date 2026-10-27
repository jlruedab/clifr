package recorder

import "testing"

func TestDropSysctlSecrets(t *testing.T) {
	in := "net.ipv6.conf.all.stable_secret = 1::2\nnet.ipv6.conf.all.use_tempaddr = 0\n" +
		"net.ipv6.conf.tun0.stable_secret = 3::4\nkernel.hostname = h\n"
	want := "net.ipv6.conf.all.use_tempaddr = 0\nkernel.hostname = h\n"
	if got := dropSysctlSecrets(in); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
