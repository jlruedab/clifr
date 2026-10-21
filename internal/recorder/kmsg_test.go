package recorder

import "testing"

func TestParseKmsg(t *testing.T) {
	r, ok := parseKmsg([]byte("6,1234,38368224769,-,caller=T42;usb 1-1: new device\\x0aline two\n SUBSYSTEM=usb\n DEVICE=c189:1\n"))
	if !ok || r.Prio != 6 || r.Seq != 1234 || r.MonoUS != 38368224769 || r.Caller != "T42" || r.Msg != `usb 1-1: new device\x0aline two` {
		t.Errorf("parseKmsg: %+v %v", r, ok)
	}
	if _, ok := parseKmsg([]byte("garbage")); ok {
		t.Error("garbage parsed")
	}
}
