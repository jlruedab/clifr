package store

import (
	"net/netip"
	"reflect"
	"testing"
)

// pointerFree reports a field of t that holds a pointer (strings, slices,
// maps and interfaces included), or "".
func pointerFree(t reflect.Type, path string) string {
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if p := pointerFree(t.Field(i).Type, path+"."+t.Field(i).Name); p != "" {
				return p
			}
		}
		return ""
	case reflect.Array:
		return pointerFree(t.Elem(), path+"[]")
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return ""
	}
	return path + " (" + t.Kind().String() + ")"
}

// The rows the recorder holds by the tens of thousands stay pointer-free,
// and TCPConn within the 128-byte allocation size class.
func TestCompactRows(t *testing.T) {
	for _, v := range []any{TCPConn{}, KeyframeRow{}} {
		if p := pointerFree(reflect.TypeOf(v), reflect.TypeOf(v).Name()); p != "" {
			t.Errorf("%s holds a pointer", p)
		}
	}
	if n := reflect.TypeOf(TCPConn{}).Size(); n > 128 {
		t.Errorf("TCPConn is %d bytes, more than 128", n)
	}
}

func TestAddr(t *testing.T) {
	for _, c := range []struct {
		family int
		ip     string
	}{{4, "127.0.0.1"}, {4, "0.0.0.0"}, {6, "::"}, {6, "::1"}, {6, "::ffff:10.1.2.3"}, {6, "fe80::1"}} {
		ip := netip.MustParseAddr(c.ip)
		a := AddrOf(ip)
		if got := a.String(c.family); got != ip.String() {
			t.Errorf("%s (family %d) prints as %q", c.ip, c.family, got)
		}
		if a.IP(c.family) != ip {
			t.Errorf("%s (family %d): IP %v", c.ip, c.family, a.IP(c.family))
		}
	}
	if s := (Addr{}).String(0); s != "" {
		t.Errorf("unset address prints as %q", s)
	}
}

func TestNames(t *testing.T) {
	if NameOf("") != 0 || Name(0).String() != "" {
		t.Error("empty name")
	}
	a, b := NameOf("eth0"), NameOf("lo")
	if a == b || NameOf("eth0") != a || a.String() != "eth0" || b.String() != "lo" {
		t.Errorf("eth0 %d lo %d", a, b)
	}
}
