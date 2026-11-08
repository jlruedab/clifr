package metrics

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"clifr/internal/webconfig"
	"clifr/internal/webconfig/webtest"
)

// /metrics over TLS with basic authentication, through Listen and Serve.
func TestMetricsTLS(t *testing.T) {
	p := webtest.New(t)
	web, err := webconfig.New("metrics", p.Config(t, webtest.TLSServer+"basic_auth_users:\n  prom: "+webtest.Hash(t, "pw")+"\n"), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", web)
	if err != nil {
		t.Fatal(err)
	}
	srv := Serve(ln, func() *Snapshot { return testSnapshot() }, web)
	defer srv.Close()
	url := "https://" + ln.Addr().String() + "/metrics"
	c := p.Client("")
	resp, err := c.Get(url)
	if err != nil || resp.StatusCode != 401 {
		t.Fatalf("no password: %v %v", resp, err)
	}
	resp.Body.Close()
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth("prom", "pw")
	if resp, err = c.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("with the password: %v %v", resp, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "clifr_build_info") {
		t.Errorf("body: %.100s", b)
	}
}

func TestCheckAddrTLS(t *testing.T) {
	for _, c := range []struct {
		addr    string
		withTLS bool
		ok      bool
	}{{":9100", true, true}, {"192.0.2.7:9100", true, true}, {":9100", false, false}, {"192.0.2.7:9100", false, false},
		{"127.0.0.1:9100", false, true}, {"host.example:9100", true, false}} {
		if _, err := CheckAddr(c.addr, c.withTLS); (err == nil) != c.ok {
			t.Errorf("%s TLS %v: %v", c.addr, c.withTLS, err)
		}
	}
}
