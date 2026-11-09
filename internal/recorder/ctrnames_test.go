package recorder

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainerNames(t *testing.T) {
	dir := t.TempDir()
	id := func(c byte) string { return strings.Repeat(string(c), 64) }
	// Kubernetes: the kubelet's log links (names only; their targets do not exist).
	k8sLogDir = filepath.Join(dir, "containers")
	os.MkdirAll(k8sLogDir, 0o755)
	os.Symlink("/nonexistent", filepath.Join(k8sLogDir, "web-7d4b9-x2x9z_shop_nginx-"+id('a')+".log"))
	os.Symlink("/nonexistent", filepath.Join(k8sLogDir, "README"))
	// Docker: a fake API on a Unix socket. It also sends an Env, which an
	// inspect call would: it must not be stored.
	dockerSocket = filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", dockerSocket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" || r.Method != http.MethodGet {
			http.Error(w, "unexpected", 400)
			return
		}
		w.Write([]byte(`[{"Id":"` + id('b') + `","Names":["/redis-1"],"Image":"redis:7","Env":["PASSWORD=secret"],
			"Labels":{"com.docker.compose.project":"shop"}}]`))
	})}
	go srv.Serve(ln)
	defer srv.Close()
	// Podman: its storage's container list.
	podmanStore = filepath.Join(dir, "containers.json")
	os.WriteFile(podmanStore, []byte(`[{"id":"`+id('c')+`","names":["db"],"metadata":"{\"image-name\":\"docker.io/library/postgres:16\",\"name\":\"db\"}"}]`), 0o600)

	r := &Recorder{ctrNew: true}
	lines, err := r.readContainerNames()
	if err != nil || r.ctrNew {
		t.Fatalf("%v (ctrNew %v)", err, r.ctrNew)
	}
	got := map[string]string{}
	for _, l := range lines {
		got[l.Key] = l.Line
	}
	for k, want := range map[string]string{
		id('a'): "kubernetes\tnginx\t\tweb-7d4b9-x2x9z\tshop\t",
		id('b'): "docker\tredis-1\tredis:7\t\t\tshop",
		id('c'): "podman\tdb\tdocker.io/library/postgres:16\t\t\t",
	} {
		if got[k] != want {
			t.Errorf("%s...: %q, want %q", k[:4], got[k], want)
		}
	}
	if len(lines) != 3 {
		t.Errorf("%d lines: %v", len(lines), got)
	}
	for _, l := range lines {
		if strings.Contains(l.Line, "secret") {
			t.Errorf("an environment value was stored: %q", l.Line)
		}
	}
	// A new container in a process's cgroup asks for the names again.
	r.noteContainer("0::/system.slice/docker-" + id('d') + ".scope")
	if !r.ctrNew {
		t.Error("a new container did not trigger a read")
	}
	r.ctrNew = false
	r.noteContainer("0::/system.slice/docker-" + id('d') + ".scope")
	if r.ctrNew {
		t.Error("a known container triggered a read")
	}
}
