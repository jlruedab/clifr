//go:build e2e

// Package e2e runs clifr end to end against a scripted incident, as root,
// in about 3 minutes:
//
//	sudo go test -tags e2e -v -count=1 ./test/e2e
//
// It builds clifrd, clifr and the load generator, starts the light load
// profile and clifrd --interval 2s writing Parquet, then stages an
// incident:
//   - a client process opens 150 connections to a local server and holds them,
//   - a process holds a file that has been deleted,
//   - a burst of 20 sub-second processes (a copy of this test binary named
//     e2eburst, in its "sleep" helper mode).
//
// Afterwards it checks that clifr ss, clifr lsof and clifr life (reading the
// Parquet files through DuckDB) each find their part of the incident at the
// right moment.
package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	nConns = 150
	nBurst = 20
)

// TestMain doubles as the helper processes of the incident.
func TestMain(m *testing.M) {
	switch os.Getenv("CLIFR_E2E_HELPER") {
	case "server":
		server()
	case "client":
		client()
	case "deleted":
		deleted()
	case "sleep":
		// Not a copy of /bin/sleep: on uutils systems (Ubuntu 26.04) that is a
		// multicall binary that dispatches on its name.
		time.Sleep(300 * time.Millisecond)
	default:
		os.Exit(m.Run())
	}
}

var held []any // keeps helper connections and files reachable

func server() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Println(ln.Addr().(*net.TCPAddr).Port)
	for {
		c, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		held = append(held, c)
	}
}

func client() {
	addr := "127.0.0.1:" + os.Getenv("CLIFR_E2E_PORT")
	for i := 0; i < nConns; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			panic(err)
		}
		held = append(held, c)
	}
	fmt.Println("READY")
	select {}
}

func deleted() {
	path := os.Getenv("CLIFR_E2E_FILE")
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	f.WriteString("incident evidence\n")
	if err := os.Remove(path); err != nil {
		panic(err)
	}
	held = append(held, f)
	fmt.Println("READY")
	select {}
}

func TestIncident(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: sudo go test -tags e2e ./test/e2e")
	}
	dir := t.TempDir()
	root, _ := filepath.Abs("../..")
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	for _, b := range []struct{ out, pkg, cgo string }{
		{"clifrd", "./cmd/clifrd", "0"}, {"clifr", "./cmd/clifr", "1"}, {"load", "./bench/load", "0"},
	} {
		cmd := exec.Command(gobin, "build", "-o", filepath.Join(dir, b.out), b.pkg)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED="+b.cgo)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", b.pkg, err, out)
		}
	}
	clifr := filepath.Join(dir, "clifr")
	data := filepath.Join(dir, "data")

	// Background load and the recorder.
	load := start(t, exec.Command(filepath.Join(dir, "load"), "--profile", "light"), "READY")
	defer stop(load)
	rec := exec.Command(filepath.Join(dir, "clifrd"), "--config", "/dev/null", "--data-dir", data, "--interval", "2s", "--fd-interval", "10s")
	recLog, _ := os.Create(filepath.Join(dir, "recorder.log"))
	rec.Stdout, rec.Stderr = recLog, recLog
	if err := rec.Start(); err != nil {
		t.Fatal(err)
	}
	defer rec.Process.Kill()
	t.Log("recording; waiting 20 s before the incident")
	time.Sleep(20 * time.Second)

	// The incident.
	srv := helper(t, "server", nil)
	defer stop(srv.cmd)
	port := srv.first
	cli := helper(t, "client", []string{"CLIFR_E2E_PORT=" + port})
	defer stop(cli.cmd)
	delPath := filepath.Join(dir, "evidence.log")
	del := helper(t, "deleted", []string{"CLIFR_E2E_FILE=" + delPath})
	defer stop(del.cmd)
	t.Logf("incident: server pid %d port %s, client pid %d (%d conns), deleted-file pid %d",
		srv.cmd.Process.Pid, port, cli.cmd.Process.Pid, nConns, del.cmd.Process.Pid)

	time.Sleep(30 * time.Second) // several samples and at least two full fd walks
	burst := filepath.Join(dir, "e2eburst")
	exe, _ := os.Executable()
	copyFile(t, exe, burst)
	burstStart := time.Now()
	var procs []*exec.Cmd
	for i := 0; i < nBurst; i++ {
		c := exec.Command(burst)
		c.Env = append(os.Environ(), "CLIFR_E2E_HELPER=sleep")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		procs = append(procs, c)
		time.Sleep(50 * time.Millisecond)
	}
	for _, c := range procs {
		c.Wait()
	}
	burstEnd := time.Now()
	time.Sleep(15 * time.Second)
	checkAt := time.Now().Add(-5 * time.Second).Truncate(time.Second) // inside the incident, between samples
	time.Sleep(30 * time.Second)

	stop(cli.cmd)
	stop(srv.cmd)
	stop(del.cmd)
	time.Sleep(10 * time.Second)
	rec.Process.Signal(syscall.SIGTERM)
	if err := rec.Wait(); err != nil {
		t.Fatalf("recorder: %v (log in %s)", err, recLog.Name())
	}
	stop(load)

	at := checkAt.Format("2006-01-02 15:04:05")

	// 1. The 150 held connections, from the client and from the server side.
	var ss []struct {
		State  string `json:"state"`
		LPort  int    `json:"lport"`
		RPort  int    `json:"rport"`
		Owners []struct {
			PID int `json:"pid"`
		} `json:"owners"`
	}
	query(t, clifr, &ss, "--at", at, "--data-dir", data, "--json", "ss", "-tanp", "dport", "=", ":"+port)
	clientConns := 0
	for _, s := range ss {
		if s.State == "ESTAB" && len(s.Owners) > 0 && s.Owners[0].PID == cli.cmd.Process.Pid {
			clientConns++
		}
	}
	query(t, clifr, &ss, "--at", at, "--data-dir", data, "--json", "ss", "-tanp", "sport", "=", ":"+port)
	serverConns := 0
	for _, s := range ss {
		if s.State == "ESTAB" && len(s.Owners) > 0 && s.Owners[0].PID == srv.cmd.Process.Pid {
			serverConns++
		}
	}
	t.Logf("ss at %s: %d client-side and %d server-side ESTAB connections on port %s", at, clientConns, serverConns, port)
	if clientConns != nConns || serverConns != nConns {
		t.Errorf("want %d connections on each side, got client %d, server %d", nConns, clientConns, serverConns)
	}

	// 2. The deleted-but-open file.
	var lsof []struct {
		FD      string `json:"fd"`
		Name    string `json:"name"`
		Deleted bool   `json:"deleted"`
	}
	query(t, clifr, &lsof, "--at", at, "--data-dir", data, "--json", "lsof", "-p", strconv.Itoa(del.cmd.Process.Pid))
	found := false
	for _, f := range lsof {
		if f.Deleted && strings.HasPrefix(f.Name, delPath) {
			found = true
			t.Logf("lsof at %s: fd %s %s", at, f.FD, f.Name)
		}
	}
	if !found {
		t.Errorf("lsof -p %d at %s: no deleted %s among %d rows", del.cmd.Process.Pid, at, delPath, len(lsof))
	}

	// 3. The burst of sub-second processes.
	var life []struct {
		Duration int64  `json:"duration_ms"`
		PID      int    `json:"pid"`
		Command  string `json:"command"`
		Source   string `json:"source"`
		EndKind  string `json:"end_kind"`
	}
	// Anchored: other command lines may mention the name (e.g. a shell running this test).
	query(t, clifr, &life, "--since", burstStart.Add(-2*time.Second).Format("2006-01-02 15:04:05"),
		"--until", burstEnd.Add(2*time.Second).Format("2006-01-02 15:04:05"), "--data-dir", data, "--json",
		"life", "--name", `^\S*/e2eburst$`)
	short := 0
	for _, l := range life {
		if l.Duration > 0 && l.Duration < 1000 {
			short++
		}
	}
	if len(life) > 0 {
		t.Logf("life: %d e2eburst processes, %d shorter than 1 s; e.g. pid %d %d ms (%s, %s)",
			len(life), short, life[0].PID, life[0].Duration, life[0].Source, life[0].EndKind)
	}
	if len(life) != nBurst || short != nBurst {
		t.Errorf("want %d sub-second e2eburst processes, got %d (%d sub-second)", nBurst, len(life), short)
		for _, l := range life {
			t.Logf("  pid %d %d ms %s %s: %s", l.PID, l.Duration, l.Source, l.EndKind, l.Command)
		}
		var all []struct {
			Duration int64  `json:"duration_ms"`
			PID      int    `json:"pid"`
			Command  string `json:"command"`
			Source   string `json:"source"`
			EndKind  string `json:"end_kind"`
		}
		query(t, clifr, &all, "--data-dir", data, "--json", "life", "--name", "e2eburst")
		for _, l := range all {
			if !strings.Contains(l.Command, "TestIncident") || strings.HasSuffix(l.Command, "/e2eburst") {
				t.Logf("  any: pid %d %d ms %s %s: %.80s", l.PID, l.Duration, l.Source, l.EndKind, l.Command)
			}
		}
		if b, err := os.ReadFile(recLog.Name()); err == nil {
			t.Logf("recorder log:\n%s", b)
		}
		if out, err := exec.Command(clifr, "info", "--data-dir", data).CombinedOutput(); err == nil {
			t.Logf("stats:\n%s", out)
		}
		if keep := os.Getenv("CLIFR_E2E_KEEP"); keep != "" { // keep the data for a look
			exec.Command("cp", "-r", data, keep).Run()
			t.Logf("data copied to %s; burst %s .. %s", keep, burstStart.Format("15:04:05.000"), burstEnd.Format("15:04:05.000"))
		}
	}
}

type helperProc struct {
	cmd   *exec.Cmd
	first string // first line of its output
}

// helper starts this test binary as an incident helper and waits for its
// first output line.
func helper(t *testing.T, kind string, env []string) helperProc {
	t.Helper()
	exe, _ := os.Executable()
	cmd := exec.Command(exe)
	cmd.Env = append(append(os.Environ(), "CLIFR_E2E_HELPER="+kind), env...)
	line := startLine(t, cmd)
	return helperProc{cmd, line}
}

// start runs cmd and waits until a stdout line contains want.
func start(t *testing.T, cmd *exec.Cmd, want string) *exec.Cmd {
	t.Helper()
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if strings.Contains(sc.Text(), want) {
			go io.Copy(io.Discard, out)
			return cmd
		}
	}
	t.Fatalf("%s exited before printing %q", cmd.Path, want)
	return nil
}

func startLine(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(out)
	if !sc.Scan() {
		t.Fatalf("helper %v printed nothing", cmd.Env[len(cmd.Env)-1])
	}
	go io.Copy(io.Discard, out)
	return strings.TrimSpace(sc.Text())
}

func stop(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil || cmd.ProcessState != nil {
		return
	}
	cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		<-done
	}
}

func query(t *testing.T, clifr string, v any, args ...string) {
	t.Helper()
	cmd := exec.Command(clifr, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("clifr %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	if err := decodeLines(out, v); err != nil {
		t.Fatalf("clifr %s: bad JSON: %v\n%.300s", strings.Join(args, " "), err, out)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

// decodeLines reads clifr's JSON Lines into v: a pointer to a slice gets
// every line, anything else the single line.
func decodeLines(out []byte, v any) error {
	out = bytes.TrimSpace(out)
	if reflect.TypeOf(v).Elem().Kind() != reflect.Slice {
		return json.Unmarshal(out, v)
	}
	if len(out) == 0 {
		out = []byte("[]")
	} else {
		out = append(append([]byte("["), bytes.ReplaceAll(out, []byte("\n"), []byte(","))...), ']')
	}
	return json.Unmarshal(out, v)
}
