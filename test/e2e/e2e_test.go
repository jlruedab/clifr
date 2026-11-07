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
//
// TestRestart (under a minute) records in two runs on one data directory
// while a process holds 50 files throughout, and checks that clifr lsof
// lists them in either run and that no fds_held id repeats across runs.
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
	case "files":
		files()
	case "sleep":
		// Not a copy of /bin/sleep: on uutils systems (Ubuntu 26.04) that is a
		// multicall binary that dispatches on its name.
		time.Sleep(300 * time.Millisecond)
	default:
		os.Exit(m.Run())
	}
}

var held []any // keeps helper connections and files reachable

// holdForever blocks until the helper is killed. Not select {}: without cgo
// the runtime ends a process whose only goroutine blocks that way (deadlock).
func holdForever() {
	for {
		time.Sleep(time.Hour)
	}
}

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
	holdForever()
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
	holdForever()
}

func TestIncident(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: sudo go test -tags e2e ./test/e2e")
	}
	dir := t.TempDir()
	buildBins(t, dir)
	clifr := filepath.Join(dir, "clifr")
	data := filepath.Join(dir, "data")
	if keep := os.Getenv("CLIFR_E2E_KEEP"); keep != "" { // keep the data and the log for a look
		defer func() {
			exec.Command("cp", "-r", data, keep).Run()
			exec.Command("cp", filepath.Join(dir, "recorder.log"), keep).Run()
			t.Logf("data copied to %s", keep)
		}()
	}

	// Background load and the recorder.
	load := start(t, exec.Command(filepath.Join(dir, "load"), "--profile", "light"), "READY")
	defer stop(load)
	rec := exec.Command(filepath.Join(dir, "clifrd"), "--config", "/dev/null", "--data-dir", data, "--interval", "2s", "--fd-interval", "10s",
		"--redact", `e2e-secret=(\S+)`)
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
	// Secrets in command lines: a process gone before any sample (exec event)
	// and one that samples see.
	exec.Command("/bin/sh", "-c", "exit 0", "sh", "e2e-secret=TOPSECRET1").Run()
	longSecret := exec.Command("/bin/sh", "-c", "sleep 8", "sh", "e2e-secret=TOPSECRET2")
	longSecret.Start()
	defer longSecret.Wait()
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
	// Neither secret reached the recording; both processes are there, masked.
	procsCSV, err := exec.Command(clifr, "export", "processes", "--data-dir", data).Output()
	if err != nil {
		t.Fatalf("export processes: %v", err)
	}
	if bytes.Contains(procsCSV, []byte("TOPSECRET")) {
		t.Error("a redacted secret is in the processes table")
	}
	if n := bytes.Count(procsCSV, []byte("e2e-secret=***")); n < 2 {
		t.Errorf("want both secret-bearing processes recorded with the secret masked, found %d", n)
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
		t.Logf("burst %s .. %s", burstStart.Format("15:04:05.000"), burstEnd.Format("15:04:05.000"))
	}
}

// buildBins puts clifrd, clifr and the load generator in dir: built from
// this tree, or copied from CLIFR_TEST_BIN (a machine without Go, such as a
// test VM).
func buildBins(t *testing.T, dir string) {
	t.Helper()
	root, _ := filepath.Abs("../..")
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	for _, b := range []struct{ out, pkg, cgo string }{
		{"clifrd", "./cmd/clifrd", "0"}, {"clifr", "./cmd/clifr", "1"}, {"load", "./bench/load", "0"},
	} {
		if bin := os.Getenv("CLIFR_TEST_BIN"); bin != "" {
			if err := exec.Command("cp", filepath.Join(bin, b.out), dir).Run(); err != nil {
				t.Fatalf("CLIFR_TEST_BIN: %s: %v", b.out, err)
			}
			continue
		}
		cmd := exec.Command(gobin, "build", "-o", filepath.Join(dir, b.out), b.pkg)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED="+b.cgo)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", b.pkg, err, out)
		}
	}
}

// nHeld is how many regular files the "files" helper holds open.
const nHeld = 50

// files holds nHeld regular files in CLIFR_E2E_DIR open until killed.
func files() {
	dir := os.Getenv("CLIFR_E2E_DIR")
	for i := 0; i < nHeld; i++ {
		f, err := os.Create(filepath.Join(dir, fmt.Sprintf("held-%02d.log", i)))
		if err != nil {
			panic(err)
		}
		held = append(held, f)
	}
	fmt.Println("READY")
	holdForever()
}

// TestRestart records in two runs on one data directory while a process
// holds the same files throughout: clifr lsof must list them at a moment of
// either run. Until 2026-11-07 fds_held ids began at 1 in every run, so the
// second run reused the first run's ids and the first run's closed rows hid
// the second run's open files (no test restarted the recorder).
func TestRestart(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: sudo go test -tags e2e ./test/e2e")
	}
	dir := t.TempDir()
	buildBins(t, dir)
	clifr := filepath.Join(dir, "clifr")
	data := filepath.Join(dir, "data")
	heldDir := filepath.Join(dir, "held")
	os.MkdirAll(heldDir, 0o755)
	h := helper(t, "files", []string{"CLIFR_E2E_DIR=" + heldDir})
	defer stop(h.cmd)

	var mids []time.Time
	for run := 1; run <= 2; run++ {
		rec := exec.Command(filepath.Join(dir, "clifrd"), "--config", "/dev/null", "--data-dir", data,
			"--interval", "2s", "--fd-interval", "4s")
		recLog, _ := os.Create(filepath.Join(dir, fmt.Sprintf("recorder-%d.log", run)))
		rec.Stdout, rec.Stderr = recLog, recLog
		if err := rec.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Second) // two full fd walks: the files are held
		mids = append(mids, time.Now().Truncate(time.Second))
		time.Sleep(10 * time.Second)
		rec.Process.Signal(syscall.SIGTERM) // a clean stop: closes the run's rows
		if err := rec.Wait(); err != nil {
			b, _ := os.ReadFile(recLog.Name())
			t.Fatalf("run %d: %v\n%s", run, err, b)
		}
		time.Sleep(2 * time.Second) // the next run starts in a later second
	}

	for run, mid := range mids {
		var lsof []struct {
			Name string `json:"name"`
		}
		at := mid.Format("2006-01-02 15:04:05")
		query(t, clifr, &lsof, "--at", at, "--data-dir", data, "--json", "lsof", "-p", strconv.Itoa(h.cmd.Process.Pid))
		n := 0
		for _, f := range lsof {
			if strings.HasPrefix(f.Name, heldDir+"/held-") {
				n++
			}
		}
		t.Logf("run %d, at %s: lsof -p %d lists %d of the %d held files (%d rows)", run+1, at, h.cmd.Process.Pid, n, nHeld, len(lsof))
		if n != nHeld {
			t.Errorf("run %d at %s: lsof lists %d of the %d held files", run+1, at, n, nHeld)
		}
	}

	// Each held fd of each run has its own id: the recorder's half of the fix
	// (the reader keeps one row per id and first_seen, which hides reuse).
	// Over all rows: a run reuses ids of the other run's fds of any process,
	// in the order the walks meet them.
	out, err := exec.Command(clifr, "export", "fds_held", "--data-dir", data).Output()
	if err != nil {
		t.Fatalf("export fds_held: %v", err)
	}
	seen := map[string]int{}
	rows, dups := 0, 0
	for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if i == 0 {
			continue
		}
		id := strings.SplitN(line, ",", 2)[0]
		if seen[id]++; seen[id] == 2 {
			dups++
		}
		if strings.Contains(line, heldDir) {
			rows++
		}
	}
	if dups > 0 {
		t.Errorf("fds_held: %d ids used by more than one fd (of %d ids): ids repeat across runs", dups, len(seen))
	}
	if rows != 2*nHeld {
		t.Errorf("fds_held: %d rows for the held files, want %d (each file once per run)", rows, 2*nHeld)
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
