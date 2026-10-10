// Command truthproc is the helper of the ground-truth test (test/truth): it
// plays the processes whose behaviour the test knows exactly. Static, small
// and quick to start, because the test runs it thousands of times.
//
//	truthproc --id=N --sleep-ms=M --exit=C [--pad=...]   a short-lived process
//	truthproc server                 accept, read until the peer closes, close
//	truthproc rstserver              accept and abort at once (SO_LINGER 0: RST)
//	truthproc client ADDR N WORKERS MIN_MS MAX_MS OUT    N connections held MIN..MAX ms
//	truthproc rstclient ADDR N OUT   N connections to rstserver, waiting for the reset
//	truthproc refused ADDR N         N connects to a closed port
//	truthproc oom CGROUP             join the cgroup and allocate until killed
//	truthproc deleted FILE           create FILE, delete it, keep it open
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		server(false)
	case "rstserver":
		server(true)
	case "client":
		client(os.Args[2:])
	case "rstclient":
		rstClient(os.Args[2:])
	case "refused":
		refused(os.Args[2:])
	case "oom":
		oom(os.Args[2])
	case "deleted":
		deleted(os.Args[2])
	default:
		short(os.Args[1:])
	}
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "truthproc:", err)
		os.Exit(111)
	}
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	die(err)
	return n
}

// short sleeps and exits with the requested code.
func short(args []string) {
	var sleep, code int
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--sleep-ms="); ok {
			sleep = atoi(v)
		} else if v, ok := strings.CutPrefix(a, "--exit="); ok {
			code = atoi(v)
		}
	}
	time.Sleep(time.Duration(sleep) * time.Millisecond)
	os.Exit(code)
}

func server(reset bool) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	die(err)
	fmt.Println(ln.Addr().(*net.TCPAddr).Port)
	for {
		c, err := ln.Accept()
		die(err)
		if reset {
			// Not before the client's connect has returned: it would fail
			// with ECONNRESET without telling the client its port.
			time.Sleep(5 * time.Millisecond)
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
			continue
		}
		go func() {
			buf := make([]byte, 16)
			for {
				if _, err := c.Read(buf); err != nil {
					break
				}
			}
			c.Close()
		}()
	}
}

// Conn is what the client knows about one of its connections.
type Conn struct {
	LPort   int   `json:"lport"`
	DialMS  int64 `json:"dial_ms"`  // just before connect
	OpenMS  int64 `json:"open_ms"`  // connect returned
	CloseMS int64 `json:"close_ms"` // just before close
	Reset   bool  `json:"reset,omitempty"`
}

func writeConns(path string, conns []Conn) {
	f, err := os.Create(path)
	die(err)
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, c := range conns {
		die(enc.Encode(c))
	}
	die(w.Flush())
	die(f.Close())
}

func client(args []string) {
	addr, n, workers, minMS, maxMS, out := args[0], atoi(args[1]), atoi(args[2]), atoi(args[3]), atoi(args[4]), args[5]
	conns := make([]Conn, n)
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				hold := time.Duration(minMS+rand.IntN(maxMS-minMS+1)) * time.Millisecond
				c := Conn{DialMS: time.Now().UnixMilli()}
				nc, err := net.Dial("tcp4", addr)
				die(err)
				c.OpenMS = time.Now().UnixMilli()
				c.LPort = nc.LocalAddr().(*net.TCPAddr).Port
				time.Sleep(hold)
				c.CloseMS = time.Now().UnixMilli()
				nc.Close()
				conns[i] = c
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
	writeConns(out, conns)
	fmt.Println("DONE")
}

func rstClient(args []string) {
	addr, n, out := args[0], atoi(args[1]), args[2]
	conns := make([]Conn, n)
	buf := make([]byte, 1)
	for i := range conns {
		c := Conn{DialMS: time.Now().UnixMilli()}
		nc, err := net.Dial("tcp4", addr)
		die(err)
		c.OpenMS = time.Now().UnixMilli()
		c.LPort = nc.LocalAddr().(*net.TCPAddr).Port
		nc.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = nc.Read(buf)
		c.Reset = errors.Is(err, syscall.ECONNRESET)
		c.CloseMS = time.Now().UnixMilli()
		nc.Close()
		conns[i] = c
		time.Sleep(2 * time.Millisecond)
	}
	writeConns(out, conns)
	fmt.Println("DONE")
}

func refused(args []string) {
	addr, n := args[0], atoi(args[1])
	got := 0
	for i := 0; i < n; i++ {
		nc, err := net.Dial("tcp4", addr)
		if errors.Is(err, syscall.ECONNREFUSED) {
			got++
		} else if err == nil {
			nc.Close()
		}
		time.Sleep(2 * time.Millisecond)
	}
	fmt.Println(got)
}

var (
	hog  [][]byte
	held *os.File
)

func oom(cgroup string) {
	die(os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644))
	fmt.Println("READY")
	for {
		b := make([]byte, 1<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		hog = append(hog, b)
		time.Sleep(5 * time.Millisecond)
	}
}

func deleted(path string) {
	f, err := os.Create(path)
	die(err)
	f.WriteString("ground truth\n")
	die(os.Remove(path))
	held = f
	fmt.Println("READY")
	for {
		time.Sleep(time.Hour)
	}
}
