// Command load reproduces a busy server's process, file and connection
// profile so sosv's cost can be measured the same way on any machine:
//
//   - N long-lived processes, each holding open files (total F fds)
//   - K concurrent TCP connections between local clients and servers,
//     with C new connections per second (each replacing an old one)
//   - E short-lived processes per second, each living 50-500 ms
//
// It prints "READY" on stdout once the steady state is reached, then a
// stats line every 5 s on stderr, and exits on SIGINT/SIGTERM or after
// --duration. The real workload (pgbench) is run separately by bench/run.sh.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Profile struct {
	Procs     int     `json:"procs"`      // long-lived processes
	FDs       int     `json:"fds"`        // total open files they hold
	Conns     int     `json:"conns"`      // concurrent TCP connections
	ConnChurn float64 `json:"conn_churn"` // new connections per second
	Spawn     float64 `json:"spawn"`      // short-lived processes per second
	Workers   int     `json:"workers"`    // server and client worker processes (each)
}

var profiles = map[string]Profile{
	"light":   {Procs: 200, FDs: 5000, Conns: 1000, ConnChurn: 50, Spawn: 5, Workers: 2},
	"busy":    {Procs: 2000, FDs: 50000, Conns: 20000, ConnChurn: 500, Spawn: 50, Workers: 4},
	"extreme": {Procs: 10000, FDs: 250000, Conns: 100000, ConnChurn: 2500, Spawn: 250, Workers: 8},
}

const basePort = 30000

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "server": // internal roles, started by the main process
			serverMain(os.Args[2:])
			return
		case "client":
			clientMain(os.Args[2:])
			return
		}
	}
	profile := flag.String("profile", "busy", "light, busy or extreme")
	procs := flag.Int("procs", -1, "override: long-lived processes")
	fds := flag.Int("fds", -1, "override: total open files held by them")
	conns := flag.Int("conns", -1, "override: concurrent TCP connections")
	churn := flag.Float64("conn-churn", -1, "override: new connections per second")
	spawn := flag.Float64("spawn", -1, "override: short-lived processes per second")
	workers := flag.Int("workers", -1, "override: server/client worker processes")
	duration := flag.Duration("duration", 0, "stop after this long (0 = until signalled)")
	dir := flag.String("dir", "", "directory for the files held open (default: a temp dir)")
	statsFile := flag.String("stats", "", "append achieved rates as CSV to this file")
	flag.Parse()

	p, ok := profiles[*profile]
	if !ok {
		log.Fatalf("unknown profile %q", *profile)
	}
	override := func(dst *int, v int) {
		if v >= 0 {
			*dst = v
		}
	}
	override(&p.Procs, *procs)
	override(&p.FDs, *fds)
	override(&p.Conns, *conns)
	override(&p.Workers, *workers)
	if *churn >= 0 {
		p.ConnChurn = *churn
	}
	if *spawn >= 0 {
		p.Spawn = *spawn
	}
	p.Workers = max(p.Workers, 1)
	raiseNofile()
	b, _ := json.Marshal(p)
	log.SetPrefix("load: ")
	log.Printf("profile %s %s", *profile, b)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	if err := run(ctx, p, *dir, *statsFile); err != nil {
		log.Fatal(err)
	}
}

func raiseNofile() {
	var r syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r)
	r.Cur = r.Max
	syscall.Setrlimit(syscall.RLIMIT_NOFILE, &r)
}

// children tracks every long-running child so they can be stopped together.
type children struct {
	mu   sync.Mutex
	cmds []*exec.Cmd
}

// dieWithParent makes a child receive SIGKILL if the load generator dies,
// so an aborted benchmark never leaves thousands of processes behind.
func dieWithParent(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

func (c *children) add(cmd *exec.Cmd) {
	c.mu.Lock()
	c.cmds = append(c.cmds, cmd)
	c.mu.Unlock()
}

func (c *children) stopAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cmd := range c.cmds {
		cmd.Process.Signal(syscall.SIGTERM)
	}
	for _, cmd := range c.cmds {
		cmd.Wait()
	}
}

func run(ctx context.Context, p Profile, dir, statsFile string) error {
	if dir == "" {
		d, err := os.MkdirTemp("", "sosv-load-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(d)
		dir = d
	}
	var kids children
	defer kids.stopAll()

	t0 := time.Now()
	if err := startHolders(p, dir, &kids); err != nil {
		return fmt.Errorf("holders: %w", err)
	}
	log.Printf("%d holder processes with %d open files started in %s", p.Procs, p.FDs, time.Since(t0).Round(time.Millisecond))

	t0 = time.Now()
	clientStats, err := startConns(ctx, p, &kids)
	if err != nil {
		return fmt.Errorf("connections: %w", err)
	}
	log.Printf("%d connections established in %s", p.Conns, time.Since(t0).Round(time.Millisecond))

	var spawned, spawnFail atomic.Int64
	go spawnLoop(ctx, p.Spawn, &spawned, &spawnFail)
	fmt.Println("READY")

	var csv io.Writer
	if statsFile != "" {
		f, err := os.OpenFile(statsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		csv = f
		if st, _ := f.Stat(); st.Size() == 0 {
			fmt.Fprintln(f, "ts,conns_open,conns_new_per_s,conn_errors,spawned_per_s,spawn_errors")
		}
	}
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	var lastNew, lastSpawn int64
	for {
		select {
		case <-ctx.Done():
			log.Printf("stopping")
			return nil
		case now := <-tick.C:
			open, newTotal, errs := clientStats.totals()
			sp := spawned.Load()
			line := fmt.Sprintf("%d,%d,%.1f,%d,%.1f,%d", now.Unix(), open, float64(newTotal-lastNew)/5,
				errs, float64(sp-lastSpawn)/5, spawnFail.Load())
			lastNew, lastSpawn = newTotal, sp
			log.Printf("conns_open,new/s,errors,spawned/s,spawn_errors: %s", line[len(strconv.FormatInt(now.Unix(), 10))+1:])
			if csv != nil {
				fmt.Fprintln(csv, line)
			}
		}
	}
}

// startHolders starts p.Procs `sleep infinity` processes that each inherit a
// share of p.FDs open files. sleep is used because it is tiny, so thousands
// of them fit in memory; the files are spread over 1,000 distinct paths.
func startHolders(p Profile, dir string, kids *children) error {
	if p.Procs == 0 {
		return nil
	}
	const distinct = 1000
	files := make([]*os.File, distinct)
	for i := range files {
		f, err := os.Create(filepath.Join(dir, fmt.Sprintf("data-%04d.log", i)))
		if err != nil {
			return err
		}
		f.WriteString("sosv load file\n")
		files[i] = f
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		return err
	}
	for i := 0; i < p.Procs; i++ {
		n := p.FDs / p.Procs
		if i < p.FDs%p.Procs {
			n++
		}
		cmd := exec.Command(sleep, "infinity")
		dieWithParent(cmd)
		for j := 0; j < n; j++ {
			cmd.ExtraFiles = append(cmd.ExtraFiles, files[(i*31+j)%distinct])
		}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("holder %d: %w", i, err)
		}
		kids.add(cmd)
	}
	return nil
}

// startConns starts server workers (each listening on its own ports) and
// client workers that hold K connections and churn C/s between them.
func startConns(ctx context.Context, p Profile, kids *children) (*clientSet, error) {
	if p.Conns == 0 {
		return &clientSet{}, nil
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// Each (client IP, server port) pair offers ~28k ephemeral ports; use
	// several loopback addresses and ports so K and churn fit with room for
	// TIME-WAIT.
	ports := max(4, p.Conns/5000+1)
	for w := 0; w < p.Workers; w++ {
		var list []string
		for port := w; port < ports; port += p.Workers {
			list = append(list, strconv.Itoa(basePort+port))
		}
		if len(list) == 0 {
			continue
		}
		cmd := exec.Command(self, "server", joinComma(list))
		dieWithParent(cmd)
		cmd.Stderr = os.Stderr
		out, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		kids.add(cmd)
		if line, _ := bufio.NewReader(out).ReadString('\n'); line != "LISTENING\n" {
			return nil, fmt.Errorf("server worker failed to start")
		}
	}
	set := &clientSet{}
	for w := 0; w < p.Workers; w++ {
		conns := p.Conns / p.Workers
		if w < p.Conns%p.Workers {
			conns++
		}
		churn := p.ConnChurn / float64(p.Workers)
		cmd := exec.Command(self, "client", strconv.Itoa(conns), strconv.FormatFloat(churn, 'f', 3, 64),
			strconv.Itoa(ports), strconv.Itoa(w))
		dieWithParent(cmd)
		cmd.Stderr = os.Stderr
		out, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		kids.add(cmd)
		c := &clientProc{}
		set.procs = append(set.procs, c)
		r := bufio.NewReader(out)
		if line, err := r.ReadString('\n'); err != nil || line != "CONNECTED\n" {
			return nil, fmt.Errorf("client worker %d failed: %q %v", w, line, err)
		}
		go c.follow(r)
	}
	return set, nil
}

func joinComma(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}

// clientProc follows "open new errors" lines from one client worker.
type clientProc struct {
	open, new, errs atomic.Int64
}

func (c *clientProc) follow(r *bufio.Reader) {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		var o, n, e int64
		if _, err := fmt.Sscan(line, &o, &n, &e); err == nil {
			c.open.Store(o)
			c.new.Store(n)
			c.errs.Store(e)
		}
	}
}

type clientSet struct{ procs []*clientProc }

func (s *clientSet) totals() (open, new, errs int64) {
	for _, c := range s.procs {
		open += c.open.Load()
		new += c.new.Load()
		errs += c.errs.Load()
	}
	return
}

// spawnLoop starts `sleep` processes living 50-500 ms at the given rate.
func spawnLoop(ctx context.Context, rate float64, spawned, failed *atomic.Int64) {
	if rate <= 0 {
		return
	}
	sleep, _ := exec.LookPath("sleep")
	interval := time.Duration(float64(time.Second) / rate)
	next := time.Now()
	for ctx.Err() == nil {
		next = next.Add(interval)
		life := 0.05 + rand.Float64()*0.45
		cmd := exec.Command(sleep, strconv.FormatFloat(life, 'f', 3, 64))
		if err := cmd.Start(); err != nil {
			failed.Add(1)
		} else {
			spawned.Add(1)
			go cmd.Wait()
		}
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		} else if d < -time.Second {
			next = time.Now() // fell behind; do not burst to catch up
		}
	}
}

// serverMain accepts connections on the given ports and keeps them open
// until the peer closes. Each accepted connection echoes one small message.
func serverMain(args []string) {
	raiseNofile()
	for _, ps := range splitComma(args[0]) {
		ln, err := net.Listen("tcp4", "127.0.0.1:"+ps)
		if err != nil {
			log.Fatalf("server: %v", err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					continue
				}
				go func() {
					buf := make([]byte, 64)
					for {
						n, err := c.Read(buf)
						if err != nil {
							c.Close()
							return
						}
						c.Write(buf[:n])
					}
				}()
			}
		}()
	}
	fmt.Println("LISTENING")
	waitSignal()
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

// clientMain holds n connections and replaces churn of them per second.
// Connections come from 127.0.0.<2..9> so each source address has its own
// ephemeral port range per server port.
func clientMain(args []string) {
	raiseNofile()
	n, _ := strconv.Atoi(args[0])
	churn, _ := strconv.ParseFloat(args[1], 64)
	ports, _ := strconv.Atoi(args[2])
	worker, _ := strconv.Atoi(args[3])
	dial := func(i int) (net.Conn, error) {
		src := &net.TCPAddr{IP: net.IPv4(127, 0, 0, byte(2+(i+worker)%8))}
		d := net.Dialer{LocalAddr: src, Timeout: 5 * time.Second}
		c, err := d.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", basePort+rand.Intn(ports)))
		if err != nil {
			return nil, err
		}
		// One request/response; reading the echo means a later Close sends
		// FIN (leaving TIME-WAIT, as on a real server) rather than RST.
		c.Write([]byte("hello\n"))
		buf := make([]byte, 6)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
	conns := make([]net.Conn, n)
	var errs, made int64
	for i := range conns {
		var err error
		for try := 0; try < 3; try++ {
			if conns[i], err = dial(i); err == nil {
				break
			}
			errs++
		}
		if err != nil {
			log.Fatalf("client %d: initial connection %d: %v", worker, i, err)
		}
		made++
	}
	fmt.Println("CONNECTED")

	// Churn runs in several goroutines (each owning every k-th connection)
	// because one replacement costs a round trip; a single loop cannot
	// reach high rates on a loaded machine.
	var nMade, nErrs, nOpen atomic.Int64
	nMade.Store(made)
	nErrs.Store(errs)
	nOpen.Store(int64(n))
	stop := make(chan struct{})
	var wg sync.WaitGroup
	if churn > 0 {
		k := min(int(churn/50)+1, n)
		for g := 0; g < k; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				r := rand.New(rand.NewSource(int64(worker*1000 + g)))
				interval := time.Duration(float64(time.Second) * float64(k) / churn)
				next := time.Now()
				for {
					select {
					case <-stop:
						return
					default:
					}
					i := g + k*r.Intn((n-g+k-1)/k) // an index owned by this goroutine
					if conns[i] != nil {
						conns[i].Close()
						nOpen.Add(-1)
					}
					if c, err := dial(i); err != nil {
						nErrs.Add(1)
						conns[i] = nil
					} else {
						conns[i] = c
						nOpen.Add(1)
						nMade.Add(1)
					}
					next = next.Add(interval)
					if d := time.Until(next); d > 0 {
						time.Sleep(d)
					} else if d < -time.Second {
						next = time.Now() // fell behind; do not burst to catch up
					}
				}
			}(g)
		}
	}
	out := bufio.NewWriter(os.Stdout)
	report := time.NewTicker(time.Second)
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGTERM, syscall.SIGINT)
	for {
		select {
		case <-done:
			close(stop)
			wg.Wait()
			for _, c := range conns {
				if c != nil {
					c.Close()
				}
			}
			return
		case <-report.C:
			fmt.Fprintf(out, "%d %d %d\n", nOpen.Load(), nMade.Load(), nErrs.Load())
			out.Flush()
		}
	}
}

func waitSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch
}
