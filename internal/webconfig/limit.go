package webconfig

import (
	"net"
	"sync"
)

// LimitListener accepts at most n connections at once (golang.org/x/net's
// netutil.LimitListener, written here to add no dependency). --metrics and
// --serve run inside the recorder, under its memory and CPU limits: without
// a bound, clients that only open connections (no token, no password, a TLS
// handshake left hanging) cost a goroutine and its buffers each, without
// limit, and could take the recorder's memory. Further connections wait in
// the kernel's backlog until one closes.
func LimitListener(l net.Listener, n int) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n), done: make(chan struct{})}
}

type limitListener struct {
	net.Listener
	sem  chan struct{}
	done chan struct{}
	once sync.Once
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: sync.OnceFunc(func() { <-l.sem })}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}
