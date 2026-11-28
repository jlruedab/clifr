package webconfig

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// LimitListener: the third connection waits until one of two closes; Close
// ends a waiting Accept.
func TestLimitListener(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := LimitListener(raw, 2)
	accepted := make(chan net.Conn, 3)
	done := make(chan error, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				done <- err
				return
			}
			accepted <- c
		}
	}()
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	var first net.Conn
	for i := 0; i < 2; i++ {
		select {
		case c := <-accepted:
			if first == nil {
				first = c
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("connection %d not accepted", i+1)
		}
	}
	select {
	case <-accepted:
		t.Fatal("a third connection was accepted while two were open")
	case <-time.After(100 * time.Millisecond):
	}
	first.Close()
	first.Close() // twice: releases its slot once
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("the third connection was not accepted after one closed")
	}
	ln.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept after Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
}

// While every bcrypt slot is taken, an unchecked password is answered busy
// (503) instead of waiting for one.
func TestBcryptBusy(t *testing.T) {
	w := &Web{name: "metrics", authOK: map[[32]byte]bool{}}
	hash := "$2a$10$" + "abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234" // a well-formed hash; no password matches it
	c := &Config{Users: map[string]string{"prometheus": hash}}
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.SetBasicAuth("prometheus", "wrong")
	for i := 0; i < cap(bcryptSlots); i++ {
		bcryptSlots <- struct{}{}
	}
	if ok, busy := w.authorized(c, r); ok || !busy {
		t.Errorf("all slots taken: ok %v busy %v, want busy", ok, busy)
	}
	for i := 0; i < cap(bcryptSlots); i++ {
		<-bcryptSlots
	}
	if ok, busy := w.authorized(c, r); ok || busy {
		t.Errorf("a free slot: ok %v busy %v, want refused", ok, busy)
	}
}
