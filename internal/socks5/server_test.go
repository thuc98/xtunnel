package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func startServer(t *testing.T, s *Server) (addr string, dialed func() []string) {
	t.Helper()
	var mu sync.Mutex
	var targets []string
	s.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		targets = append(targets, address)
		mu.Unlock()
		if address == "intranet.local:7" {
			address = s.Name
		}
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.ListenAndServe(ctx, addr) }()
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return addr, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), targets...)
	}
}

func connect(t *testing.T, proxyAddr, user, pass, host string, port uint16) (net.Conn, byte) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	method := byte(methodNoAuth)
	if user != "" {
		method = methodUserPass
	}
	_, _ = c.Write([]byte{version5, 1, method})
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		t.Fatal(err)
	}
	if sel[1] == methodNoAcceptable {
		return c, methodNoAcceptable
	}
	if user != "" {
		msg := append([]byte{1, byte(len(user))}, user...)
		msg = append(append(msg, byte(len(pass))), pass...)
		_, _ = c.Write(msg)
		var status [2]byte
		if _, err := io.ReadFull(c, status[:]); err != nil {
			t.Fatal(err)
		}
		if status[1] != 0 {
			return c, 0xfe
		}
	}
	req := append([]byte{version5, cmdConnect, 0, atypDomain, byte(len(host))}, host...)
	req = binary.BigEndian.AppendUint16(req, port)
	_, _ = c.Write(req)
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal(err)
	}
	return c, reply[1]
}

func TestConnectNoAuth(t *testing.T) {
	echo := startEcho(t)
	addr, dialed := startServer(t, &Server{Name: echo})

	c, rep := connect(t, addr, "", "", "intranet.local", 7)
	defer c.Close()
	if rep != repSucceeded {
		t.Fatalf("reply %d", rep)
	}
	_, _ = c.Write([]byte("ping"))
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo %q, %v", got, err)
	}

	if d := dialed(); len(d) != 1 || d[0] != "intranet.local:7" {
		t.Fatalf("dialed %v", d)
	}
}

func TestConnectUserPass(t *testing.T) {
	echo := startEcho(t)
	addr, _ := startServer(t, &Server{Name: echo, Username: "u", Password: "p"})

	c, rep := connect(t, addr, "u", "p", "intranet.local", 7)
	c.Close()
	if rep != repSucceeded {
		t.Fatalf("reply %d", rep)
	}

	c, rep = connect(t, addr, "u", "wrong", "intranet.local", 7)
	c.Close()
	if rep != 0xfe {
		t.Fatalf("wrong password accepted (reply %d)", rep)
	}

	c, rep = connect(t, addr, "", "", "intranet.local", 7)
	c.Close()
	if rep != methodNoAcceptable {
		t.Fatalf("no-auth client accepted (reply %d)", rep)
	}
}

func TestConnectUnreachable(t *testing.T) {
	addr, _ := startServer(t, &Server{Name: "127.0.0.1:1"})
	c, rep := connect(t, addr, "", "", "127.0.0.1", 1)
	c.Close()
	if rep != repHostUnreachable {
		t.Fatalf("reply %d, want %d", rep, repHostUnreachable)
	}
}
