package xtunnel_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"xtunnel/internal/config"
	"xtunnel/internal/connector"
	"xtunnel/internal/receiver"
)

func TestQuicTCPTunnel(t *testing.T) {
	targetAddr, stopTarget := startTCPEchoTarget(t)
	defer stopTarget()

	serverPort := freePort(t)
	localPort := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server, err := connector.NewQuicConnector(config.ServerConfig{
		Listen:    fmt.Sprintf("127.0.0.1:%d", serverPort),
		SecretKey: "test-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = server.Serve(ctx)
	}()
	time.Sleep(100 * time.Millisecond)

	client, err := receiver.NewQuicReceiver(config.ClientConfig{
		ServerAddr: fmt.Sprintf("127.0.0.1:%d", serverPort),
		SecretKey:  "test-secret",
	}, []config.RouteConfig{{
		LocalPort: localPort,
		Target:    targetAddr,
		Protocol:  "tcp",
	}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = client.Start(ctx)
	}()

	conn := dialWithRetry(t, fmt.Sprintf("127.0.0.1:%d", localPort))
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	got := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "echo:ping" {
		t.Fatalf("unexpected reply %q", string(got))
	}
}

func TestQuicTCPTunnelRejectsInvalidSecret(t *testing.T) {
	targetAddr, stopTarget := startTCPEchoTarget(t)
	defer stopTarget()

	serverPort := freePort(t)
	localPort := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server, err := connector.NewQuicConnector(config.ServerConfig{
		Listen:    fmt.Sprintf("127.0.0.1:%d", serverPort),
		SecretKey: "server-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = server.Serve(ctx)
	}()
	time.Sleep(100 * time.Millisecond)

	client, err := receiver.NewQuicReceiver(config.ClientConfig{
		ServerAddr: fmt.Sprintf("127.0.0.1:%d", serverPort),
		SecretKey:  "wrong-secret",
	}, []config.RouteConfig{{
		LocalPort: localPort,
		Target:    targetAddr,
		Protocol:  "tcp",
	}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = client.Start(ctx)
	}()

	conn := dialWithRetry(t, fmt.Sprintf("127.0.0.1:%d", localPort))
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected invalid secret to close the tunnel stream")
	}
}

func TestQuicReceiverConnectsAfterServerStarts(t *testing.T) {
	targetAddr, stopTarget := startTCPEchoTarget(t)
	defer stopTarget()

	serverPort := freePort(t)
	localPort := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := receiver.NewQuicReceiver(config.ClientConfig{
		ServerAddr:           fmt.Sprintf("127.0.0.1:%d", serverPort),
		SecretKey:            "test-secret",
		ReconnectIntervalSec: 1,
	}, []config.RouteConfig{{
		LocalPort: localPort,
		Target:    targetAddr,
		Protocol:  "tcp",
	}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = client.Start(ctx)
	}()

	conn := dialWithRetry(t, fmt.Sprintf("127.0.0.1:%d", localPort))
	defer conn.Close()

	server, err := connector.NewQuicConnector(config.ServerConfig{
		Listen:    fmt.Sprintf("127.0.0.1:%d", serverPort),
		SecretKey: "test-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = server.Serve(ctx)
	}()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	got := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "echo:ping" {
		t.Fatalf("unexpected reply %q", string(got))
	}
}

func startTCPEchoTarget(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				_, _ = conn.Write(append([]byte("echo:"), buf[:n]...))
			}(conn)
		}
	}()

	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func dialWithRetry(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			return conn
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("dial %s: %v", addr, lastErr)
	return nil
}
