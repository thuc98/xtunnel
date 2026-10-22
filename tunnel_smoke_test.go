package xtunnel_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"xtunnel/internal/config"
	"xtunnel/internal/connector"
	"xtunnel/internal/receiver"
	"xtunnel/internal/tunnel"
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
	}}, nil)
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
	}}, nil)
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
	}}, nil)
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

func startQuicServer(t *testing.T, ctx context.Context, port int, secret string) {
	t.Helper()
	server, err := connector.NewQuicConnector(config.ServerConfig{
		Listen:    fmt.Sprintf("127.0.0.1:%d", port),
		SecretKey: secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = server.Serve(ctx)
	}()
}

func expectTCPEcho(t *testing.T, addr string) {
	t.Helper()
	conn := dialWithRetry(t, addr)
	defer conn.Close()

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

func TestQuicReverseTCPTunnel(t *testing.T) {
	targetAddr, stopTarget := startTCPEchoTarget(t)
	defer stopTarget()

	serverPort := freePort(t)
	remotePort := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startQuicServer(t, ctx, serverPort, "test-secret")
	time.Sleep(100 * time.Millisecond)

	client, err := receiver.NewQuicReceiver(config.ClientConfig{
		ServerAddr:           fmt.Sprintf("127.0.0.1:%d", serverPort),
		SecretKey:            "test-secret",
		ReconnectIntervalSec: 1,
	}, nil, []config.ReverseRouteConfig{{
		RemotePort: remotePort,
		Target:     targetAddr,
		Protocol:   "tcp",
	}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = client.Start(ctx)
	}()

	expectTCPEcho(t, fmt.Sprintf("127.0.0.1:%d", remotePort))
}

func TestQuicReverseUDPTunnel(t *testing.T) {
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := target.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = target.WriteToUDP(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()

	serverPort := freePort(t)
	remotePort := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startQuicServer(t, ctx, serverPort, "test-secret")
	time.Sleep(100 * time.Millisecond)

	client, err := receiver.NewQuicReceiver(config.ClientConfig{
		ServerAddr:           fmt.Sprintf("127.0.0.1:%d", serverPort),
		SecretKey:            "test-secret",
		ReconnectIntervalSec: 1,
	}, nil, []config.ReverseRouteConfig{{
		RemotePort: remotePort,
		Target:     target.LocalAddr().String(),
		Protocol:   "udp",
	}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = client.Start(ctx)
	}()

	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", remotePort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, _ = conn.Write([]byte("ping"))
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}
		if string(buf[:n]) != "echo:ping" {
			t.Fatalf("unexpected reply %q", string(buf[:n]))
		}
		return
	}
	t.Fatal("no udp reply through reverse tunnel")
}

func TestQuicReverseRebindsAfterServerRestart(t *testing.T) {
	targetAddr, stopTarget := startTCPEchoTarget(t)
	defer stopTarget()

	serverPort := freePort(t)
	remotePort := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverCtx, stopServer := context.WithCancel(ctx)
	startQuicServer(t, serverCtx, serverPort, "test-secret")
	time.Sleep(100 * time.Millisecond)

	client, err := receiver.NewQuicReceiver(config.ClientConfig{
		ServerAddr:           fmt.Sprintf("127.0.0.1:%d", serverPort),
		SecretKey:            "test-secret",
		ReconnectIntervalSec: 1,
		MaxIdleTimeoutSec:    2,
		KeepAliveIntervalSec: 1,
	}, nil, []config.ReverseRouteConfig{{
		RemotePort: remotePort,
		Target:     targetAddr,
		Protocol:   "tcp",
	}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = client.Start(ctx)
	}()

	expectTCPEcho(t, fmt.Sprintf("127.0.0.1:%d", remotePort))

	stopServer()
	time.Sleep(200 * time.Millisecond)
	startQuicServer(t, ctx, serverPort, "test-secret")

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort), 100*time.Millisecond)
		if err == nil {
			_, _ = conn.Write([]byte("ping"))
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			got := make([]byte, len("echo:ping"))
			_, err = io.ReadFull(conn, got)
			conn.Close()
			if err == nil && string(got) == "echo:ping" {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("reverse route was not re-bound after server restart")
}

type countingDialer struct {
	calls atomic.Int32
}

func (d *countingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls.Add(1)
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

func TestFortiVPNRoutesDialDirectly(t *testing.T) {
	tcpTarget, stopTarget := startTCPEchoTarget(t)
	defer stopTarget()

	udpTarget, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpTarget.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := udpTarget.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udpTarget.WriteToUDP(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()

	tcpPort := freePort(t)
	udpPort := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := receiver.NewQuicReceiver(config.ClientConfig{
		ServerAddr:           fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		SecretKey:            "test-secret",
		ReconnectIntervalSec: 1,
	}, []config.RouteConfig{
		{LocalPort: tcpPort, Target: tcpTarget, Protocol: "tcp", FortiVPN: "office"},
		{LocalPort: udpPort, Target: udpTarget.LocalAddr().String(), Protocol: "udp", FortiVPN: "lab"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	office, lab := &countingDialer{}, &countingDialer{}
	client.SetVPNDialers(map[string]tunnel.DialFunc{"office": office.DialContext, "lab": lab.DialContext})
	go func() {
		_ = client.Start(ctx)
	}()

	expectTCPEcho(t, fmt.Sprintf("127.0.0.1:%d", tcpPort))

	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", udpPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "echo:ping" {
		t.Fatalf("unexpected reply %q", string(buf[:n]))
	}

	if got := office.calls.Load(); got != 1 {
		t.Fatalf("office vpn dialer used %d times, want 1", got)
	}
	if got := lab.calls.Load(); got != 1 {
		t.Fatalf("lab vpn dialer used %d times, want 1", got)
	}
}

func TestFortiVPNReverseRouteUsesVPNDialer(t *testing.T) {
	targetAddr, stopTarget := startTCPEchoTarget(t)
	defer stopTarget()

	serverPort := freePort(t)
	remotePort := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startQuicServer(t, ctx, serverPort, "test-secret")
	time.Sleep(100 * time.Millisecond)

	client, err := receiver.NewQuicReceiver(config.ClientConfig{
		ServerAddr:           fmt.Sprintf("127.0.0.1:%d", serverPort),
		SecretKey:            "test-secret",
		ReconnectIntervalSec: 1,
	}, nil, []config.ReverseRouteConfig{{
		RemotePort: remotePort,
		Target:     targetAddr,
		Protocol:   "tcp",
		FortiVPN:   "office",
	}})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &countingDialer{}
	client.SetVPNDialers(map[string]tunnel.DialFunc{"office": dialer.DialContext})
	go func() {
		_ = client.Start(ctx)
	}()

	expectTCPEcho(t, fmt.Sprintf("127.0.0.1:%d", remotePort))
	if got := dialer.calls.Load(); got != 1 {
		t.Fatalf("vpn dialer used %d times, want 1", got)
	}
}

func TestDialTunnelWithoutRoutes(t *testing.T) {
	targetAddr, stopTarget := startTCPEchoTarget(t)
	defer stopTarget()

	serverPort := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startQuicServer(t, ctx, serverPort, "test-secret")
	time.Sleep(100 * time.Millisecond)

	client, err := receiver.NewQuicReceiver(config.ClientConfig{
		ServerAddr:           fmt.Sprintf("127.0.0.1:%d", serverPort),
		SecretKey:            "test-secret",
		ReconnectIntervalSec: 1,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()
	conn, err := client.DialTunnel(dialCtx, "tcp", targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "echo:ping" {
		t.Fatalf("unexpected reply %q", got)
	}
}
