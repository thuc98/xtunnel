package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"xtunnel/internal/config"
	"xtunnel/internal/connector"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func startEcho(t *testing.T, tag string) string {
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
				_, _ = io.WriteString(c, tag)
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func startServer(t *testing.T, ctx context.Context, secret string) int {
	t.Helper()
	port := freePort(t)
	c, err := connector.NewQuicConnector(config.ServerConfig{Listen: fmt.Sprintf("127.0.0.1:%d", port), SecretKey: secret})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = c.Serve(ctx) }()
	return port
}

func readTag(port int) (string, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func waitTag(t *testing.T, port int, want string) {
	t.Helper()
	var got string
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if got, err = readTag(port); err == nil && got == want {
			return
		}
	}
	t.Fatalf("port %d: got %q, %v; want %q", port, got, err, want)
}

func TestTunnelsAreIndependent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targetA, targetB := startEcho(t, "A:"), startEcho(t, "B:")
	portA, portB := startServer(t, ctx, "secret-a"), startServer(t, ctx, "secret-b")
	localA, localB := freePort(t), freePort(t)

	write := func(bDisabled bool) *config.Config {
		text := fmt.Sprintf(`tunnels:
  - name: a
    server_addr: "127.0.0.1:%d"
    secret_key: secret-a
  - name: b
    disabled: %v
    server_addr: "127.0.0.1:%d"
    secret_key: secret-b
routes:
  - {local_port: %d, target: "%s", protocol: tcp, tunnel: a}
  - {local_port: %d, target: "%s", protocol: tcp, tunnel: b}
`, portA, bDisabled, portB, localA, targetA, localB, targetB)
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	a := New("unused.yaml", false)
	runDone := make(chan struct{})
	go func() {
		_ = a.Run(ctx, write(false))
		close(runDone)
	}()
	defer func() {
		cancel()
		<-runDone
	}()

	waitTag(t, localA, "A:")
	waitTag(t, localB, "B:")

	a.mu.Lock()
	tunnelA := a.tunnels["a"]
	a.mu.Unlock()

	a.apply(write(true))
	if _, err := readTag(localB); err == nil {
		t.Fatal("route of disabled tunnel b still answers")
	}
	waitTag(t, localA, "A:")

	a.mu.Lock()
	same := a.tunnels["a"] == tunnelA
	a.mu.Unlock()
	if !same {
		t.Fatal("tunnel a was restarted although its config did not change")
	}

	st := a.Status()
	if len(st.Tunnels) != 2 || st.Tunnels[0].State != "up" || st.Tunnels[1].State != "disabled" {
		t.Fatalf("tunnels status = %+v", st.Tunnels)
	}
}

func socksTag(proxy, target string) (string, error) {
	c, err := net.DialTimeout("tcp", proxy, time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	req := []byte{5, 1, 0}
	if _, err := c.Write(req); err != nil {
		return "", err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		return "", err
	}
	ip := net.ParseIP(host).To4()
	connect := append([]byte{5, 1, 0, 1}, ip...)
	connect = append(connect, byte(port>>8), byte(port))
	if _, err := c.Write(connect); err != nil {
		return "", err
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil {
		return "", err
	}
	if resp[1] != 0 {
		return "", fmt.Errorf("socks reply %d", resp[1])
	}
	tag := make([]byte, 2)
	_, err = io.ReadFull(c, tag)
	return string(tag), err
}

func TestTunnelSocksToggle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target := startEcho(t, "A:")
	server := startServer(t, ctx, "secret-a")
	socksPort := freePort(t)
	proxy := fmt.Sprintf("127.0.0.1:%d", socksPort)

	cfgWith := func(disabled bool) *config.Config {
		path := filepath.Join(t.TempDir(), "config.yaml")
		text := fmt.Sprintf(`tunnels:
  - name: a
    server_addr: "127.0.0.1:%d"
    secret_key: secret-a
    socks5: {listen: "%s", disabled: %v}
`, server, proxy, disabled)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	a := New("unused.yaml", false)
	runDone := make(chan struct{})
	go func() {
		_ = a.Run(ctx, cfgWith(true))
		close(runDone)
	}()
	defer func() {
		cancel()
		<-runDone
	}()

	time.Sleep(200 * time.Millisecond)
	if _, err := socksTag(proxy, target); err == nil {
		t.Fatal("socks5 answers while disabled")
	}
	a.mu.Lock()
	tunnel := a.tunnels["a"]
	a.mu.Unlock()

	a.apply(cfgWith(false))
	var tag string
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if tag, err = socksTag(proxy, target); err == nil {
			break
		}
	}
	if err != nil || tag != "A:" {
		t.Fatalf("socks5 through tunnel a: %q, %v", tag, err)
	}
	a.mu.Lock()
	same := a.tunnels["a"] == tunnel
	a.mu.Unlock()
	if !same {
		t.Fatal("turning the socks5 proxy on restarted the tunnel")
	}

	a.apply(cfgWith(true))
	if _, err := socksTag(proxy, target); err == nil {
		t.Fatal("socks5 still answers after turning it off")
	}
}
