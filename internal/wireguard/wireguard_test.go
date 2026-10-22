package wireguard

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"xtunnel/internal/config"
)

func keypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.Bytes(), k.PublicKey().Bytes()
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// startPeer runs the remote side: a WireGuard device on 10.99.0.1 with a TCP
// echo server on port 7.
func startPeer(t *testing.T, priv, clientPub []byte, port int) {
	t.Helper()
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.99.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "peer: "))
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=10.99.0.2/32\n",
		hex.EncodeToString(priv), port, hex.EncodeToString(clientPub))
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)

	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.99.0.1"), Port: 7})
	if err != nil {
		t.Fatal(err)
	}
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
}

func TestTunnelEcho(t *testing.T) {
	peerPriv, peerPub := keypair(t)
	clientPriv, clientPub := keypair(t)
	port := freeUDPPort(t)
	startPeer(t, peerPriv, clientPub, port)

	b64 := base64.StdEncoding.EncodeToString
	cfg := config.WireGuardConfig{
		Name:       "home",
		PrivateKey: b64(clientPriv),
		Addresses:  []string{"10.99.0.2/32"},
		MTU:        1420,
		Peers: []config.WireGuardPeer{{
			PublicKey:  b64(peerPub),
			Endpoint:   fmt.Sprintf("127.0.0.1:%d", port),
			AllowedIPs: []string{"10.99.0.0/24"},
		}},
	}
	tun := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = tun.Run(ctx)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	var c net.Conn
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		dctx, dcancel := context.WithTimeout(ctx, 3*time.Second)
		c, err = tun.DialContext(dctx, "tcp", "10.99.0.1:7")
		dcancel()
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo %q, %v", got, err)
	}

	st := tun.Status()
	if st.State != "up" || st.LastHandshake.IsZero() || st.Address != "10.99.0.2" {
		t.Fatalf("status = %+v", st)
	}
}

func TestTunnelBadKeyReportsDown(t *testing.T) {
	tun := New(config.WireGuardConfig{Name: "bad", PrivateKey: "nope", Addresses: []string{"10.99.0.2/32"}, MTU: 1420,
		Peers: []config.WireGuardPeer{{PublicKey: "nope", Endpoint: "127.0.0.1:1", AllowedIPs: []string{"0.0.0.0/0"}}}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = tun.Run(ctx)
		close(done)
	}()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline) && tun.Status().State != "down"; time.Sleep(20 * time.Millisecond) {
	}
	cancel()
	<-done
	if st := tun.Status(); st.State != "down" || st.Error == "" {
		t.Fatalf("status = %+v", st)
	}
}
