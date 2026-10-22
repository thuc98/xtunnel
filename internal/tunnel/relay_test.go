package tunnel

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// A UDP flow must reach the target from one stable source port, and the
// target must be able to send any number of replies (QUIC needs both).
func TestUDPSessionKeepsSourcePort(t *testing.T) {
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	sources := make(chan string, 16)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := target.ReadFromUDP(buf)
			if err != nil {
				return
			}
			sources <- addr.String()
			for i := 0; i < 2; i++ {
				_, _ = target.WriteToUDP([]byte(fmt.Sprintf("%s#%d", buf[:n], i)), addr)
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	open := func(ctx context.Context) (net.Conn, error) {
		local, remote := net.Pipe()
		go func() {
			defer remote.Close()
			relayUDP(defaultDialer.DialContext, target.LocalAddr().String(), remote, remote)
		}()
		return newFramedPacketConn(local, local), nil
	}

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = serveUDPConn(ctx, listener, open, "test") }()

	conn, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("p%d", i)
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 2; j++ {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("packet %d reply %d: %v", i, j, err)
			}
			if want := fmt.Sprintf("%s#%d", msg, j); string(buf[:n]) != want {
				t.Fatalf("got %q, want %q", buf[:n], want)
			}
		}
	}

	first := <-sources
	for i := 1; i < 3; i++ {
		if src := <-sources; src != first {
			t.Fatalf("source port changed: %s -> %s", first, src)
		}
	}
}
