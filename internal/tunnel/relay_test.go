package tunnel

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

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
			relayUDP(defaultDialer.DialContext, target.LocalAddr().String(), remote, remote, defaultUDPIdleTimeout)
		}()
		return newFramedPacketConn(local, local), nil
	}

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = serveUDPConn(ctx, listener, open, "test", defaultUDPIdleTimeout) }()

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

func TestUDPSessionClosesAfterIdleTimeout(t *testing.T) {
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
			_, _ = target.WriteToUDP(buf[:n], addr)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const idle = 400 * time.Millisecond
	open := func(ctx context.Context) (net.Conn, error) {
		local, remote := net.Pipe()
		go func() {
			defer remote.Close()
			relayUDP(defaultDialer.DialContext, target.LocalAddr().String(), remote, remote, idle)
		}()
		return newFramedPacketConn(local, local), nil
	}

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = serveUDPConn(ctx, listener, open, "test", idle) }()

	conn, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	roundTrip := func() string {
		t.Helper()
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Read(buf); err != nil {
			t.Fatal(err)
		}
		return <-sources
	}

	first := roundTrip()
	if again := roundTrip(); again != first {
		t.Fatalf("source port changed before idle timeout: %s -> %s", first, again)
	}
	time.Sleep(3 * idle)
	if after := roundTrip(); after == first {
		t.Fatalf("session was not closed after idle timeout (still %s)", after)
	}
}
