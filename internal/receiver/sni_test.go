package receiver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"xtunnel/internal/config"
	"xtunnel/internal/utils"
)

// sniServer accepts QUIC connections and reports the SNI each client sent.
func sniServer(t *testing.T) (string, <-chan string) {
	t.Helper()
	tlsConfig, err := utils.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	names := make(chan string, 4)
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		names <- hello.ServerName
		return nil, nil
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, utils.QUICConfig(10, 60))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			if _, err := ln.Accept(context.Background()); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String(), names
}

func TestTunnelSNI(t *testing.T) {
	for _, tt := range []struct{ sni, want string }{{"cdn.example.com", "cdn.example.com"}, {"", ""}} {
		t.Run(fmt.Sprintf("sni=%q", tt.sni), func(t *testing.T) {
			addr, names := sniServer(t)
			r, err := NewQuicReceiver(config.ClientConfig{ServerAddr: addr, SecretKey: "k", SNI: tt.sni, ReconnectIntervalSec: 1}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go func() { _, _ = r.DialTunnel(ctx, "tcp", "127.0.0.1:1") }()
			select {
			case got := <-names:
				if host, _, err := net.SplitHostPort(got); err == nil {
					got = host
				}
				if got != tt.want {
					t.Fatalf("server saw SNI %q, want %q", got, tt.want)
				}
			case <-ctx.Done():
				t.Fatal("no connection")
			}
			r.close()
		})
	}
}
