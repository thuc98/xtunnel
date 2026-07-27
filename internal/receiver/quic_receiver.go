package receiver

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/quic-go/quic-go"

	"xtunnel/internal/config"
	"xtunnel/internal/manager"
	"xtunnel/internal/tunnel"
	"xtunnel/internal/utils"
)

type QuicReceiver struct {
	clientConfig config.ClientConfig
	routes       []config.RouteConfig
	xconn        manager.XConnection
	mu           sync.RWMutex
}

func NewQuicReceiver(clientConfig config.ClientConfig, routes []config.RouteConfig) (*QuicReceiver, error) {
	if clientConfig.SecretKey == "" {
		return nil, fmt.Errorf("client secret_key is required")
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("client requires at least one route")
	}
	return &QuicReceiver{clientConfig: clientConfig, routes: routes}, nil
}

func (r *QuicReceiver) Start(ctx context.Context) error {
	if err := r.connect(ctx); err != nil {
		return err
	}
	defer r.close()

	client := tunnel.NewClient(r.clientConfig.SecretKey, r.routes, r)
	return client.ServeRoutes(ctx)
}

func (r *QuicReceiver) connect(ctx context.Context) error {
	conn, err := quic.DialAddr(ctx, r.clientConfig.ServerAddr, utils.ClientTLSConfig(), nil)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.xconn = manager.NewQuicXConnection(conn)
	r.mu.Unlock()
	log.Printf("connected to server %s", r.clientConfig.ServerAddr)
	return nil
}

func (r *QuicReceiver) OpenStream(ctx context.Context) (net.Conn, error) {
	r.mu.RLock()
	xconn := r.xconn
	r.mu.RUnlock()
	if xconn == nil {
		return nil, io.ErrClosedPipe
	}

	return xconn.OpenStream(ctx)
}

func (r *QuicReceiver) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.xconn != nil {
		_ = r.xconn.Close()
		r.xconn = nil
	}
}
