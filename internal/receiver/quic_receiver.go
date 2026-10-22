package receiver

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"xtunnel/internal/config"
	"xtunnel/internal/manager"
	"xtunnel/internal/tunnel"
	"xtunnel/internal/utils"
)

type QuicReceiver struct {
	clientConfig  config.ClientConfig
	routes        []config.RouteConfig
	reverseRoutes []config.ReverseRouteConfig
	vpnDialers    map[string]tunnel.DialFunc
	xconn         manager.XConnection
	mu            sync.RWMutex
	reconnectMu   sync.Mutex
}

func NewQuicReceiver(clientConfig config.ClientConfig, routes []config.RouteConfig, reverseRoutes []config.ReverseRouteConfig) (*QuicReceiver, error) {
	if clientConfig.SecretKey == "" {
		return nil, fmt.Errorf("client secret_key is required")
	}
	return &QuicReceiver{clientConfig: clientConfig, routes: routes, reverseRoutes: reverseRoutes}, nil
}

func (r *QuicReceiver) SetVPNDialers(dialers map[string]tunnel.DialFunc) {
	r.vpnDialers = dialers
}

func (r *QuicReceiver) DialTunnel(ctx context.Context, network, address string) (net.Conn, error) {
	return tunnel.NewClient(r.clientConfig.SecretKey, nil, nil, r).Dial(ctx, network, address)
}

func (r *QuicReceiver) Connected() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.xconn != nil
}

func (r *QuicReceiver) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer r.close()

	client := tunnel.NewClient(r.clientConfig.SecretKey, r.routes, r.reverseRoutes, r)
	client.SetVPNDialers(r.vpnDialers)
	if len(r.reverseRoutes) > 0 {
		go r.serveReverse(ctx, client)
	}
	return client.ServeRoutes(ctx)
}

func (r *QuicReceiver) serveReverse(ctx context.Context, client *tunnel.Client) {
	interval := time.Duration(r.clientConfig.ReconnectIntervalSec) * time.Second
	for {
		xconn, err := r.connection(ctx)
		if err != nil {
			return
		}
		err = client.ServeReverse(ctx, xconn, interval)
		if ctx.Err() != nil {
			return
		}
		log.Printf("reverse tunnel to %s lost, reconnecting: %v", r.clientConfig.ServerAddr, err)
		r.dropConnection(xconn)
	}
}

func (r *QuicReceiver) connect(ctx context.Context) error {
	quicConfig := utils.QUICConfig(r.clientConfig.KeepAliveIntervalSec, r.clientConfig.MaxIdleTimeoutSec)
	conn, err := quic.DialAddr(ctx, r.clientConfig.ServerAddr, utils.ClientTLSConfig(), quicConfig)
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
	for {
		xconn, err := r.connection(ctx)
		if err != nil {
			return nil, err
		}

		conn, err := xconn.OpenStream(ctx)
		if err == nil {
			return conn, nil
		}

		log.Printf("open stream failed, reconnecting to %s: %v", r.clientConfig.ServerAddr, err)
		r.dropConnection(xconn)
	}
}

func (r *QuicReceiver) connection(ctx context.Context) (manager.XConnection, error) {
	r.mu.RLock()
	xconn := r.xconn
	r.mu.RUnlock()
	if xconn != nil {
		return xconn, nil
	}

	r.reconnectMu.Lock()
	defer r.reconnectMu.Unlock()

	r.mu.RLock()
	xconn = r.xconn
	r.mu.RUnlock()
	if xconn != nil {
		return xconn, nil
	}

	interval := time.Duration(r.clientConfig.ReconnectIntervalSec) * time.Second
	for {
		if err := r.connect(ctx); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			log.Printf("connect to server %s failed, retrying in %s: %v", r.clientConfig.ServerAddr, interval, err)
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
			continue
		}

		r.mu.RLock()
		xconn = r.xconn
		r.mu.RUnlock()
		if xconn == nil {
			return nil, io.ErrClosedPipe
		}
		return xconn, nil
	}
}

func (r *QuicReceiver) dropConnection(xconn manager.XConnection) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.xconn == xconn {
		_ = r.xconn.Close()
		r.xconn = nil
	}
}

func (r *QuicReceiver) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.xconn != nil {
		_ = r.xconn.Close()
		r.xconn = nil
	}
}
