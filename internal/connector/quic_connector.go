package connector

import (
	"context"
	"fmt"
	"log"

	"github.com/quic-go/quic-go"

	"xtunnel/internal/config"
	"xtunnel/internal/manager"
	"xtunnel/internal/tunnel"
	"xtunnel/internal/utils"
)

type QuicConnector struct {
	serverConfig config.ServerConfig
	server       *tunnel.Server
}

func NewQuicConnector(serverConfig config.ServerConfig) (*QuicConnector, error) {
	if serverConfig.Listen == "" {
		return nil, fmt.Errorf("server listen address is required")
	}
	if serverConfig.SecretKey == "" {
		return nil, fmt.Errorf("server secret_key is required")
	}
	return &QuicConnector{
		serverConfig: serverConfig,
		server:       tunnel.NewServer(serverConfig.SecretKey),
	}, nil
}

func (c *QuicConnector) Serve(ctx context.Context) error {
	tlsConfig, err := utils.ServerTLSConfig()
	if err != nil {
		return err
	}
	listener, err := quic.ListenAddr(c.serverConfig.Listen, tlsConfig, nil)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Printf("server listening on %s", c.serverConfig.Listen)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		xconn := manager.NewQuicXConnection(conn)
		go c.server.ServeConnection(ctx, xconn)
	}
}
