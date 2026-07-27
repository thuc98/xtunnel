package tunnel

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"xtunnel/internal/config"
	"xtunnel/internal/utils"
)

type StreamOpener interface {
	OpenStream(context.Context) (net.Conn, error)
}

type Client struct {
	secretKey string
	routes    []config.RouteConfig
	opener    StreamOpener
}

func NewClient(secretKey string, routes []config.RouteConfig, opener StreamOpener) *Client {
	return &Client{
		secretKey: secretKey,
		routes:    routes,
		opener:    opener,
	}
}

func (c *Client) ServeRoutes(ctx context.Context) error {
	errCh := make(chan error, len(c.routes))
	for _, route := range c.routes {
		route := route
		go func() {
			if route.Protocol == ProtocolUDP {
				errCh <- c.listenUDP(ctx, route)
				return
			}
			errCh <- c.listenTCP(ctx, route)
		}()
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (c *Client) openStream(ctx context.Context, route config.RouteConfig) (net.Conn, error) {
	conn, err := c.opener.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	req := StreamRequest{
		Protocol:  route.Protocol,
		Target:    route.Target,
		SecretKey: c.secretKey,
	}
	if err := WriteStreamRequest(conn, req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) listenTCP(ctx context.Context, route config.RouteConfig) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", route.LocalPort))
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("tcp route :%d -> %s", route.LocalPort, route.Target)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		localConn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go c.handleTCP(ctx, route, localConn)
	}
}

func (c *Client) handleTCP(ctx context.Context, route config.RouteConfig, localConn net.Conn) {
	defer localConn.Close()

	streamConn, err := c.openStream(ctx, route)
	if err != nil {
		log.Printf("open stream for %s: %v", route.Target, err)
		return
	}
	defer streamConn.Close()

	utils.Pipe(streamConn, localConn)
}

func (c *Client) listenUDP(ctx context.Context, route config.RouteConfig) error {
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: route.LocalPort}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("udp route :%d -> %s", route.LocalPort, route.Target)

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, 64*1024)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		packet := append([]byte(nil), buf[:n]...)
		go c.handleUDP(ctx, route, conn, clientAddr, packet)
	}
}

func (c *Client) handleUDP(ctx context.Context, route config.RouteConfig, localConn *net.UDPConn, clientAddr *net.UDPAddr, packet []byte) {
	streamConn, err := c.openStream(ctx, route)
	if err != nil {
		log.Printf("open udp stream for %s: %v", route.Target, err)
		return
	}
	defer streamConn.Close()

	if _, err := streamConn.Write(packet); err != nil {
		log.Printf("write udp packet to stream: %v", err)
		return
	}
	if cw, ok := streamConn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}

	_ = streamConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reply, err := io.ReadAll(streamConn)
	if err != nil {
		log.Printf("read udp reply from stream: %v", err)
		return
	}
	if len(reply) == 0 {
		return
	}
	if _, err := localConn.WriteToUDP(reply, clientAddr); err != nil {
		log.Printf("write udp reply to client: %v", err)
	}
}
