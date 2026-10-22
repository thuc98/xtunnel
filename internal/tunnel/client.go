package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"xtunnel/internal/config"
)

type StreamOpener interface {
	OpenStream(context.Context) (net.Conn, error)
}

type Client struct {
	secretKey     string
	routes        []config.RouteConfig
	reverseRoutes map[string]config.ReverseRouteConfig
	opener        StreamOpener
	vpnDialers    map[string]DialFunc
}

func NewClient(secretKey string, routes []config.RouteConfig, reverseRoutes []config.ReverseRouteConfig, opener StreamOpener) *Client {
	reverse := make(map[string]config.ReverseRouteConfig, len(reverseRoutes))
	for _, route := range reverseRoutes {
		reverse[reverseKey(route.Protocol, route.RemotePort)] = route
	}
	return &Client{
		secretKey:     secretKey,
		routes:        routes,
		reverseRoutes: reverse,
		opener:        opener,
	}
}

func (c *Client) SetVPNDialers(dialers map[string]DialFunc) {
	c.vpnDialers = dialers
}

func (c *Client) targetDialer(vpn string) (DialFunc, error) {
	if vpn == "" {
		return defaultDialer.DialContext, nil
	}
	dial, ok := c.vpnDialers[vpn]
	if !ok {
		return nil, fmt.Errorf("fortivpn %q is not configured", vpn)
	}
	return dial, nil
}

func viaLabel(vpn string) string {
	if vpn == "" {
		return ""
	}
	return " via fortivpn " + vpn
}

func reverseKey(protocol string, port int) string {
	return fmt.Sprintf("%s:%d", protocol, port)
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

func (c *Client) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("unsupported network %q", network)
	}
	return c.openStream(ctx, config.RouteConfig{Protocol: ProtocolTCP, Target: address})
}

func (c *Client) routeOpener(route config.RouteConfig) (openStreamFunc, string, error) {
	if route.FortiVPN == "" {
		return func(ctx context.Context) (net.Conn, error) {
			return c.openStream(ctx, route)
		}, "", nil
	}
	dial, err := c.targetDialer(route.FortiVPN)
	if err != nil {
		return nil, "", err
	}
	if route.Protocol == ProtocolUDP {
		return func(ctx context.Context) (net.Conn, error) {
			conn, err := dial(ctx, "udp", route.Target)
			if err != nil {
				return nil, err
			}
			return &datagramConn{Conn: conn}, nil
		}, viaLabel(route.FortiVPN), nil
	}
	return func(ctx context.Context) (net.Conn, error) {
		return dial(ctx, "tcp", route.Target)
	}, viaLabel(route.FortiVPN), nil
}

func (c *Client) listenTCP(ctx context.Context, route config.RouteConfig) error {
	open, via, err := c.routeOpener(route)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", route.LocalPort))
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("tcp route :%d -> %s%s", route.LocalPort, route.Target, via)

	return serveTCPListener(ctx, ln, open, route.Target)
}

func (c *Client) listenUDP(ctx context.Context, route config.RouteConfig) error {
	open, via, err := c.routeOpener(route)
	if err != nil {
		return err
	}
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: route.LocalPort}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("udp route :%d -> %s%s", route.LocalPort, route.Target, via)

	return serveUDPConn(ctx, conn, open, route.Target)
}

func (c *Client) ServeReverse(ctx context.Context, conn StreamConn, retryInterval time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()

	for _, route := range c.reverseRoutes {
		route := route
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.keepBind(ctx, conn, route, retryInterval)
		}()
	}

	for {
		streamConn, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go c.handleReverseStream(streamConn)
	}
}

func (c *Client) keepBind(ctx context.Context, conn StreamConn, route config.ReverseRouteConfig, retryInterval time.Duration) {
	for {
		err := c.bind(ctx, conn, route)
		if ctx.Err() != nil {
			return
		}
		log.Printf("reverse %s route server:%d -> %s: %v, retrying in %s", route.Protocol, route.RemotePort, route.Target, err, retryInterval)

		timer := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (c *Client) bind(ctx context.Context, conn StreamConn, route config.ReverseRouteConfig) error {
	streamConn, err := conn.OpenStream(ctx)
	if err != nil {
		return err
	}
	defer streamConn.Close()
	stop := context.AfterFunc(ctx, func() { _ = streamConn.Close() })
	defer stop()

	req := StreamRequest{
		Type:      StreamTypeBind,
		Protocol:  route.Protocol,
		Port:      route.RemotePort,
		SecretKey: c.secretKey,
	}
	if err := WriteStreamRequest(streamConn, req); err != nil {
		return err
	}

	br := bufio.NewReader(streamConn)
	resp, err := ReadBindResponse(br)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("server rejected bind: %s", resp.Error)
	}
	log.Printf("reverse %s route server:%d -> %s%s", route.Protocol, route.RemotePort, route.Target, viaLabel(route.FortiVPN))

	_, err = io.Copy(io.Discard, br)
	if err == nil {
		err = errors.New("bind closed by server")
	}
	return err
}

func (c *Client) handleReverseStream(streamConn net.Conn) {
	defer streamConn.Close()

	header, reader, err := ReadReverseStreamHeader(streamConn)
	if err != nil {
		log.Printf("read reverse stream: %v", err)
		return
	}
	route, ok := c.reverseRoutes[reverseKey(header.Protocol, header.Port)]
	if !ok {
		log.Printf("reject reverse stream: no %s route for server port %d", header.Protocol, header.Port)
		return
	}

	dial, err := c.targetDialer(route.FortiVPN)
	if err != nil {
		log.Printf("reverse %s route server:%d -> %s: %v", route.Protocol, route.RemotePort, route.Target, err)
		return
	}
	switch route.Protocol {
	case ProtocolTCP:
		relayTCP(dial, route.Target, reader, streamConn)
	case ProtocolUDP:
		relayUDP(dial, route.Target, reader, streamConn)
	}
}
