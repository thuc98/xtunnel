package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

type StreamConn interface {
	StreamOpener
	AcceptStream(context.Context) (net.Conn, error)
	Close() error
	RemoteAddr() string
}

type Server struct {
	secretKey string

	mu    sync.Mutex
	binds map[string]io.Closer
}

func NewServer(secretKey string) *Server {
	return &Server{secretKey: secretKey, binds: make(map[string]io.Closer)}
}

func (s *Server) ServeConnection(ctx context.Context, conn StreamConn) {
	defer conn.Close()
	log.Printf("accepted client %s", conn.RemoteAddr())

	for {
		streamConn, err := conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("accept stream from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}
		go s.HandleStream(ctx, conn, streamConn)
	}
}

func (s *Server) HandleStream(ctx context.Context, conn StreamConn, streamConn net.Conn) {
	defer streamConn.Close()

	req, reader, err := ReadStreamRequest(streamConn)
	if err != nil {
		log.Printf("read stream request: %v", err)
		return
	}
	if req.SecretKey != s.secretKey {
		log.Printf("reject stream: invalid secret key")
		if req.Type == StreamTypeBind {
			_ = WriteBindResponse(streamConn, BindResponse{Error: "invalid secret key"})
		}
		return
	}

	if req.Type == StreamTypeBind {
		s.handleBind(ctx, conn, req, reader, streamConn)
		return
	}

	switch req.Protocol {
	case ProtocolTCP:
		relayTCP(defaultDialer.DialContext, req.Target, reader, streamConn)
	case ProtocolUDP:
		relayUDP(defaultDialer.DialContext, req.Target, reader, streamConn, udpIdleTimeout(req.UDPIdleTimeoutSec))
	default:
		log.Printf("unsupported protocol %q", req.Protocol)
	}
}

func (s *Server) handleBind(ctx context.Context, conn StreamConn, req StreamRequest, reader *bufio.Reader, streamConn net.Conn) {
	key := fmt.Sprintf("%s:%d", req.Protocol, req.Port)
	listener, err := s.listen(key, req.Protocol, req.Port)
	if err != nil {
		log.Printf("reverse bind %s from %s: %v", key, conn.RemoteAddr(), err)
		_ = WriteBindResponse(streamConn, BindResponse{Error: err.Error()})
		return
	}
	defer s.unbind(key, listener)

	if err := WriteBindResponse(streamConn, BindResponse{OK: true}); err != nil {
		return
	}
	log.Printf("reverse %s bound :%d for client %s", req.Protocol, req.Port, conn.RemoteAddr())

	bindCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		_, _ = io.Copy(io.Discard, reader)
		cancel()
	}()

	open := func(ctx context.Context) (net.Conn, error) {
		c, err := conn.OpenStream(ctx)
		if err != nil {
			return nil, err
		}
		if err := WriteReverseStreamHeader(c, ReverseStreamHeader{Protocol: req.Protocol, Port: req.Port}); err != nil {
			_ = c.Close()
			return nil, err
		}
		if req.Protocol == ProtocolUDP {
			return newFramedPacketConn(c, c), nil
		}
		return c, nil
	}

	label := fmt.Sprintf("client %s", conn.RemoteAddr())
	switch l := listener.(type) {
	case net.Listener:
		err = serveTCPListener(bindCtx, l, open, label)
	case *net.UDPConn:
		err = serveUDPConn(bindCtx, l, open, label, udpIdleTimeout(req.UDPIdleTimeoutSec))
	}
	if err != nil && bindCtx.Err() == nil {
		log.Printf("reverse %s :%d closed: %v", req.Protocol, req.Port, err)
	}
	log.Printf("reverse %s unbound :%d for client %s", req.Protocol, req.Port, conn.RemoteAddr())
}

func (s *Server) listen(key, protocol string, port int) (io.Closer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if old, ok := s.binds[key]; ok {
		log.Printf("reverse bind %s: replacing previous bind", key)
		_ = old.Close()
		delete(s.binds, key)
	}

	var listener io.Closer
	var err error
	switch protocol {
	case ProtocolTCP:
		listener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	case ProtocolUDP:
		listener, err = net.ListenUDP("udp", &net.UDPAddr{Port: port})
	default:
		return nil, fmt.Errorf("unsupported protocol %q", protocol)
	}
	if err != nil {
		return nil, err
	}
	s.binds[key] = listener
	return listener, nil
}

func (s *Server) unbind(key string, listener io.Closer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binds[key] == listener {
		delete(s.binds, key)
	}
	_ = listener.Close()
}
