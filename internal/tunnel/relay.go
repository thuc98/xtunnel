package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"xtunnel/internal/utils"
)

const (
	maxUDPPacketSize      = 64*1024 - 1
	udpSessionQueueSize   = 256
	defaultUDPIdleTimeout = 60 * time.Second
)

func udpIdleTimeout(sec int) time.Duration {
	if sec <= 0 {
		return defaultUDPIdleTimeout
	}
	return time.Duration(sec) * time.Second
}

type openStreamFunc func(context.Context) (net.Conn, error)

type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

var defaultDialer net.Dialer

func serveTCPListener(ctx context.Context, ln net.Listener, open openStreamFunc, target string) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	for {
		localConn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go func() {
			defer localConn.Close()

			streamConn, err := open(ctx)
			if err != nil {
				log.Printf("open stream for %s: %v", target, err)
				return
			}
			defer streamConn.Close()

			utils.Pipe(streamConn, localConn)
		}()
	}
}

func serveUDPConn(ctx context.Context, conn *net.UDPConn, open openStreamFunc, target string, idleTimeout time.Duration) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	var mu sync.Mutex
	sessions := make(map[string]*udpSession)

	buf := make([]byte, maxUDPPacketSize)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		packet := append([]byte(nil), buf[:n]...)
		key := clientAddr.String()

		mu.Lock()
		s, ok := sessions[key]
		if !ok {
			s = &udpSession{packets: make(chan []byte, udpSessionQueueSize)}
			sessions[key] = s
			go func() {
				s.run(ctx, conn, clientAddr, open, target, idleTimeout)
				mu.Lock()
				if sessions[key] == s {
					delete(sessions, key)
				}
				mu.Unlock()
			}()
		}
		mu.Unlock()

		select {
		case s.packets <- packet:
		default:
		}
	}
}

type udpSession struct {
	packets chan []byte
	idle    idleTracker
}

func (s *udpSession) run(ctx context.Context, localConn *net.UDPConn, clientAddr *net.UDPAddr, open openStreamFunc, target string, idleTimeout time.Duration) {
	streamConn, err := open(ctx)
	if err != nil {
		log.Printf("open udp stream for %s: %v", target, err)
		return
	}
	defer streamConn.Close()
	s.idle.touch()

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, maxUDPPacketSize)
		for {
			n, err := streamConn.Read(buf)
			if err != nil {
				return
			}
			s.idle.touch()
			if _, err := localConn.WriteToUDP(buf[:n], clientAddr); err != nil {
				log.Printf("write udp reply to client: %v", err)
				return
			}
		}
	}()

	ticker := time.NewTicker(idleTimeout / 4)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-readDone:
			return
		case packet := <-s.packets:
			s.idle.touch()
			if _, err := streamConn.Write(packet); err != nil {
				log.Printf("write udp packet to stream: %v", err)
				return
			}
		case <-ticker.C:
			if s.idle.expired(idleTimeout) {
				return
			}
		}
	}
}

func relayTCP(dial DialFunc, target string, streamReader io.Reader, streamConn net.Conn) {
	targetConn, err := dial(context.Background(), "tcp", target)
	if err != nil {
		log.Printf("dial tcp target %s: %v", target, err)
		return
	}
	defer targetConn.Close()

	utils.PipeBidirectional(
		&streamConnReader{reader: streamReader, conn: streamConn},
		&connCloseWriter{Conn: targetConn},
		0,
	)
}

func relayUDP(dial DialFunc, target string, streamReader io.Reader, streamConn net.Conn, idleTimeout time.Duration) {
	targetConn, err := dial(context.Background(), "udp", target)
	if err != nil {
		log.Printf("dial udp target %s: %v", target, err)
		return
	}
	defer targetConn.Close()

	stream := newFramedPacketConn(streamReader, streamConn)
	var idle idleTracker
	idle.touch()

	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, maxUDPPacketSize)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				return
			}
			idle.touch()
			if _, err := targetConn.Write(buf[:n]); err != nil {
				log.Printf("write udp target %s: %v", target, err)
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, maxUDPPacketSize)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				return
			}
			idle.touch()
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(idleTimeout / 4)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if idle.expired(idleTimeout) {
				return
			}
		}
	}
}

type idleTracker struct {
	last atomic.Int64
}

func (t *idleTracker) touch() {
	t.last.Store(time.Now().UnixNano())
}

func (t *idleTracker) expired(timeout time.Duration) bool {
	return time.Since(time.Unix(0, t.last.Load())) > timeout
}

type framedPacketConn struct {
	net.Conn
	reader io.Reader
	header [2]byte
	wmu    sync.Mutex
}

func newFramedPacketConn(reader io.Reader, conn net.Conn) *framedPacketConn {
	return &framedPacketConn{Conn: conn, reader: reader}
}

func (c *framedPacketConn) Read(p []byte) (int, error) {
	if _, err := io.ReadFull(c.reader, c.header[:]); err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(c.header[:]))
	if size <= len(p) {
		if _, err := io.ReadFull(c.reader, p[:size]); err != nil {
			return 0, unexpectedEOF(err)
		}
		return size, nil
	}
	if _, err := io.ReadFull(c.reader, p); err != nil {
		return 0, unexpectedEOF(err)
	}
	if _, err := io.CopyN(io.Discard, c.reader, int64(size-len(p))); err != nil {
		return 0, unexpectedEOF(err)
	}
	return len(p), nil
}

func (c *framedPacketConn) Write(p []byte) (int, error) {
	if len(p) > maxUDPPacketSize {
		return 0, fmt.Errorf("udp packet too large: %d bytes", len(p))
	}
	frame := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(frame, uint16(len(p)))
	copy(frame[2:], p)

	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

type streamConnReader struct {
	reader io.Reader
	conn   net.Conn
}

func (c *streamConnReader) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *streamConnReader) Write(p []byte) (int, error) {
	return c.conn.Write(p)
}

func (c *streamConnReader) Close() error {
	return c.conn.Close()
}

func (c *streamConnReader) CloseWrite() error {
	if closeWriter, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return nil
}

type connCloseWriter struct {
	net.Conn
}

func (c *connCloseWriter) CloseWrite() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
