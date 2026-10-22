package tunnel

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"time"

	"xtunnel/internal/utils"
)

const udpReplyTimeout = 10 * time.Second

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

func serveUDPConn(ctx context.Context, conn *net.UDPConn, open openStreamFunc, target string) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

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
		go handleUDPPacket(ctx, conn, clientAddr, packet, open, target)
	}
}

func handleUDPPacket(ctx context.Context, localConn *net.UDPConn, clientAddr *net.UDPAddr, packet []byte, open openStreamFunc, target string) {
	streamConn, err := open(ctx)
	if err != nil {
		log.Printf("open udp stream for %s: %v", target, err)
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

	_ = streamConn.SetReadDeadline(time.Now().Add(udpReplyTimeout))
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

func relayUDP(dial DialFunc, target string, streamReader io.Reader, streamConn net.Conn) {
	targetConn, err := dial(context.Background(), "udp", target)
	if err != nil {
		log.Printf("dial udp target %s: %v", target, err)
		return
	}
	defer targetConn.Close()

	packet, err := io.ReadAll(streamReader)
	if err != nil {
		log.Printf("read udp packet from stream: %v", err)
		return
	}
	if len(packet) == 0 {
		return
	}
	if _, err := targetConn.Write(packet); err != nil {
		log.Printf("write udp target %s: %v", target, err)
		return
	}

	_ = targetConn.SetReadDeadline(time.Now().Add(udpReplyTimeout))
	buf := make([]byte, 64*1024)
	n, err := targetConn.Read(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return
		}
		log.Printf("read udp target %s: %v", target, err)
		return
	}
	_, _ = streamConn.Write(buf[:n])
}

type datagramConn struct {
	net.Conn
	reply *bytes.Reader
}

func (c *datagramConn) Read(p []byte) (int, error) {
	if c.reply == nil {
		buf := make([]byte, 64*1024)
		n, err := c.Conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				err = io.EOF
			}
			return 0, err
		}
		c.reply = bytes.NewReader(buf[:n])
	}
	return c.reply.Read(p)
}

func (c *datagramConn) CloseWrite() error {
	return nil
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
	if tcpConn, ok := c.Conn.(*net.TCPConn); ok {
		return tcpConn.CloseWrite()
	}
	return nil
}
