package tunnel

import (
	"context"
	"io"
	"log"
	"net"
	"time"

	"xtunnel/internal/utils"
)

type StreamAccepter interface {
	AcceptStream(context.Context) (net.Conn, error)
	Close() error
	RemoteAddr() string
}

type Server struct {
	secretKey string
}

func NewServer(secretKey string) *Server {
	return &Server{secretKey: secretKey}
}

func (s *Server) ServeConnection(ctx context.Context, conn StreamAccepter) {
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
		go s.HandleStream(streamConn)
	}
}

func (s *Server) HandleStream(streamConn net.Conn) {
	defer streamConn.Close()

	req, reader, err := ReadStreamRequest(streamConn)
	if err != nil {
		log.Printf("read stream request: %v", err)
		return
	}
	if req.SecretKey != s.secretKey {
		log.Printf("reject stream: invalid secret key")
		return
	}

	switch req.Protocol {
	case ProtocolTCP:
		s.handleTCP(req.Target, reader, streamConn)
	case ProtocolUDP:
		s.handleUDP(req.Target, reader, streamConn)
	default:
		log.Printf("unsupported protocol %q", req.Protocol)
	}
}

func (s *Server) handleTCP(target string, streamReader io.Reader, streamConn net.Conn) {
	targetConn, err := net.Dial("tcp", target)
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

func (s *Server) handleUDP(target string, streamReader io.Reader, streamConn net.Conn) {
	targetConn, err := net.Dial("udp", target)
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

	_ = targetConn.SetReadDeadline(time.Now().Add(10 * time.Second))
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
