package socks5

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"xtunnel/internal/metrics"
	"xtunnel/internal/utils"
)

const (
	version5 = 5

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xff

	cmdConnect = 1

	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4

	repSucceeded          = 0
	repGeneralFailure     = 1
	repHostUnreachable    = 4
	repCommandUnsupported = 7
	repAddrUnsupported    = 8
)

type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

type Server struct {
	Name     string
	Dial     DialFunc
	Username string
	Password string
	Stats    *metrics.Stats
}

func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	log.Printf("socks5 %s listening on %s", s.Name, addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)

	if err := s.negotiate(br, conn); err != nil {
		log.Printf("socks5 %s %s: %v", s.Name, conn.RemoteAddr(), err)
		return
	}
	target, err := readRequest(br, conn)
	if err != nil {
		log.Printf("socks5 %s %s: %v", s.Name, conn.RemoteAddr(), err)
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	remote, err := s.Dial(dialCtx, "tcp", target)
	cancel()
	if err != nil {
		log.Printf("socks5 %s connect %s: %v", s.Name, target, err)
		_ = writeReply(conn, repHostUnreachable)
		return
	}
	if s.Stats != nil {
		remote = s.Stats.Wrap(remote)
	}
	defer remote.Close()
	if err := writeReply(conn, repSucceeded); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	utils.Pipe(remote, &bufferedConn{Conn: conn, r: br})
}

func (s *Server) negotiate(br *bufio.Reader, conn net.Conn) error {
	var head [2]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return err
	}
	if head[0] != version5 {
		return fmt.Errorf("unsupported SOCKS version %d", head[0])
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}

	want := byte(methodNoAuth)
	if s.Username != "" {
		want = methodUserPass
	}
	offered := false
	for _, m := range methods {
		offered = offered || m == want
	}
	if !offered {
		_, _ = conn.Write([]byte{version5, methodNoAcceptable})
		return errors.New("client does not offer the required authentication method")
	}
	if _, err := conn.Write([]byte{version5, want}); err != nil {
		return err
	}
	if want == methodUserPass {
		return s.checkUserPass(br, conn)
	}
	return nil
}

func (s *Server) checkUserPass(br *bufio.Reader, conn net.Conn) error {
	readField := func() ([]byte, error) {
		n, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		b := make([]byte, n)
		_, err = io.ReadFull(br, b)
		return b, err
	}
	ver, err := br.ReadByte()
	if err != nil {
		return err
	}
	if ver != 1 {
		return fmt.Errorf("unsupported auth version %d", ver)
	}
	user, err := readField()
	if err != nil {
		return err
	}
	pass, err := readField()
	if err != nil {
		return err
	}
	userOK := subtle.ConstantTimeCompare(user, []byte(s.Username)) == 1
	passOK := subtle.ConstantTimeCompare(pass, []byte(s.Password)) == 1
	if !userOK || !passOK {
		_, _ = conn.Write([]byte{1, 1})
		return errors.New("authentication failed")
	}
	_, err = conn.Write([]byte{1, 0})
	return err
}

func readRequest(br *bufio.Reader, conn net.Conn) (string, error) {
	var head [4]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return "", err
	}
	if head[0] != version5 {
		return "", fmt.Errorf("unsupported SOCKS version %d", head[0])
	}

	var host string
	switch head[3] {
	case atypIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case atypDomain:
		n, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		name := make([]byte, n)
		if _, err := io.ReadFull(br, name); err != nil {
			return "", err
		}
		host = string(name)
	case atypIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	default:
		_ = writeReply(conn, repAddrUnsupported)
		return "", fmt.Errorf("unsupported address type %d", head[3])
	}
	var port [2]byte
	if _, err := io.ReadFull(br, port[:]); err != nil {
		return "", err
	}
	if head[1] != cmdConnect {
		_ = writeReply(conn, repCommandUnsupported)
		return "", fmt.Errorf("unsupported command %d (only CONNECT)", head[1])
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func writeReply(conn net.Conn, rep byte) error {

	_, err := conn.Write([]byte{version5, rep, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
