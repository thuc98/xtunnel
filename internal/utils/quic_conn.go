package utils

import (
	"errors"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

type QuicNetConn struct {
	quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func QuicStreamToNetConn(stream quic.Stream, conn quic.Connection) net.Conn {
	return &QuicNetConn{
		Stream:     stream,
		localAddr:  conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
	}
}

func (c *QuicNetConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *QuicNetConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *QuicNetConn) SetDeadline(t time.Time) error {
	if c.Stream == nil {
		return errors.New("quic stream is nil")
	}
	return c.Stream.SetDeadline(t)
}

func (c *QuicNetConn) SetReadDeadline(t time.Time) error {
	if c.Stream == nil {
		return errors.New("quic stream is nil")
	}
	return c.Stream.SetReadDeadline(t)
}

func (c *QuicNetConn) SetWriteDeadline(t time.Time) error {
	if c.Stream == nil {
		return errors.New("quic stream is nil")
	}
	return c.Stream.SetWriteDeadline(t)
}

func (c *QuicNetConn) Close() error {
	if c == nil || c.Stream == nil {
		return nil
	}
	err := c.Stream.Close()
	c.Stream.CancelRead(0)
	return err
}

func (c *QuicNetConn) CloseWrite() error {
	if c == nil || c.Stream == nil {
		return nil
	}
	return c.Stream.Close()
}
