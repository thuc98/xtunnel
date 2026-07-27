package manager

import (
	"context"
	"io"
	"net"

	"github.com/quic-go/quic-go"

	"xtunnel/internal/utils"
)

type XConnection interface {
	OpenStream(context.Context) (net.Conn, error)
	AcceptStream(context.Context) (net.Conn, error)
	Close() error
	RemoteAddr() string
}

type QuicXConnection struct {
	conn quic.Connection
}

func NewQuicXConnection(conn quic.Connection) XConnection {
	return &QuicXConnection{conn: conn}
}

func (x *QuicXConnection) OpenStream(ctx context.Context) (net.Conn, error) {
	if x == nil || x.conn == nil {
		return nil, io.ErrClosedPipe
	}
	stream, err := x.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return utils.QuicStreamToNetConn(stream, x.conn), nil
}

func (x *QuicXConnection) AcceptStream(ctx context.Context) (net.Conn, error) {
	if x == nil || x.conn == nil {
		return nil, io.ErrClosedPipe
	}
	stream, err := x.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return utils.QuicStreamToNetConn(stream, x.conn), nil
}

func (x *QuicXConnection) Close() error {
	if x == nil || x.conn == nil {
		return nil
	}
	return x.conn.CloseWithError(0, "")
}

func (x *QuicXConnection) RemoteAddr() string {
	if x == nil || x.conn == nil {
		return ""
	}
	return x.conn.RemoteAddr().String()
}
