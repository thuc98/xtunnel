package metrics

import (
	"net"
	"strconv"
	"sync"
	"sync/atomic"
)

type Stats struct {
	active atomic.Int64
	total  atomic.Uint64
	up     atomic.Uint64
	down   atomic.Uint64
}

type Snapshot struct {
	Active int64  `json:"active"`
	Total  uint64 `json:"total"`
	Up     uint64 `json:"up"`
	Down   uint64 `json:"down"`
}

var registry sync.Map

func Get(key string) *Stats {
	if s, ok := registry.Load(key); ok {
		return s.(*Stats)
	}
	s, _ := registry.LoadOrStore(key, &Stats{})
	return s.(*Stats)
}

func Lookup(key string) Snapshot {
	if s, ok := registry.Load(key); ok {
		return s.(*Stats).Snapshot()
	}
	return Snapshot{}
}

func (s *Stats) Snapshot() Snapshot {
	return Snapshot{Active: s.active.Load(), Total: s.total.Load(), Up: s.up.Load(), Down: s.down.Load()}
}

func (a Snapshot) Add(b Snapshot) Snapshot {
	return Snapshot{Active: a.Active + b.Active, Total: a.Total + b.Total, Up: a.Up + b.Up, Down: a.Down + b.Down}
}

func (s *Stats) Wrap(c net.Conn) net.Conn {
	s.active.Add(1)
	s.total.Add(1)
	return &conn{Conn: c, stats: s}
}

type conn struct {
	net.Conn
	stats  *Stats
	closed atomic.Bool
}

func (c *conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.stats.down.Add(uint64(n))
	return n, err
}

func (c *conn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.stats.up.Add(uint64(n))
	return n, err
}

func (c *conn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.stats.active.Add(-1)
	}
	return c.Conn.Close()
}

func (c *conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func RouteKey(protocol string, port int) string {
	return "route/" + protocol + "/" + strconv.Itoa(port)
}

func ReverseKey(tunnel, protocol string, port int) string {
	return "reverse/" + tunnel + "/" + protocol + "/" + strconv.Itoa(port)
}

func SocksKey(kind, name string) string {
	return "socks/" + kind + "/" + name
}

func VPNKey(name string) string {
	return "vpn/" + name
}
