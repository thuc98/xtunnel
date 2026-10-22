package fortivpn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID = 1

type netStack struct {
	stack *stack.Stack
	ep    *channel.Endpoint
	dns   []netip.Addr
}

func newNetStack(addr netip.Addr, mtu int, dns []netip.Addr) (*netStack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(512, uint32(mtu), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create nic: %s", err)
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(addr.As4()).WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add address: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	sack := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	return &netStack{stack: s, ep: ep, dns: dns}, nil
}

func (n *netStack) inject(pkt []byte) {
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	n.ep.InjectInbound(ipv4.ProtocolNumber, pb)
	pb.DecRef()
}

func (n *netStack) pumpOutbound(ctx context.Context, write func([]byte) error) error {
	for {
		pb := n.ep.ReadContext(ctx)
		if pb == nil {
			return ctx.Err()
		}
		view := pb.ToView()
		err := write(view.AsSlice())
		view.Release()
		pb.DecRef()
		if err != nil {
			return err
		}
	}
}

func (n *netStack) close() {
	n.ep.Close()
	n.stack.Close()
}

func (n *netStack) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}
	ip, err := n.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	return n.dialIP(ctx, network, netip.AddrPortFrom(ip, uint16(port)))
}

func (n *netStack) dialIP(ctx context.Context, network string, addr netip.AddrPort) (net.Conn, error) {
	full := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(addr.Addr().As4()), Port: addr.Port()}
	switch network {
	case "tcp", "tcp4":
		return gonet.DialContextTCP(ctx, n.stack, full, ipv4.ProtocolNumber)
	case "udp", "udp4":
		return gonet.DialUDP(n.stack, nil, &full, ipv4.ProtocolNumber)
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
}

func (n *netStack) resolve(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !ip.Unmap().Is4() {
			return netip.Addr{}, fmt.Errorf("only IPv4 targets are supported through the VPN: %s", host)
		}
		return ip.Unmap(), nil
	}

	var lastErr error
	for _, server := range n.dns {
		server := server
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return n.dialIP(ctx, network, netip.AddrPortFrom(server, 53))
			},
		}
		ips, err := r.LookupNetIP(ctx, "ip4", host)
		if err == nil && len(ips) > 0 {
			return ips[0].Unmap(), nil
		}
		lastErr = err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err == nil && len(ips) > 0 {
		return ips[0].Unmap(), nil
	}
	if err == nil {
		err = lastErr
	}
	return netip.Addr{}, fmt.Errorf("resolve %s: %w", host, err)
}
