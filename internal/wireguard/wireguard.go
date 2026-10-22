package wireguard

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"xtunnel/internal/config"
	"xtunnel/internal/metrics"
)

const handshakeFresh = 3 * time.Minute

type Status struct {
	Name          string       `json:"name"`
	Endpoint      string       `json:"endpoint"`
	State         string       `json:"state"`
	Address       string       `json:"address,omitempty"`
	DNS           []netip.Addr `json:"dns,omitempty"`
	Error         string       `json:"error,omitempty"`
	LastHandshake time.Time    `json:"last_handshake"`
	Since         time.Time    `json:"since"`
}

type Tunnel struct {
	cfg  config.WireGuardConfig
	addr []netip.Addr
	dns  []netip.Addr

	mu      sync.RWMutex
	dev     *device.Device
	tnet    *netstack.Net
	err     error
	started time.Time
}

func New(cfg config.WireGuardConfig) *Tunnel {
	t := &Tunnel{cfg: cfg}
	for _, a := range cfg.Addresses {
		if ip, err := config.ParseWGAddress(a); err == nil {
			t.addr = append(t.addr, ip)
		}
	}
	for _, d := range cfg.DNS {
		if ip, err := netip.ParseAddr(d); err == nil {
			t.dns = append(t.dns, ip)
		}
	}
	return t
}

func (t *Tunnel) Run(ctx context.Context) error {
	err := t.start()
	t.mu.Lock()
	t.err, t.started = err, time.Now()
	t.mu.Unlock()
	if err != nil {
		log.Printf("wireguard %s: %v", t.cfg.Name, err)
		<-ctx.Done()
		return err
	}
	log.Printf("wireguard %s up: address %v, peer %s", t.cfg.Name, t.addr, t.cfg.Peers[0].Endpoint)
	<-ctx.Done()

	t.mu.Lock()
	dev := t.dev
	t.dev, t.tnet = nil, nil
	t.mu.Unlock()
	dev.Close()
	return ctx.Err()
}

func (t *Tunnel) start() error {
	tunDev, tnet, err := netstack.CreateNetTUN(t.addr, t.dns, t.cfg.MTU)
	if err != nil {
		return fmt.Errorf("create netstack: %w", err)
	}
	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, args ...any) {
			log.Printf("wireguard "+t.cfg.Name+": "+format, args...)
		},
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	uapi, err := t.uapiConfig()
	if err != nil {
		dev.Close()
		return err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return fmt.Errorf("configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("bring device up: %w", err)
	}
	t.mu.Lock()
	t.dev, t.tnet = dev, tnet
	t.mu.Unlock()
	return nil
}

func keyHex(k string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("invalid WireGuard key")
	}
	return hex.EncodeToString(b), nil
}

func (t *Tunnel) uapiConfig() (string, error) {
	var b strings.Builder
	priv, err := keyHex(t.cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private_key: %w", err)
	}
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	for _, p := range t.cfg.Peers {
		pub, err := keyHex(p.PublicKey)
		if err != nil {
			return "", fmt.Errorf("public_key: %w", err)
		}
		fmt.Fprintf(&b, "public_key=%s\n", pub)
		if p.PresharedKey != "" {
			psk, err := keyHex(p.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("preshared_key: %w", err)
			}
			fmt.Fprintf(&b, "preshared_key=%s\n", psk)
		}
		endpoint, err := resolveEndpoint(p.Endpoint)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
		}
		for _, a := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
	}
	return b.String(), nil
}

func resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip, mustPort(port)).String(), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("resolve endpoint %s: %v", host, err)
	}
	return netip.AddrPortFrom(ips[0].Unmap(), mustPort(port)).String(), nil
}

func mustPort(p string) uint16 {
	n, _ := strconv.ParseUint(p, 10, 16)
	return uint16(n)
}

func (t *Tunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	t.mu.RLock()
	tnet := t.tnet
	t.mu.RUnlock()
	if tnet == nil {
		return nil, fmt.Errorf("wireguard %s is down", t.cfg.Name)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		ip, err := t.resolve(ctx, tnet, host)
		if err != nil {
			return nil, err
		}
		address = net.JoinHostPort(ip, port)
	}
	c, err := tnet.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return metrics.Get(metrics.VPNKey(t.cfg.Name)).Wrap(c), nil
}

func (t *Tunnel) resolve(ctx context.Context, tnet *netstack.Net, host string) (string, error) {
	if len(t.dns) > 0 {
		if addrs, err := tnet.LookupContextHost(ctx, host); err == nil && len(addrs) > 0 {
			return addrs[0], nil
		}
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("resolve %s: %v", host, err)
	}
	return ips[0].Unmap().String(), nil
}

func (t *Tunnel) Status() Status {
	t.mu.RLock()
	dev, err, started := t.dev, t.err, t.started
	t.mu.RUnlock()

	st := Status{Name: t.cfg.Name, State: "connecting", DNS: t.dns, Since: started}
	if len(t.cfg.Peers) > 0 {
		st.Endpoint = t.cfg.Peers[0].Endpoint
	}
	if len(t.addr) > 0 {
		st.Address = t.addr[0].String()
	}
	if err != nil {
		st.State, st.Error = "down", err.Error()
		return st
	}
	if dev == nil {
		return st
	}
	uapi, err := dev.IpcGet()
	if err != nil {
		return st
	}
	sc := bufio.NewScanner(strings.NewReader(uapi))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		if k == "last_handshake_time_sec" {
			if sec, _ := strconv.ParseInt(v, 10, 64); sec > 0 && time.Unix(sec, 0).After(st.LastHandshake) {
				st.LastHandshake = time.Unix(sec, 0)
			}
		}
	}
	if !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) < handshakeFresh {
		st.State = "up"
	} else if !st.LastHandshake.IsZero() {
		st.Error = "no handshake since " + st.LastHandshake.Format(time.TimeOnly)
	}
	return st
}
