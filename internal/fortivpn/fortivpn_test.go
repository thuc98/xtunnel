package fortivpn

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"

	"xtunnel/internal/config"
)

var (
	gatewayIP  = netip.MustParseAddr("10.9.0.1")
	assignedIP = netip.MustParseAddr("10.9.0.2")
)

type fakeGateway struct {
	t       *testing.T
	srv     *httptest.Server
	logins  atomic.Int32
	tunnels atomic.Int32

	mu   sync.Mutex
	conn net.Conn
}

func newFakeGateway(t *testing.T) *fakeGateway {
	g := &fakeGateway{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/remote/logincheck", g.logincheck)
	for _, path := range []string{"/remote/index", "/remote/fortisslvpn"} {
		mux.HandleFunc(path, g.requireCookie(func(w http.ResponseWriter, r *http.Request) {}))
	}
	mux.HandleFunc("/remote/fortisslvpn_xml", g.requireCookie(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<?xml version='1.0' encoding='utf-8'?><sslvpn-tunnel ver='2'><ipv4>"+
			"<dns ip='"+gatewayIP.String()+"' /><assigned-addr ipv4='"+assignedIP.String()+"' /></ipv4></sslvpn-tunnel>")
	}))
	mux.HandleFunc("/remote/sslvpn-tunnel", g.requireCookie(g.tunnel))
	g.srv = httptest.NewTLSServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGateway) vpnConfig() config.FortiVPNConfig {
	host, port, _ := net.SplitHostPort(g.srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	sum := sha256.Sum256(g.srv.Certificate().Raw)
	return config.FortiVPNConfig{
		Name: "office", Host: host, Port: p, Username: "thuc", Password: "secret",
		TrustedCert: hex.EncodeToString(sum[:]), UserAgent: "test",
		ReconnectIntervalSec: 1,
	}
}

func (g *fakeGateway) dropTunnel() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.conn != nil {
		_ = g.conn.Close()
	}
}

func (g *fakeGateway) logincheck(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	switch {
	case form.Get("code") == "123456" && form.Get("reqid") == "77" && form.Get("magic") == "1-abc":
		g.logins.Add(1)
		http.SetCookie(w, &http.Cookie{Name: "SVPNCOOKIE", Value: "session-" + strconv.Itoa(int(g.logins.Load()))})
		_, _ = io.WriteString(w, "ret=1,redir=/remote/fortisslvpn_xml")
	case form.Get("username") == "thuc" && form.Get("credential") == "secret":
		_, _ = io.WriteString(w, "ret=6,actionurl=/remote/logincheck,tokeninfo=email,reqid=77,polid=1-1,grp=g,portal=p,peer=thuc,magic=1-abc")
	default:
		_, _ = io.WriteString(w, "ret=0,redir=/remote/login")
	}
}

func (g *fakeGateway) requireCookie(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("SVPNCOOKIE")
		if err != nil || !strings.HasPrefix(c.Value, "session-") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

func (g *fakeGateway) tunnel(w http.ResponseWriter, r *http.Request) {
	conn, brw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	g.mu.Lock()
	g.conn = conn
	g.mu.Unlock()
	g.tunnels.Add(1)

	n, err := newNetStack(gatewayIP, 1400, nil)
	if err != nil {
		g.t.Error(err)
		return
	}
	defer n.close()
	startEchoServers(g.t, n)

	fc := newFrameConn(conn)

	fc.r = brw.Reader
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = n.pumpOutbound(ctx, func(pkt []byte) error { return fc.writeFrame(protoIPv4, pkt) })
	}()
	g.servePPP(fc, n)
}

func (g *fakeGateway) servePPP(fc *frameConn, n *netStack) {
	send := func(proto uint16, code, id byte, data []byte) {
		_ = fc.writeFrame(proto, cpPacket{code: code, id: id, data: data}.marshal())
	}
	send(protoLCP, codeConfReq, 1, marshalOptions([]cpOption{
		{typ: lcpOptMRU, data: binary.BigEndian.AppendUint16(nil, 1400)},
		{typ: lcpOptMagic, data: []byte{1, 2, 3, 4}},
	}))
	for {
		frame, err := fc.readFrame()
		if err != nil {
			return
		}
		proto := binary.BigEndian.Uint16(frame)
		if proto == protoIPv4 {
			n.inject(frame[2:])
			continue
		}
		pkt, ok := parseCP(frame[2:])
		if !ok {
			continue
		}
		switch {
		case proto == protoLCP && pkt.code == codeConfReq:
			send(protoLCP, codeConfAck, pkt.id, pkt.data)
		case proto == protoLCP && pkt.code == codeConfAck:
			send(protoIPCP, codeConfReq, 1, marshalOptions([]cpOption{{typ: ipcpOptAddr, data: gatewayIP.AsSlice()}}))
		case proto == protoLCP && pkt.code == codeEchoReq:
			send(protoLCP, codeEchoReply, pkt.id, pkt.data)
		case proto == protoIPCP && pkt.code == codeConfReq:
			opts, _ := parseOptions(pkt.data)
			var nak, rej []cpOption
			for _, o := range opts {
				switch o.typ {
				case ipcpOptAddr:
					if netip.AddrFrom4([4]byte(o.data)) != assignedIP {
						nak = append(nak, cpOption{typ: o.typ, data: assignedIP.AsSlice()})
					}
				case ipcpOptDNS1:
					if netip.AddrFrom4([4]byte(o.data)) != gatewayIP {
						nak = append(nak, cpOption{typ: o.typ, data: gatewayIP.AsSlice()})
					}
				default:
					rej = append(rej, o)
				}
			}
			switch {
			case len(rej) > 0:
				send(protoIPCP, codeConfRej, pkt.id, marshalOptions(rej))
			case len(nak) > 0:
				send(protoIPCP, codeConfNak, pkt.id, marshalOptions(nak))
			default:
				send(protoIPCP, codeConfAck, pkt.id, pkt.data)
			}
		}
	}
}

func startEchoServers(t *testing.T, n *netStack) {
	addr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(gatewayIP.As4()), Port: 7}
	ln, err := gonet.ListenTCP(n.stack, addr, ipv4.ProtocolNumber)
	if err != nil {
		t.Error(err)
		return
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	uc, err := gonet.DialUDP(n.stack, &addr, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Error(err)
		return
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			k, from, err := uc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = uc.WriteTo(append([]byte("echo:"), buf[:k]...), from)
		}
	}()
}

func expectEcho(t *testing.T, s *Supervisor, network string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := s.DialContext(ctx, network, gatewayIP.String()+":7")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	want := "ping"
	if network == "udp" {
		want = "echo:ping"
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s echo = %q, want %q", network, got, want)
	}
}

func TestTunnelWithOTP(t *testing.T) {
	g := newFakeGateway(t)
	var otpCalls atomic.Int32
	s := NewSupervisor(g.vpnConfig(), func(ctx context.Context, vpn, prompt string) (string, error) {
		otpCalls.Add(1)
		return "123456", nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()
	waitCtx, waitCancel := context.WithTimeout(ctx, 10*time.Second)
	defer waitCancel()
	if err := s.WaitUp(waitCtx); err != nil {
		t.Fatal(err)
	}

	expectEcho(t, s, "tcp")
	expectEcho(t, s, "udp")

	g.dropTunnel()
	deadline := time.Now().Add(10 * time.Second)
	for g.tunnels.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	for time.Now().Before(deadline) {
		if conn, err := s.DialContext(ctx, "tcp", gatewayIP.String()+":7"); err == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	expectEcho(t, s, "tcp")
	if got := otpCalls.Load(); got != 1 {
		t.Fatalf("otp asked %d times, want 1", got)
	}
	if got := g.logins.Load(); got != 1 {
		t.Fatalf("logged in %d times, want 1", got)
	}
}

func TestLoginRejected(t *testing.T) {
	g := newFakeGateway(t)
	cfg := g.vpnConfig()
	cfg.Password = "wrong"
	err := newSession(cfg, nil).login(context.Background())
	if err == nil || !strings.Contains(err.Error(), "login rejected") {
		t.Fatalf("got %v", err)
	}
}

func TestUntrustedCertificate(t *testing.T) {
	g := newFakeGateway(t)
	cfg := g.vpnConfig()
	want := cfg.TrustedCert
	cfg.TrustedCert = ""
	err := newSession(cfg, nil).login(context.Background())
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error should name the certificate digest %s: %v", want, err)
	}
}

func TestParseTunnelConfig(t *testing.T) {
	cfg := parseTunnelConfig(`<sslvpn-tunnel ver='2' dtls='1'><ipv4><dns ip='10.0.0.53' /><dns domain='corp.local' />` +
		`<dns ip='10.0.0.54' /><assigned-addr ipv4='10.212.134.200' /><split-tunnel-info><addr ip='10.0.0.0' mask='255.0.0.0' />` +
		`</split-tunnel-info></ipv4></sslvpn-tunnel>`)
	if cfg.addr.String() != "10.212.134.200" {
		t.Fatalf("addr = %s", cfg.addr)
	}
	if len(cfg.dns) != 2 || cfg.dns[0].String() != "10.0.0.53" || cfg.dns[1].String() != "10.0.0.54" {
		t.Fatalf("dns = %v", cfg.dns)
	}
}

func TestInsecureSkipVerify(t *testing.T) {
	g := newFakeGateway(t)
	cfg := g.vpnConfig()
	cfg.TrustedCert = ""
	cfg.InsecureSkipVerify = true
	s := newSession(cfg, func(context.Context, string, string) (string, error) { return "123456", nil })
	if err := s.login(context.Background()); err != nil {
		t.Fatal(err)
	}
}
