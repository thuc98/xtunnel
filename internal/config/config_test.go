package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func vpn(name string) FortiVPNConfig {
	return FortiVPNConfig{Name: name, Host: "vpn.example.com", Username: "u", Password: "p"}
}

func tun(name string) TunnelConfig {
	return TunnelConfig{Name: name, ClientConfig: ClientConfig{ServerAddr: "1.2.3.4:443", SecretKey: "k"}}
}

func TestValidateTunnels(t *testing.T) {
	route := func(tunnel, vpn string) RouteConfig {
		return RouteConfig{LocalPort: 1, Target: "10.0.0.1:1", Protocol: "tcp", Tunnel: tunnel, VPN: vpn}
	}
	tests := []struct {
		name       string
		cfg        Config
		wantErr    string
		wantTunnel string
	}{
		{name: "single tunnel is the default", cfg: Config{Tunnels: []TunnelConfig{tun("sg")}, Routes: []RouteConfig{route("", "")}}, wantTunnel: "sg"},
		{name: "named tunnel", cfg: Config{Tunnels: []TunnelConfig{tun("sg"), tun("hk")}, Routes: []RouteConfig{route("hk", "")}}, wantTunnel: "hk"},
		{name: "several tunnels need a name", cfg: Config{Tunnels: []TunnelConfig{tun("sg"), tun("hk")}, Routes: []RouteConfig{route("", "")}}, wantErr: "tunnel is required"},
		{name: "unknown tunnel", cfg: Config{Tunnels: []TunnelConfig{tun("sg")}, Routes: []RouteConfig{route("hk", "")}}, wantErr: `unknown tunnel "hk"`},
		{name: "no tunnel", cfg: Config{Routes: []RouteConfig{route("", "")}}, wantErr: "no tunnel is configured"},
		{name: "vpn route needs no tunnel", cfg: Config{FortiVPNs: []FortiVPNConfig{vpn("dev")}, Routes: []RouteConfig{route("", "dev")}}},
		{name: "tunnel and vpn conflict", cfg: Config{Tunnels: []TunnelConfig{tun("sg")}, FortiVPNs: []FortiVPNConfig{vpn("dev")}, Routes: []RouteConfig{route("sg", "dev")}}, wantErr: "either tunnel or vpn"},
		{name: "duplicate tunnel", cfg: Config{Tunnels: []TunnelConfig{tun("sg"), tun("sg")}}, wantErr: `duplicate name "sg"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.cfg.Routes[0].Tunnel != tt.wantTunnel {
				t.Fatalf("tunnel = %q, want %q", tt.cfg.Routes[0].Tunnel, tt.wantTunnel)
			}
		})
	}
}

func TestValidateFortiVPNs(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name: "routes pick vpns by name",
			cfg: Config{
				Tunnels:       []TunnelConfig{tun("main")},
				FortiVPNs:     []FortiVPNConfig{vpn("office"), vpn("lab")},
				Routes:        []RouteConfig{{LocalPort: 1, Target: "10.0.0.1:1", Protocol: "tcp", VPN: "office"}},
				ReverseRoutes: []ReverseRouteConfig{{RemotePort: 1, Target: "10.0.0.2:1", Protocol: "tcp", VPN: "lab"}},
			},
		},
		{
			name:    "duplicate name",
			cfg:     Config{FortiVPNs: []FortiVPNConfig{vpn("office"), vpn("office")}},
			wantErr: `duplicate name "office"`,
		},
		{
			name:    "missing name",
			cfg:     Config{FortiVPNs: []FortiVPNConfig{vpn("")}},
			wantErr: "name is required",
		},
		{
			name: "unknown vpn on route",
			cfg: Config{
				FortiVPNs: []FortiVPNConfig{vpn("office")},
				Routes:    []RouteConfig{{LocalPort: 1, Target: "10.0.0.1:1", Protocol: "tcp", VPN: "lab"}},
			},
			wantErr: `routes[0].vpn: unknown vpn "lab"`,
		},
		{
			name: "unknown vpn on reverse route",
			cfg: Config{
				ReverseRoutes: []ReverseRouteConfig{{RemotePort: 1, Target: "10.0.0.1:1", Protocol: "tcp", VPN: "lab"}},
			},
			wantErr: `reverse_routes[0].vpn: unknown vpn "lab"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got error %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadExpandsEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := `
# A commented ${XT_TEST_UNSET} reference is ignored.
fortivpns:
  - name: office
    host: vpn.example.com
    username: u
    password: "${XT_TEST_VPN_PASSWORD}"
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "XT_TEST_VPN_PASSWORD") {
		t.Fatalf("unset variable: got %v", err)
	}

	t.Setenv("XT_TEST_VPN_PASSWORD", "p@ss$word")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.VPNs[0].Password; got != "p@ss$word" {
		t.Fatalf("password = %q", got)
	}
}

func wg(name string) WireGuardConfig {
	key := "YEocP0e2o1WT5GlvBvQzVF7h8L1WcVPajxb0mfn4b0s="
	return WireGuardConfig{Name: name, PrivateKey: key, Addresses: []string{"10.8.0.2/32"},
		Peers: []WireGuardPeer{{PublicKey: key, Endpoint: "vpn.example.com:51820", AllowedIPs: []string{"10.8.0.0/24"}}}}
}

func TestValidateWireGuard(t *testing.T) {
	ok := Config{
		WireGuards: []WireGuardConfig{wg("home")},
		FortiVPNs:  []FortiVPNConfig{vpn("office")},
		Routes:     []RouteConfig{{LocalPort: 1, Target: "10.8.0.5:22", Protocol: "tcp", VPN: "home"}},
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if ok.VPNs[1].Type != VPNTypeWireGuard || ok.VPNs[1].MTU != 1420 {
		t.Fatalf("wireguard entry = %+v", ok.VPNs[1])
	}

	bad := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"bad private key", func(c *Config) { c.WireGuards[0].PrivateKey = "x" }, "private_key"},
		{"no address", func(c *Config) { c.WireGuards[0].Addresses = nil }, "addresses is required"},
		{"no peer", func(c *Config) { c.WireGuards[0].Peers = nil }, "at least one peer"},
		{"bad endpoint", func(c *Config) { c.WireGuards[0].Peers[0].Endpoint = "nohost" }, "endpoint"},
		{"bad allowed ip", func(c *Config) { c.WireGuards[0].Peers[0].AllowedIPs = []string{"10.8.0.0"} }, "allowed_ips"},
		{"name shared with fortivpn", func(c *Config) { c.WireGuards[0].Name = "office" }, `duplicate name "office"`},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{WireGuards: []WireGuardConfig{wg("home")}, FortiVPNs: []FortiVPNConfig{vpn("office")}}
			tt.mutate(&c)
			if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestOldFortivpnRouteKey(t *testing.T) {
	cfg, err := ParseRaw([]byte(`routes:
  - {local_port: 1, target: "10.0.0.1:1", protocol: tcp, fortivpn: dev}
reverse_routes:
  - {remote_port: 2, target: "10.0.0.1:2", protocol: tcp, fortivpn: dev}
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Routes[0].VPN != "dev" || cfg.ReverseRoutes[0].VPN != "dev" || cfg.Routes[0].FortiVPN != "" {
		t.Fatalf("routes = %+v / %+v", cfg.Routes, cfg.ReverseRoutes)
	}
	out, err := Marshal(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "fortivpn:") || !strings.Contains(string(out), "vpn: dev") {
		t.Fatalf("saved:\n%s", out)
	}
}

func TestVPNsWithType(t *testing.T) {
	cfg, err := Parse([]byte(`vpns:
  - name: office
    type: fortivpn
    host: vpn.example.com
    username: u
    password: p
  - name: home
    type: wireguard
    private_key: YEocP0e2o1WT5GlvBvQzVF7h8L1WcVPajxb0mfn4b0s=
    addresses: [10.8.0.2/32]
    peers:
      - public_key: YEocP0e2o1WT5GlvBvQzVF7h8L1WcVPajxb0mfn4b0s=
        endpoint: vpn.example.com:51820
        allowed_ips: [10.8.0.0/24]
routes:
  - {local_port: 1, target: "10.8.0.5:22", protocol: tcp, vpn: home}
  - {local_port: 2, target: "10.0.0.5:22", protocol: tcp, vpn: office}
`), "config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if f := cfg.VPNs[0].FortiVPN(); f.Port != 443 || f.UserAgent == "" {
		t.Fatalf("fortivpn defaults not applied: %+v", f)
	}
	if w := cfg.VPNs[1].WireGuard(); w.MTU != 1420 || w.Name != "home" {
		t.Fatalf("wireguard = %+v", w)
	}

	_, err = Parse([]byte("vpns:\n  - {name: x, type: openvpn}\n"), "config.yaml")
	if err == nil || !strings.Contains(err.Error(), "type must be fortivpn or wireguard") {
		t.Fatalf("unknown type: %v", err)
	}
}

func TestOldVPNListsBecomeTyped(t *testing.T) {
	old := `fortivpns:
  - {name: office, host: vpn.example.com, username: u, password: p}
wireguards:
  - name: home
    private_key: YEocP0e2o1WT5GlvBvQzVF7h8L1WcVPajxb0mfn4b0s=
    addresses: [10.8.0.2/32]
    peers: [{public_key: YEocP0e2o1WT5GlvBvQzVF7h8L1WcVPajxb0mfn4b0s=, endpoint: "h:1", allowed_ips: [10.8.0.0/24]}]
`
	raw, err := ParseRaw([]byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw.VPNs) != 2 || raw.VPNs[0].Type != VPNTypeFortiVPN || raw.VPNs[1].Type != VPNTypeWireGuard {
		t.Fatalf("vpns = %+v", raw.VPNs)
	}
	out, err := Marshal(raw, []byte(old))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if strings.Contains(text, "fortivpns:") || strings.Contains(text, "wireguards:") || !strings.Contains(text, "type: wireguard") {
		t.Fatalf("saved:\n%s", text)
	}
	if strings.Contains(text, "peers") && strings.Count(text, "host:") != 1 {
		t.Fatalf("fields of the other type leaked:\n%s", text)
	}
}
