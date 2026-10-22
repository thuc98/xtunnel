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
		return RouteConfig{LocalPort: 1, Target: "10.0.0.1:1", Protocol: "tcp", Tunnel: tunnel, FortiVPN: vpn}
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
		{name: "tunnel and vpn conflict", cfg: Config{Tunnels: []TunnelConfig{tun("sg")}, FortiVPNs: []FortiVPNConfig{vpn("dev")}, Routes: []RouteConfig{route("sg", "dev")}}, wantErr: "either tunnel or fortivpn"},
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
				Routes:        []RouteConfig{{LocalPort: 1, Target: "10.0.0.1:1", Protocol: "tcp", FortiVPN: "office"}},
				ReverseRoutes: []ReverseRouteConfig{{RemotePort: 1, Target: "10.0.0.2:1", Protocol: "tcp", FortiVPN: "lab"}},
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
				Routes:    []RouteConfig{{LocalPort: 1, Target: "10.0.0.1:1", Protocol: "tcp", FortiVPN: "lab"}},
			},
			wantErr: `routes[0].fortivpn: unknown vpn "lab"`,
		},
		{
			name: "unknown vpn on reverse route",
			cfg: Config{
				ReverseRoutes: []ReverseRouteConfig{{RemotePort: 1, Target: "10.0.0.1:1", Protocol: "tcp", FortiVPN: "lab"}},
			},
			wantErr: `reverse_routes[0].fortivpn: unknown vpn "lab"`,
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
	if got := cfg.FortiVPNs[0].Password; got != "p@ss$word" {
		t.Fatalf("password = %q", got)
	}
}
