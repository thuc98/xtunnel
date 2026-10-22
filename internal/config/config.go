package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server ServerConfig `yaml:"server,omitempty" json:"server"`

	Client ClientConfig `yaml:"client,omitempty" json:"-"`

	Tunnels []TunnelConfig `yaml:"tunnels,omitempty" json:"tunnels"`
	Routes  []RouteConfig  `yaml:"routes,omitempty" json:"routes"`

	ReverseRoutes []ReverseRouteConfig `yaml:"reverse_routes,omitempty" json:"reverse_routes"`

	FortiVPNs []FortiVPNConfig `yaml:"fortivpns,omitempty" json:"fortivpns"`

	Web WebConfig `yaml:"web,omitempty" json:"web"`

	OTP OTPConfig `yaml:"otp,omitempty" json:"otp"`
}

type ServerConfig struct {
	Listen               string `yaml:"listen,omitempty" json:"listen"`
	SecretKey            string `yaml:"secret_key,omitempty" json:"secret_key"`
	KeepAliveIntervalSec int    `yaml:"keep_alive_interval_sec,omitempty" json:"keep_alive_interval_sec"`
	MaxIdleTimeoutSec    int    `yaml:"max_idle_timeout_sec,omitempty" json:"max_idle_timeout_sec"`
}

type ClientConfig struct {
	ServerAddr           string `yaml:"server_addr,omitempty" json:"server_addr"`
	SecretKey            string `yaml:"secret_key,omitempty" json:"secret_key"`
	KeepAliveIntervalSec int    `yaml:"keep_alive_interval_sec,omitempty" json:"keep_alive_interval_sec"`
	MaxIdleTimeoutSec    int    `yaml:"max_idle_timeout_sec,omitempty" json:"max_idle_timeout_sec"`
	ReconnectIntervalSec int    `yaml:"reconnect_interval_sec,omitempty" json:"reconnect_interval_sec"`

	Socks5 Socks5Config `yaml:"socks5,omitempty" json:"socks5"`
}

type TunnelConfig struct {
	Name string `yaml:"name" json:"name"`

	Disabled     bool `yaml:"disabled,omitempty" json:"disabled"`
	ClientConfig `yaml:",inline"`
}

type RouteConfig struct {
	LocalPort int    `yaml:"local_port" json:"local_port"`
	Target    string `yaml:"target" json:"target"`
	Protocol  string `yaml:"protocol" json:"protocol"`

	Tunnel string `yaml:"tunnel,omitempty" json:"tunnel"`

	FortiVPN string `yaml:"fortivpn,omitempty" json:"fortivpn"`
	Note     string `yaml:"note,omitempty" json:"note"`
}

type ReverseRouteConfig struct {
	RemotePort int    `yaml:"remote_port" json:"remote_port"`
	Target     string `yaml:"target" json:"target"`
	Protocol   string `yaml:"protocol" json:"protocol"`

	Tunnel string `yaml:"tunnel,omitempty" json:"tunnel"`

	FortiVPN string `yaml:"fortivpn,omitempty" json:"fortivpn"`
	Note     string `yaml:"note,omitempty" json:"note"`
}

type FortiVPNConfig struct {
	Name string `yaml:"name" json:"name"`

	Disabled bool   `yaml:"disabled,omitempty" json:"disabled"`
	Host     string `yaml:"host" json:"host"`
	Port     int    `yaml:"port,omitempty" json:"port"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
	Realm    string `yaml:"realm,omitempty" json:"realm"`

	TrustedCert string `yaml:"trusted_cert,omitempty" json:"trusted_cert"`

	InsecureSkipVerify   bool   `yaml:"insecure_skip_verify,omitempty" json:"insecure_skip_verify"`
	UserAgent            string `yaml:"user_agent,omitempty" json:"user_agent"`
	ReconnectIntervalSec int    `yaml:"reconnect_interval_sec,omitempty" json:"reconnect_interval_sec"`

	Socks5 Socks5Config `yaml:"socks5,omitempty" json:"socks5"`
}

type Socks5Config struct {
	Listen string `yaml:"listen,omitempty" json:"listen"`

	Disabled bool   `yaml:"disabled,omitempty" json:"disabled"`
	Username string `yaml:"username,omitempty" json:"username"`
	Password string `yaml:"password,omitempty" json:"password"`
}

func (s Socks5Config) Active() bool {
	return s.Listen != "" && !s.Disabled
}

type WebConfig struct {
	Listen string `yaml:"listen,omitempty" json:"listen"`

	PublicURL string `yaml:"public_url,omitempty" json:"public_url"`

	Password string `yaml:"password,omitempty" json:"password"`
}

type OTPConfig struct {
	TimeoutSec int               `yaml:"timeout_sec,omitempty" json:"timeout_sec"`
	Telegram   OTPTelegramConfig `yaml:"telegram,omitempty" json:"telegram"`
}

type OTPTelegramConfig struct {
	Enabled  bool   `yaml:"enabled,omitempty" json:"enabled"`
	BotToken string `yaml:"bot_token,omitempty" json:"bot_token"`

	ChatID     int64  `yaml:"chat_id,omitempty" json:"chat_id"`
	ChatIDFile string `yaml:"chat_id_file,omitempty" json:"chat_id_file"`
	APIURL     string `yaml:"api_url,omitempty" json:"api_url"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, path)
}

func Parse(data []byte, path string) (*Config, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if err := expandEnv(&root); err != nil {
		return nil, err
	}
	var cfg Config
	if len(root.Content) > 0 {
		if err := root.Decode(&cfg); err != nil {
			return nil, err
		}
	}
	if err := cfg.migrateClient(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.OTP.Telegram.Enabled && cfg.OTP.Telegram.ChatIDFile == "" {
		cfg.OTP.Telegram.ChatIDFile = filepath.Join(filepath.Dir(path), "telegram_chat_id")
	}
	return &cfg, nil
}

func ParseRaw(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.migrateClient(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) migrateClient() error {
	if c.Client == (ClientConfig{}) {
		return nil
	}
	if len(c.Tunnels) > 0 {
		return fmt.Errorf("both client and tunnels are set: move the client settings into tunnels")
	}
	c.Tunnels = []TunnelConfig{{Name: "default", ClientConfig: c.Client}}
	c.Client = ClientConfig{}
	return nil
}

var envRefRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func expandEnv(root *yaml.Node) error {
	var missing []string
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode {
			n.Value = envRefRe.ReplaceAllStringFunc(n.Value, func(ref string) string {
				name := ref[2 : len(ref)-1]
				value, ok := os.LookupEnv(name)
				if !ok {
					missing = append(missing, name)
				}
				return value
			})
		}
		for _, child := range n.Content {
			walk(child)
		}
	}
	walk(root)
	if len(missing) > 0 {
		return fmt.Errorf("config references unset environment variables: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (c *Config) Validate() error {
	if c.Server.Listen == "" {
		c.Server.Listen = ":8443"
	}
	if c.Server.KeepAliveIntervalSec <= 0 {
		c.Server.KeepAliveIntervalSec = 10
	}
	if c.Server.MaxIdleTimeoutSec <= 0 {
		c.Server.MaxIdleTimeoutSec = 60
	}
	if err := c.Web.validate(); err != nil {
		return err
	}
	if err := c.OTP.validate(); err != nil {
		return err
	}
	socksListen := map[string]bool{}
	tunnels := map[string]bool{}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		if err := t.validate(); err != nil {
			return fmt.Errorf("tunnels[%d]: %w", i, err)
		}
		if tunnels[t.Name] {
			return fmt.Errorf("tunnels[%d]: duplicate name %q", i, t.Name)
		}
		tunnels[t.Name] = true
		if l := t.Socks5.Listen; t.Socks5.Active() {
			if socksListen[l] {
				return fmt.Errorf("tunnels[%d].socks5.listen: %s is already used by another proxy", i, l)
			}
			socksListen[l] = true
		}
	}

	resolveTunnel := func(name string) (string, error) {
		switch {
		case name != "" && !tunnels[name]:
			return "", fmt.Errorf("unknown tunnel %q", name)
		case name != "":
			return name, nil
		case len(c.Tunnels) == 1:
			return c.Tunnels[0].Name, nil
		case len(c.Tunnels) == 0:
			return "", fmt.Errorf("no tunnel is configured")
		default:
			return "", fmt.Errorf("tunnel is required when several tunnels are configured")
		}
	}
	vpns := make(map[string]bool, len(c.FortiVPNs))
	for i := range c.FortiVPNs {
		vpn := &c.FortiVPNs[i]
		if err := vpn.validate(); err != nil {
			return fmt.Errorf("fortivpns[%d]: %w", i, err)
		}
		if vpns[vpn.Name] {
			return fmt.Errorf("fortivpns[%d]: duplicate name %q", i, vpn.Name)
		}
		vpns[vpn.Name] = true
		if l := vpn.Socks5.Listen; vpn.Socks5.Active() {
			if socksListen[l] {
				return fmt.Errorf("fortivpns[%d].socks5.listen: %s is already used by another proxy", i, l)
			}
			socksListen[l] = true
		}
	}
	for i := range c.Routes {
		route := &c.Routes[i]
		route.Protocol = strings.ToLower(route.Protocol)
		if route.LocalPort <= 0 || route.LocalPort > 65535 {
			return fmt.Errorf("routes[%d].local_port must be 1..65535", i)
		}
		if route.Target == "" {
			return fmt.Errorf("routes[%d].target is required", i)
		}
		if route.Protocol != "tcp" && route.Protocol != "udp" {
			return fmt.Errorf("routes[%d].protocol must be tcp or udp", i)
		}
		if route.FortiVPN != "" {
			if !vpns[route.FortiVPN] {
				return fmt.Errorf("routes[%d].fortivpn: unknown vpn %q", i, route.FortiVPN)
			}
			if route.Tunnel != "" {
				return fmt.Errorf("routes[%d]: set either tunnel or fortivpn, not both", i)
			}
			continue
		}
		name, err := resolveTunnel(route.Tunnel)
		if err != nil {
			return fmt.Errorf("routes[%d].tunnel: %w", i, err)
		}
		route.Tunnel = name
	}
	seen := make(map[string]bool, len(c.ReverseRoutes))
	for i := range c.ReverseRoutes {
		route := &c.ReverseRoutes[i]
		route.Protocol = strings.ToLower(route.Protocol)
		if route.RemotePort <= 0 || route.RemotePort > 65535 {
			return fmt.Errorf("reverse_routes[%d].remote_port must be 1..65535", i)
		}
		if route.Target == "" {
			return fmt.Errorf("reverse_routes[%d].target is required", i)
		}
		if route.Protocol != "tcp" && route.Protocol != "udp" {
			return fmt.Errorf("reverse_routes[%d].protocol must be tcp or udp", i)
		}
		if route.FortiVPN != "" && !vpns[route.FortiVPN] {
			return fmt.Errorf("reverse_routes[%d].fortivpn: unknown vpn %q", i, route.FortiVPN)
		}
		name, err := resolveTunnel(route.Tunnel)
		if err != nil {
			return fmt.Errorf("reverse_routes[%d].tunnel: %w", i, err)
		}
		route.Tunnel = name
		key := fmt.Sprintf("%s:%s:%d", route.Tunnel, route.Protocol, route.RemotePort)
		if seen[key] {
			return fmt.Errorf("reverse_routes[%d]: duplicate %s remote_port %d on tunnel %s", i, route.Protocol, route.RemotePort, route.Tunnel)
		}
		seen[key] = true
	}
	return nil
}

func (t *TunnelConfig) validate() error {
	if t.Name == "" {
		return fmt.Errorf("name is required")
	}
	if t.ServerAddr == "" {
		return fmt.Errorf("server_addr is required")
	}
	if t.SecretKey == "" {
		return fmt.Errorf("secret_key is required")
	}
	if t.KeepAliveIntervalSec <= 0 {
		t.KeepAliveIntervalSec = 10
	}
	if t.MaxIdleTimeoutSec <= 0 {
		t.MaxIdleTimeoutSec = 60
	}
	if t.ReconnectIntervalSec <= 0 {
		t.ReconnectIntervalSec = 2
	}
	return t.Socks5.validate()
}

func (f *FortiVPNConfig) validate() error {
	if f.Name == "" {
		return fmt.Errorf("name is required")
	}
	if f.Host == "" {
		return fmt.Errorf("host is required")
	}
	if f.Port == 0 {
		f.Port = 443
	}
	if f.Port < 0 || f.Port > 65535 {
		return fmt.Errorf("port must be 1..65535")
	}
	if f.Username == "" || f.Password == "" {
		return fmt.Errorf("username and password are required")
	}
	f.TrustedCert = strings.ToLower(strings.ReplaceAll(f.TrustedCert, ":", ""))
	if f.UserAgent == "" {
		f.UserAgent = "Mozilla/5.0 SV1"
	}
	if f.ReconnectIntervalSec <= 0 {
		f.ReconnectIntervalSec = 5
	}
	return f.Socks5.validate()
}

func (s Socks5Config) validate() error {
	if (s.Username == "") != (s.Password == "") {
		return fmt.Errorf("socks5.username and socks5.password must be set together")
	}
	if len(s.Username) > 255 || len(s.Password) > 255 {
		return fmt.Errorf("socks5.username and socks5.password must be at most 255 bytes")
	}
	return nil
}

func (o *OTPConfig) validate() error {
	if o.TimeoutSec <= 0 {
		o.TimeoutSec = 600
	}
	if o.Telegram.Enabled {
		if o.Telegram.BotToken == "" {
			return fmt.Errorf("otp.telegram.bot_token is required")
		}
		if o.Telegram.APIURL == "" {
			o.Telegram.APIURL = "https://api.telegram.org"
		}
		o.Telegram.APIURL = strings.TrimRight(o.Telegram.APIURL, "/")
	}
	return nil
}

func (w *WebConfig) validate() error {
	if w.Listen == "" {
		return nil
	}
	if w.PublicURL == "" {
		host := w.Listen
		if strings.HasPrefix(host, ":") {
			host = "localhost" + host
		}
		w.PublicURL = "http://" + host
	}
	w.PublicURL = strings.TrimRight(w.PublicURL, "/")
	return nil
}
