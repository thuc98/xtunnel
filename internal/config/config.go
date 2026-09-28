package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server ServerConfig  `yaml:"server"`
	Client ClientConfig  `yaml:"client"`
	Routes []RouteConfig `yaml:"routes"`
	// ReverseRoutes expose a port on the server that forwards to a target reachable from the client.
	ReverseRoutes []ReverseRouteConfig `yaml:"reverse_routes"`
}

type ServerConfig struct {
	Listen               string `yaml:"listen"`
	SecretKey            string `yaml:"secret_key"`
	KeepAliveIntervalSec int    `yaml:"keep_alive_interval_sec"`
	MaxIdleTimeoutSec    int    `yaml:"max_idle_timeout_sec"`
}

type ClientConfig struct {
	ServerAddr           string `yaml:"server_addr"`
	SecretKey            string `yaml:"secret_key"`
	KeepAliveIntervalSec int    `yaml:"keep_alive_interval_sec"`
	MaxIdleTimeoutSec    int    `yaml:"max_idle_timeout_sec"`
	ReconnectIntervalSec int    `yaml:"reconnect_interval_sec"`
}

type RouteConfig struct {
	LocalPort int    `yaml:"local_port"`
	Target    string `yaml:"target"`
	Protocol  string `yaml:"protocol"`
}

type ReverseRouteConfig struct {
	RemotePort int    `yaml:"remote_port"`
	Target     string `yaml:"target"`
	Protocol   string `yaml:"protocol"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
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
	if c.Client.ServerAddr == "" {
		c.Client.ServerAddr = "127.0.0.1:8443"
	}
	if c.Client.KeepAliveIntervalSec <= 0 {
		c.Client.KeepAliveIntervalSec = 10
	}
	if c.Client.MaxIdleTimeoutSec <= 0 {
		c.Client.MaxIdleTimeoutSec = 60
	}
	if c.Client.ReconnectIntervalSec <= 0 {
		c.Client.ReconnectIntervalSec = 2
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
		key := fmt.Sprintf("%s:%d", route.Protocol, route.RemotePort)
		if seen[key] {
			return fmt.Errorf("reverse_routes[%d]: duplicate %s remote_port %d", i, route.Protocol, route.RemotePort)
		}
		seen[key] = true
	}
	return nil
}
