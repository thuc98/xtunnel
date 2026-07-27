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
}

type ServerConfig struct {
	Listen    string `yaml:"listen"`
	SecretKey string `yaml:"secret_key"`
}

type ClientConfig struct {
	ServerAddr string `yaml:"server_addr"`
	SecretKey  string `yaml:"secret_key"`
}

type RouteConfig struct {
	LocalPort int    `yaml:"local_port"`
	Target    string `yaml:"target"`
	Protocol  string `yaml:"protocol"`
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
	if c.Client.ServerAddr == "" {
		c.Client.ServerAddr = "127.0.0.1:8443"
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
	return nil
}
