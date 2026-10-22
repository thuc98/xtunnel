package config

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const SecretMask = "••••••"

func secretFields(cfg, old *Config) [][2]*string {
	var none string
	pick := func(p *string) *string {
		if old == nil {
			return &none
		}
		return p
	}
	var o Config
	if old != nil {
		o = *old
	}
	fields := [][2]*string{
		{&cfg.Server.SecretKey, pick(&o.Server.SecretKey)},
		{&cfg.Web.Password, pick(&o.Web.Password)},
		{&cfg.OTP.Telegram.BotToken, pick(&o.OTP.Telegram.BotToken)},
	}
	for i := range cfg.Tunnels {
		t := &cfg.Tunnels[i]
		oldT := &TunnelConfig{}
		for j := range o.Tunnels {
			if o.Tunnels[j].Name == t.Name {
				oldT = &o.Tunnels[j]
			}
		}
		fields = append(fields,
			[2]*string{&t.SecretKey, &oldT.SecretKey},
			[2]*string{&t.Socks5.Password, &oldT.Socks5.Password})
	}
	for i := range cfg.VPNs {
		v := &cfg.VPNs[i]
		oldV := &VPNConfig{}
		for j := range o.VPNs {
			if o.VPNs[j].Name == v.Name {
				oldV = &o.VPNs[j]
			}
		}
		fields = append(fields,
			[2]*string{&v.Password, &oldV.Password},
			[2]*string{&v.PrivateKey, &oldV.PrivateKey},
			[2]*string{&v.Socks5.Password, &oldV.Socks5.Password})
		for k := range v.Peers {
			p := &v.Peers[k]
			oldP := &WireGuardPeer{}
			for _, op := range oldV.Peers {
				if op.PublicKey == p.PublicKey {
					op := op
					oldP = &op
				}
			}
			fields = append(fields, [2]*string{&p.PresharedKey, &oldP.PresharedKey})
		}
	}
	return fields
}

func (c *Config) MaskSecrets() *Config {
	masked := c.clone()
	for _, f := range secretFields(masked, nil) {
		if *f[0] != "" {
			*f[0] = SecretMask
		}
	}
	return masked
}

func (c *Config) RestoreSecrets(old *Config) {
	for _, f := range secretFields(c, old) {
		if *f[0] == SecretMask {
			*f[0] = *f[1]
		}
	}
}

func (c *Config) clone() *Config {
	data, _ := yaml.Marshal(c)
	var out Config
	_ = yaml.Unmarshal(data, &out)
	return &out
}

func Marshal(cfg *Config, original []byte) ([]byte, error) {
	var node yaml.Node
	if err := node.Encode(cfg); err != nil {
		return nil, err
	}
	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{&node}}
	var old yaml.Node
	if err := yaml.Unmarshal(original, &old); err == nil && old.Kind == yaml.DocumentNode {
		copyComments(&old, doc)
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var renamedKeys = map[string][]string{
	"tunnels": {"client"},
	"vpns":    {"fortivpns", "wireguards"},
}

func copyComments(old, cur *yaml.Node) {
	cur.HeadComment, cur.LineComment, cur.FootComment = old.HeadComment, old.LineComment, old.FootComment
	switch {
	case old.Kind == yaml.DocumentNode && cur.Kind == yaml.DocumentNode:
		if len(old.Content) > 0 && len(cur.Content) > 0 {
			copyComments(old.Content[0], cur.Content[0])
		}
	case old.Kind == yaml.MappingNode && cur.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(cur.Content); i += 2 {
			matched := false
			for j := 0; j+1 < len(old.Content); j += 2 {
				if old.Content[j].Value == cur.Content[i].Value {
					copyComments(old.Content[j], cur.Content[i])
					copyComments(old.Content[j+1], cur.Content[i+1])
					matched = true
					break
				}
			}

			if matched {
				continue
			}
			for _, alias := range renamedKeys[cur.Content[i].Value] {
				for j := 0; j+1 < len(old.Content); j += 2 {
					if old.Content[j].Value == alias {
						cur.Content[i].HeadComment = old.Content[j].HeadComment
						copyComments(old.Content[j+1], cur.Content[i+1])
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
		}
	case old.Kind == yaml.SequenceNode && cur.Kind == yaml.SequenceNode:
		for i, item := range cur.Content {
			if match := matchItem(old, item, i); match != nil {
				copyComments(match, item)
			}
		}
	}
}

func matchItem(old, item *yaml.Node, index int) *yaml.Node {
	if name := mappingValue(item, "name"); name != "" {
		for _, o := range old.Content {
			if mappingValue(o, "name") == name {
				return o
			}
		}
		return nil
	}
	if index < len(old.Content) {
		return old.Content[index]
	}
	return nil
}

func mappingValue(n *yaml.Node, key string) string {
	if n.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1].Value
		}
	}
	return ""
}

func WriteFile(path string, data []byte) (*Config, error) {
	cfg, err := Parse(data, path)
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return nil, err
	}
	return cfg, f.Close()
}
