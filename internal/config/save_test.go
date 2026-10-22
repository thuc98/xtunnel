package config

import (
	"strings"
	"testing"
)

const savedConfig = `# xtunnel client
tunnels:
  - name: "main"
    server_addr: "1.2.3.4:443"
    secret_key: "${XT_SECRET}" # from the environment
routes:
  - local_port: 5433
    target: "10.0.0.5:5432"
    protocol: "tcp"
    fortivpn: "dev"
fortivpns:
#  - name: "office"
#    host: "old.example.com"
  - name: "dev"
    host: "vpn.example.com"
    port: 44365
    username: "me"
    password: "hunter2"
    socks5:
      listen: ":1080"
`

func TestMarshalKeepsCommentsAndSecrets(t *testing.T) {
	raw, err := ParseRaw([]byte(savedConfig))
	if err != nil {
		t.Fatal(err)
	}

	edited := raw.MaskSecrets()
	if edited.VPNs[0].Password != SecretMask || edited.Tunnels[0].SecretKey != SecretMask {
		t.Fatalf("secrets not masked: %+v", edited)
	}
	if raw.VPNs[0].Password != "hunter2" {
		t.Fatal("MaskSecrets changed the original")
	}

	edited.Routes = append(edited.Routes, RouteConfig{LocalPort: 8080, Target: "10.0.0.6:80", Protocol: "tcp"})
	edited.Tunnels[0].ServerAddr = "5.6.7.8:443"
	edited.RestoreSecrets(raw)

	out, err := Marshal(edited, []byte(savedConfig))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{
		"# xtunnel client",
		"# from the environment",
		`#  - name: "office"`,
		"${XT_SECRET}",
		"hunter2",
		"5.6.7.8:443",
		"local_port: 8080",
		"listen: :1080",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("saved config missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, SecretMask) {
		t.Errorf("saved config contains the mask:\n%s", text)
	}

	if strings.Contains(text, "server:") || strings.Contains(text, "reverse_routes") {
		t.Errorf("saved config has empty sections:\n%s", text)
	}

	t.Setenv("XT_SECRET", "s")
	if _, err := Parse(out, "config.yaml"); err != nil {
		t.Fatalf("saved config does not parse: %v\n%s", err, text)
	}
}

func TestRestoreSecretsNewValue(t *testing.T) {
	raw, _ := ParseRaw([]byte(savedConfig))
	edited := raw.MaskSecrets()
	edited.VPNs[0].Password = "new-password"
	edited.RestoreSecrets(raw)
	if edited.VPNs[0].Password != "new-password" {
		t.Fatalf("password = %q", edited.VPNs[0].Password)
	}
	if edited.Tunnels[0].SecretKey != "${XT_SECRET}" {
		t.Fatalf("secret key = %q", edited.Tunnels[0].SecretKey)
	}
}

func TestOldClientSectionBecomesTunnel(t *testing.T) {
	old := `client:
  server_addr: "1.2.3.4:443"
  secret_key: "k"
routes:
  - local_port: 8080
    target: "10.0.0.6:80"
    protocol: "tcp"
`
	cfg, err := Parse([]byte(old), "config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tunnels) != 1 || cfg.Tunnels[0].Name != "default" || cfg.Tunnels[0].ServerAddr != "1.2.3.4:443" {
		t.Fatalf("tunnels = %+v", cfg.Tunnels)
	}
	if cfg.Routes[0].Tunnel != "default" {
		t.Fatalf("route tunnel = %q", cfg.Routes[0].Tunnel)
	}

	raw, _ := ParseRaw([]byte(old))
	out, err := Marshal(raw, []byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "client:") || !strings.Contains(string(out), "name: default") {
		t.Fatalf("saved:\n%s", out)
	}
}
