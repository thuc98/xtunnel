package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xtunnel/internal/app"
	"xtunnel/internal/config"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

type client struct {
	t      *testing.T
	base   string
	cookie *http.Cookie
}

func (c client) do(method, path, contentType string, body any, auth bool) (int, []byte) {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		r = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, c.base+path, r)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if auth && c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (c *client) login(password string) int {
	resp, err := noRedirect.PostForm(c.base+"/login", url.Values{"password": {password}})
	if err != nil {
		c.t.Fatal(err)
	}
	resp.Body.Close()
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			c.cookie = ck
		}
	}
	return resp.StatusCode
}

func TestDashboardEditsConfig(t *testing.T) {
	webPort, routePort, newRoutePort := freePort(t), freePort(t), freePort(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := fmt.Sprintf(`# my tunnel
client:
  server_addr: "127.0.0.1:1"
  secret_key: "s3cret"
routes:
  - local_port: %d
    target: "127.0.0.1:1"
    protocol: "tcp"
fortivpns:
  - name: "lab"
    host: "127.0.0.1"
    port: 1
    username: "u"
    password: "vpn-pw"
    reconnect_interval_sec: 60
web:
  listen: "127.0.0.1:%d"
  password: "pw"
`, routePort, webPort)
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	a := app.New(path, false)
	a.SetDashboard(New(a))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = a.Run(ctx, cfg)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	c := client{t: t, base: fmt.Sprintf("http://127.0.0.1:%d", webPort)}
	waitFor(t, "web server", func() bool {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", webPort))
		if err == nil {
			conn.Close()
		}
		return err == nil
	})

	if code, _ := c.do("GET", "/", "", nil, false); code != http.StatusSeeOther {
		t.Fatalf("no login: status %d, want redirect", code)
	}
	if code, _ := c.do("GET", "/api/status", "", nil, false); code != http.StatusUnauthorized {
		t.Fatalf("api without login: status %d", code)
	}
	if code := c.login("wrong"); code != http.StatusUnauthorized || c.cookie != nil {
		t.Fatalf("wrong password: status %d", code)
	}
	if code := c.login("pw"); code != http.StatusSeeOther || c.cookie == nil {
		t.Fatalf("login: status %d", code)
	}
	if code, body := c.do("GET", "/", "", nil, true); code != http.StatusOK || !strings.Contains(string(body), "<title>xtunnel</title>") {
		t.Fatalf("index: status %d", code)
	}

	code, body := c.do("GET", "/api/config", "", nil, true)
	if code != http.StatusOK {
		t.Fatalf("config: status %d", code)
	}
	var got struct {
		Config config.Config `json:"config"`
		YAML   string        `json:"yaml"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Config.Tunnels[0].SecretKey != config.SecretMask || got.Config.Web.Password != config.SecretMask {
		t.Fatalf("secrets not masked: %+v", got.Config)
	}

	edited := got.Config
	edited.Routes = append(edited.Routes, config.RouteConfig{LocalPort: newRoutePort, Target: "127.0.0.1:1", Protocol: "tcp"})

	if code, _ := c.do("PUT", "/api/config", "text/plain", edited, true); code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-JSON write: status %d", code)
	}
	bad := edited
	bad.Routes = append([]config.RouteConfig{}, edited.Routes...)
	bad.Routes = append(bad.Routes, config.RouteConfig{LocalPort: 70000, Target: "x:1", Protocol: "tcp"})
	if code, body := c.do("PUT", "/api/config", "application/json", bad, true); code != http.StatusBadRequest || !strings.Contains(string(body), "local_port") {
		t.Fatalf("invalid config: status %d %s", code, body)
	}

	if code, body := c.do("PUT", "/api/config", "application/json", edited, true); code != http.StatusOK {
		t.Fatalf("save: status %d %s", code, body)
	}

	saved, _ := os.ReadFile(path)
	for _, want := range []string{"# my tunnel", "s3cret", fmt.Sprintf("local_port: %d", newRoutePort)} {
		if !strings.Contains(string(saved), want) {
			t.Errorf("saved file missing %q:\n%s", want, saved)
		}
	}

	waitFor(t, "new route", func() bool {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", newRoutePort))
		if err == nil {
			conn.Close()
		}
		return err == nil
	})

	code, body = c.do("GET", "/api/status", "", nil, true)
	var st app.Status
	if err := json.Unmarshal(body, &st); err != nil || code != http.StatusOK {
		t.Fatalf("status: %d %v", code, err)
	}
	if st.Mode != "client" || !st.Writable {
		t.Fatalf("status = %+v", st)
	}

	if code, body := c.do("POST", "/api/vpns/lab/enabled", "application/json", map[string]bool{"enabled": false}, true); code != http.StatusOK {
		t.Fatalf("disable vpn: %d %s", code, body)
	}
	waitFor(t, "vpn disabled", func() bool {
		_, body := c.do("GET", "/api/status", "", nil, true)
		var st app.Status
		_ = json.Unmarshal(body, &st)
		return len(st.VPNs) == 1 && st.VPNs[0].State == "disabled"
	})
	saved, _ = os.ReadFile(path)
	if !strings.Contains(string(saved), "disabled: true") || !strings.Contains(string(saved), "vpn-pw") {
		t.Fatalf("saved file after disabling:\n%s", saved)
	}

	c.do("POST", "/api/logout", "application/json", map[string]string{}, true)
	if code, _ := c.do("GET", "/api/status", "", nil, true); code != http.StatusUnauthorized {
		t.Fatalf("after logout: status %d", code)
	}
}
