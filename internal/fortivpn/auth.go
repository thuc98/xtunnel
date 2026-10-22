package fortivpn

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"xtunnel/internal/config"
)

type session struct {
	cfg       config.FortiVPNConfig
	otp       OTPFunc
	tlsConfig *tls.Config
	client    *http.Client

	cookie string
}

type tunnelConfig struct {
	addr netip.Addr
	dns  []netip.Addr
}

func newSession(cfg config.FortiVPNConfig, otp OTPFunc) *session {
	tlsConfig := gatewayTLSConfig(cfg)
	return &session{
		cfg:       cfg,
		otp:       otp,
		tlsConfig: tlsConfig,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,

				TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (s *session) addr() string {
	return net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
}

func gatewayTLSConfig(cfg config.FortiVPNConfig) *tls.Config {
	return &tls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("gateway sent no certificate")
			}
			leaf := cs.PeerCertificates[0]
			opts := x509.VerifyOptions{DNSName: cfg.Host, Intermediates: x509.NewCertPool()}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			if _, err := leaf.Verify(opts); err == nil {
				return nil
			}
			sum := sha256.Sum256(leaf.Raw)
			digest := hex.EncodeToString(sum[:])
			if cfg.InsecureSkipVerify || (cfg.TrustedCert != "" && digest == cfg.TrustedCert) {
				return nil
			}
			return fmt.Errorf("gateway certificate is not trusted, set trusted_cert: %q if it is the right gateway (subject %q)",
				digest, leaf.Subject.String())
		},
	}
}

func (s *session) request(ctx context.Context, method, path, body string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "https://"+s.addr()+path, strings.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s.cookie != "" {
		req.Header.Set("Cookie", s.cookie)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "SVPNCOOKIE" && c.Value != "" {
			s.cookie = "SVPNCOOKIE=" + c.Value
		}
	}
	return resp, data, nil
}

func (s *session) login(ctx context.Context) error {
	s.cookie = ""
	body := "username=" + url.QueryEscape(s.cfg.Username) +
		"&credential=" + url.QueryEscape(s.cfg.Password) +
		"&realm=" + url.QueryEscape(s.cfg.Realm) + "&ajax=1"
	resp, data, err := s.request(ctx, http.MethodPost, "/remote/logincheck", body)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		resp, data, err = s.formOTP(ctx, data)
		if err != nil {
			return err
		}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed: HTTP %d", resp.StatusCode)
	}
	if s.cookie != "" {
		return nil
	}

	values := responseValues(string(data))
	token, ok := values["tokeninfo"]
	if !ok {
		return errors.New("login rejected, check username, password and realm")
	}

	var tokenParams string
	if token == "ftm_push" {
		log.Printf("fortivpn %s: approve the FortiToken Mobile push notification", s.cfg.Name)
		tokenParams = "ftmpush=1"
	} else {
		tokenParams, err = s.askCode(ctx, "Enter the token code sent by FortiGate (email/SMS):", values["magic"])
		if err != nil {
			return err
		}
	}

	body = fmt.Sprintf("username=%s&realm=%s&reqid=%s&polid=%s&grp=%s&portal=%s&peer=%s&%s",
		url.QueryEscape(s.cfg.Username), url.QueryEscape(s.cfg.Realm),
		values["reqid"], values["polid"], values["grp"], values["portal"], values["peer"], tokenParams)
	resp, _, err = s.request(ctx, http.MethodPost, "/remote/logincheck", body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK || s.cookie == "" {
		return fmt.Errorf("token rejected (HTTP %d)", resp.StatusCode)
	}
	return nil
}

func (s *session) askCode(ctx context.Context, prompt, magic string) (string, error) {
	if s.otp == nil {
		return "", errors.New("gateway asks for a token code but no otp channel (web/telegram) is configured")
	}
	code, err := s.otp(ctx, s.cfg.Name, prompt)
	if err != nil {
		return "", err
	}
	return "code=" + url.QueryEscape(code) + "&code2=&magic=" + magic, nil
}

var (
	formActionRe = regexp.MustCompile(`(?i)<form[^>]*\saction="([^"]+)"`)
	inputRe      = regexp.MustCompile(`(?i)<input[^>]*>`)
	attrRe       = regexp.MustCompile(`(?i)\s(type|name|value)="([^"]*)"`)
	promptRe     = regexp.MustCompile(`Please[^<]*`)
)

func (s *session) formOTP(ctx context.Context, page []byte) (*http.Response, []byte, error) {
	html := string(page)
	action := formActionRe.FindStringSubmatch(html)
	if action == nil {
		return nil, nil, errors.New("login failed: HTTP 401")
	}
	if s.otp == nil {
		return nil, nil, errors.New("gateway asks for a one-time password but no otp channel (web/telegram) is configured")
	}
	prompt := promptRe.FindString(html)
	if prompt == "" {
		prompt = "Please enter one-time password:"
	}

	var fields []string
	for _, input := range inputRe.FindAllString(html, -1) {
		attrs := map[string]string{}
		for _, m := range attrRe.FindAllStringSubmatch(input, -1) {
			attrs[strings.ToLower(m[1])] = m[2]
		}
		switch attrs["type"] {
		case "hidden":
			fields = append(fields, url.QueryEscape(attrs["name"])+"="+url.QueryEscape(attrs["value"]))
		case "password":
			code, err := s.otp(ctx, s.cfg.Name, prompt)
			if err != nil {
				return nil, nil, err
			}
			fields = append(fields, url.QueryEscape(attrs["name"])+"="+url.QueryEscape(code))
			if s.cfg.Realm != "" {
				fields = append(fields, "realm="+url.QueryEscape(s.cfg.Realm))
			}
		}
	}
	return s.request(ctx, http.MethodPost, action[1], strings.Join(fields, "&"))
}

func responseValues(body string) map[string]string {
	values := map[string]string{}
	for _, pair := range strings.FieldsFunc(body, func(r rune) bool {
		return r == '&' || r == ',' || r == '\r' || r == '\n'
	}) {
		if k, v, ok := strings.Cut(pair, "="); ok {
			if _, seen := values[k]; !seen {
				values[k] = v
			}
		}
	}
	return values
}

func (s *session) allocate(ctx context.Context) (tunnelConfig, error) {
	for _, path := range []string{"/remote/index", "/remote/fortisslvpn"} {
		if _, _, err := s.request(ctx, http.MethodGet, path, ""); err != nil {
			return tunnelConfig{}, err
		}
	}
	resp, data, err := s.request(ctx, http.MethodGet, "/remote/fortisslvpn_xml", "")
	if err != nil {
		return tunnelConfig{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return tunnelConfig{}, fmt.Errorf("get tunnel config: HTTP %d", resp.StatusCode)
	}
	return parseTunnelConfig(string(data)), nil
}

var (
	assignedAddrRe = regexp.MustCompile(`<assigned-addr[^>]*\sipv4=['"]([0-9.]+)['"]`)
	dnsIPRe        = regexp.MustCompile(`<dns[^>]*\sip=['"]([0-9.]+)['"]`)
)

func parseTunnelConfig(xml string) tunnelConfig {
	var cfg tunnelConfig
	if m := assignedAddrRe.FindStringSubmatch(xml); m != nil {
		cfg.addr, _ = netip.ParseAddr(m[1])
	}
	for _, m := range dnsIPRe.FindAllStringSubmatch(xml, -1) {
		if addr, err := netip.ParseAddr(m[1]); err == nil {
			cfg.dns = append(cfg.dns, addr)
		}
	}
	return cfg
}

func (s *session) logout(ctx context.Context) {
	if s.cookie == "" {
		return
	}
	_, _, _ = s.request(ctx, http.MethodGet, "/remote/logout", "")
	s.cookie = ""
}

func (s *session) dialTunnel(ctx context.Context) (net.Conn, error) {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second}, Config: s.tlsConfig}
	conn, err := d.DialContext(ctx, "tcp", s.addr())
	if err != nil {
		return nil, err
	}
	req := "GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\nCookie: " + s.cookie + "\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
