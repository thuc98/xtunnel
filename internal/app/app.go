package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"xtunnel/internal/config"
	"xtunnel/internal/connector"
	"xtunnel/internal/fortivpn"
	"xtunnel/internal/metrics"
	"xtunnel/internal/otp"
	"xtunnel/internal/receiver"
	"xtunnel/internal/socks5"
	"xtunnel/internal/tunnel"
)

type runner struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func start(parent context.Context, f func(ctx context.Context)) *runner {
	ctx, cancel := context.WithCancel(parent)
	r := &runner{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		f(ctx)
	}()
	return r
}

func (r *runner) stop() {
	if r != nil {
		r.cancel()
		<-r.done
	}
}

type vpnRun struct {
	cfg   config.FortiVPNConfig
	sup   *fortivpn.Supervisor
	run   *runner
	socks *runner
}

type socksRun struct {
	cfg config.Socks5Config
	run *runner
}

type tunnelRun struct {
	key      string
	receiver *receiver.QuicReceiver
	run      *runner

	errMu sync.Mutex
	err   string
}

func (t *tunnelRun) setErr(err error) {
	t.errMu.Lock()
	t.err = err.Error()
	t.errMu.Unlock()
}

func (t *tunnelRun) lastErr() string {
	if t == nil {
		return ""
	}
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.err
}

func (t *tunnelRun) stop() {
	if t != nil {
		t.run.stop()
	}
}

type App struct {
	path       string
	serverMode bool
	ctx        context.Context
	started    time.Time

	dashboard http.Handler

	saveMu sync.Mutex

	pendingMu sync.Mutex
	pending   *config.Config
	applyMu   sync.Mutex

	mu          sync.Mutex
	cfg         *config.Config
	brokerMu    sync.RWMutex
	broker      *otp.Broker
	brokerKey   string
	brokerRun   *runner
	vpnsMu      sync.RWMutex
	vpns        map[string]*vpnRun
	tunnelsMu   sync.RWMutex
	tunnels     map[string]*tunnelRun
	tunnelSocks map[string]*socksRun
	vpnRoutes   *tunnelRun
	server      *tunnelRun
	webListen   string
	webServer   *http.Server
	webStopped  chan struct{}
	errMu       sync.Mutex
	applyErrors []string
}

func New(path string, serverMode bool) *App {
	return &App{path: path, serverMode: serverMode, started: time.Now(), vpns: map[string]*vpnRun{}, tunnels: map[string]*tunnelRun{}, tunnelSocks: map[string]*socksRun{}}
}

func (a *App) SetDashboard(h http.Handler) {
	a.dashboard = h
}

func (a *App) Run(ctx context.Context, cfg *config.Config) error {
	a.ctx = ctx
	a.apply(cfg)
	<-ctx.Done()

	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopWeb()
	a.server.stop()
	a.vpnRoutes.stop()
	for _, p := range a.tunnelSocks {
		p.run.stop()
	}
	for _, t := range a.tunnels {
		t.stop()
	}
	for _, v := range a.vpns {
		v.socks.stop()
		v.run.stop()
	}
	a.brokerRun.stop()
	return nil
}

func key(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}

func (a *App) apply(cfg *config.Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg = cfg
	a.errMu.Lock()
	a.applyErrors = nil
	a.errMu.Unlock()

	linkBase := cfg.Web.PublicURL
	if cfg.Web.Listen == "" {
		linkBase = ""
	}
	if k := key([]any{cfg.OTP, linkBase}); k != a.brokerKey || a.broker == nil {
		a.brokerRun.stop()
		broker := otp.NewBroker(cfg.OTP, linkBase)
		a.brokerMu.Lock()
		a.broker = broker
		a.brokerMu.Unlock()
		a.brokerKey = k
		a.brokerRun = start(a.ctx, func(ctx context.Context) {
			if err := broker.Run(ctx); err != nil && ctx.Err() == nil {
				log.Printf("otp: %v", err)
			}
		})
	}

	wanted := map[string]config.FortiVPNConfig{}
	for _, v := range cfg.FortiVPNs {
		if !v.Disabled {
			wanted[v.Name] = v
		}
	}
	for name, v := range a.vpns {
		newCfg, ok := wanted[name]
		if !ok || !sameVPN(v.cfg, newCfg) {
			log.Printf("fortivpn %s: stopping (config changed)", name)
			v.socks.stop()
			v.run.stop()
			a.vpnsMu.Lock()
			delete(a.vpns, name)
			a.vpnsMu.Unlock()
		}
	}
	for _, vc := range cfg.FortiVPNs {
		if vc.Disabled {
			continue
		}
		v, ok := a.vpns[vc.Name]
		if !ok {
			sup := fortivpn.NewSupervisor(vc, a.requestOTP)
			v = &vpnRun{sup: sup}
			v.run = start(a.ctx, func(ctx context.Context) { _ = sup.Run(ctx) })
			a.vpnsMu.Lock()
			a.vpns[vc.Name] = v
			a.vpnsMu.Unlock()
		}
		if !ok || v.cfg.Socks5 != vc.Socks5 {
			v.socks.stop()
			v.socks = nil
			if vc.Socks5.Active() {
				v.socks = a.startSocks("fortivpn "+vc.Name, metrics.SocksKey("vpn", vc.Name), vc.Socks5, v.sup.DialContext)
			}
		}
		v.cfg = vc
	}

	if a.serverMode {
		if k := key(cfg.Server); a.server == nil || a.server.key != k {
			a.server.stop()
			a.server = a.startServer(cfg.Server, k)
		}
	} else {
		a.applyTunnels(cfg)
	}

	if cfg.Web.Listen != a.webListen {
		a.stopWeb()
		if cfg.Web.Listen != "" {
			a.startWeb(cfg.Web.Listen)
		}
	}
}

func sameVPN(a, b config.FortiVPNConfig) bool {
	a.Socks5, b.Socks5 = config.Socks5Config{}, config.Socks5Config{}
	return reflect.DeepEqual(a, b)
}

func (a *App) currentBroker() *otp.Broker {
	a.brokerMu.RLock()
	defer a.brokerMu.RUnlock()
	return a.broker
}

func (a *App) requestOTP(ctx context.Context, vpn, prompt string) (string, error) {
	broker := a.currentBroker()
	if broker == nil || !broker.Enabled() {
		return "", errors.New("gateway asks for a token code but neither web.listen nor otp.telegram is configured")
	}
	return broker.Request(ctx, vpn, prompt)
}

func (a *App) vpnDial(name string) tunnel.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		a.vpnsMu.RLock()
		v, ok := a.vpns[name]
		a.vpnsMu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("fortivpn %q is disabled", name)
		}
		return v.sup.DialContext(ctx, network, address)
	}
}

func (a *App) startSocks(name, statsKey string, sc config.Socks5Config, dial socks5.DialFunc) *runner {
	proxy := &socks5.Server{Name: name, Dial: dial, Username: sc.Username, Password: sc.Password, Stats: metrics.Get(statsKey)}
	return start(a.ctx, func(ctx context.Context) {
		if err := proxy.ListenAndServe(ctx, sc.Listen); err != nil {
			log.Printf("socks5 %s: %v", name, err)
			a.addError(fmt.Sprintf("socks5 %s: %v", name, err))
		}
	})
}

func (a *App) tunnelDial(name string) socks5.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		a.tunnelsMu.RLock()
		t, ok := a.tunnels[name]
		a.tunnelsMu.RUnlock()
		if !ok || t.receiver == nil {
			return nil, fmt.Errorf("tunnel %q is not running", name)
		}
		return t.receiver.DialTunnel(ctx, network, address)
	}
}

func (a *App) applyTunnels(cfg *config.Config) {
	routes := map[string][]config.RouteConfig{}
	reverse := map[string][]config.ReverseRouteConfig{}
	var vpnRoutes []config.RouteConfig
	for _, r := range cfg.Routes {
		r.Note = ""
		if r.FortiVPN != "" {
			vpnRoutes = append(vpnRoutes, r)
		} else {
			routes[r.Tunnel] = append(routes[r.Tunnel], r)
		}
	}
	for _, r := range cfg.ReverseRoutes {
		r.Note = ""
		reverse[r.Tunnel] = append(reverse[r.Tunnel], r)
	}

	wanted := map[string]bool{}
	for _, tc := range cfg.Tunnels {
		if tc.Disabled {
			continue
		}
		wanted[tc.Name] = true

		conn := tc
		conn.Socks5 = config.Socks5Config{}
		k := key([]any{conn, routes[tc.Name], reverse[tc.Name]})
		if t, ok := a.tunnels[tc.Name]; !ok || t.key != k {
			a.tunnels[tc.Name].stop()
			t = a.startTunnel(tc, routes[tc.Name], reverse[tc.Name], k)
			a.tunnelsMu.Lock()
			a.tunnels[tc.Name] = t
			a.tunnelsMu.Unlock()
		}
		if p, ok := a.tunnelSocks[tc.Name]; !ok || p.cfg != tc.Socks5 {
			if ok {
				p.run.stop()
				delete(a.tunnelSocks, tc.Name)
			}
			if tc.Socks5.Active() {
				a.tunnelSocks[tc.Name] = &socksRun{cfg: tc.Socks5, run: a.startSocks("tunnel "+tc.Name, metrics.SocksKey("tunnel", tc.Name), tc.Socks5, a.tunnelDial(tc.Name))}
			}
		}
	}
	for name, p := range a.tunnelSocks {
		if !wanted[name] {
			p.run.stop()
			delete(a.tunnelSocks, name)
		}
	}
	for name, t := range a.tunnels {
		if !wanted[name] {
			log.Printf("tunnel %s: stopping", name)
			t.stop()
			a.tunnelsMu.Lock()
			delete(a.tunnels, name)
			a.tunnelsMu.Unlock()
		}
	}

	if k := key(vpnRoutes); a.vpnRoutes == nil || a.vpnRoutes.key != k {
		a.vpnRoutes.stop()
		a.vpnRoutes = nil
		if len(vpnRoutes) > 0 {
			t := &tunnelRun{key: k}
			client := tunnel.NewClient("", vpnRoutes, nil, nil)
			client.SetVPNDialers(a.vpnDialers(cfg))
			t.run = start(a.ctx, func(ctx context.Context) {
				if err := client.ServeRoutes(ctx); err != nil && ctx.Err() == nil {
					log.Printf("vpn routes: %v", err)
					t.setErr(err)
				}
			})
			a.vpnRoutes = t
		}
	}
}

func (a *App) vpnDialers(cfg *config.Config) map[string]tunnel.DialFunc {
	dialers := map[string]tunnel.DialFunc{}
	for _, v := range cfg.FortiVPNs {
		dialers[v.Name] = a.vpnDial(v.Name)
	}
	return dialers
}

func (a *App) startTunnel(tc config.TunnelConfig, routes []config.RouteConfig, reverse []config.ReverseRouteConfig, k string) *tunnelRun {
	t := &tunnelRun{key: k}
	r, err := receiver.NewQuicReceiver(tc.ClientConfig, routes, reverse)
	if err != nil {
		t.setErr(err)
		t.run = start(a.ctx, func(context.Context) {})
		return t
	}
	r.SetVPNDialers(a.vpnDialers(a.cfg))
	r.SetName(tc.Name)
	t.receiver = r
	t.run = start(a.ctx, func(ctx context.Context) {
		if err := r.Start(ctx); err != nil && ctx.Err() == nil {
			log.Printf("tunnel %s: %v", tc.Name, err)
			t.setErr(err)
		}
	})
	return t
}

func (a *App) startServer(sc config.ServerConfig, k string) *tunnelRun {
	t := &tunnelRun{key: k}
	c, err := connector.NewQuicConnector(sc)
	if err != nil {
		t.setErr(err)
		t.run = start(a.ctx, func(context.Context) {})
		return t
	}
	t.run = start(a.ctx, func(ctx context.Context) {
		if err := c.Serve(ctx); err != nil && ctx.Err() == nil {
			log.Printf("server: %v", err)
			t.setErr(err)
		}
	})
	return t
}

func (a *App) startWeb(listen string) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Printf("web: %v", err)
		a.addError(fmt.Sprintf("web: %v", err))
		return
	}
	srv := &http.Server{Handler: http.HandlerFunc(a.serveHTTP), ReadHeaderTimeout: 10 * time.Second}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("web: %v", err)
		}
	}()
	log.Printf("web dashboard listening on %s", listen)
	a.webListen, a.webServer, a.webStopped = listen, srv, stopped
}

func (a *App) stopWeb() {
	if a.webServer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = a.webServer.Shutdown(ctx)
	<-a.webStopped
	a.webListen, a.webServer = "", nil
}

func (a *App) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/otp/") {
		a.currentBroker().Handler().ServeHTTP(w, r)
		return
	}
	if a.dashboard == nil {
		http.NotFound(w, r)
		return
	}
	a.dashboard.ServeHTTP(w, r)
}

func (a *App) addError(msg string) {
	a.errMu.Lock()
	a.applyErrors = append(a.applyErrors, msg)
	a.errMu.Unlock()
}

func (a *App) AdminPassword() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.Web.Password
}

func (a *App) ResolveOTP(id, code string) error {
	return a.currentBroker().Resolve(id, code)
}

type VPNStatus struct {
	fortivpn.Status
	Socks5 string `json:"socks5,omitempty"`
}

type TunnelStatus struct {
	Name   string `json:"name"`
	Server string `json:"server"`
	State  string `json:"state"`
	Socks5 string `json:"socks5,omitempty"`
	Error  string `json:"error,omitempty"`
}

type Status struct {
	Mode       string         `json:"mode"`
	Listen     string         `json:"listen,omitempty"`
	Tunnels    []TunnelStatus `json:"tunnels"`
	VPNs       []VPNStatus    `json:"vpns"`
	Pending    []otp.Pending  `json:"pending"`
	Errors     []string       `json:"errors"`
	ConfigPath string         `json:"config_path"`
	Writable   bool           `json:"writable"`
	Started    time.Time      `json:"started"`
}

func (a *App) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.errMu.Lock()
	errs := append([]string{}, a.applyErrors...)
	a.errMu.Unlock()
	st := Status{
		Mode:       "client",
		Pending:    a.currentBroker().Pending(),
		ConfigPath: a.path,
		Started:    a.started,
		Tunnels:    []TunnelStatus{},
		VPNs:       []VPNStatus{},
	}
	if a.serverMode {
		st.Mode, st.Listen = "server", a.cfg.Server.Listen
		if e := a.server.lastErr(); e != "" {
			errs = append(errs, e)
		}
	} else {
		for _, tc := range a.cfg.Tunnels {
			ts := TunnelStatus{Name: tc.Name, Server: tc.ServerAddr, State: "disabled"}
			if tc.Socks5.Active() && !tc.Disabled {
				ts.Socks5 = tc.Socks5.Listen
			}
			if t, ok := a.tunnels[tc.Name]; ok {
				ts.State, ts.Error = "connecting", t.lastErr()
				if t.receiver != nil && t.receiver.Connected() {
					ts.State = "up"
				}
			}
			st.Tunnels = append(st.Tunnels, ts)
		}
		if e := a.vpnRoutes.lastErr(); e != "" {
			errs = append(errs, "vpn routes: "+e)
		}
	}
	st.Errors = errs
	for _, vc := range a.cfg.FortiVPNs {
		if v, ok := a.vpns[vc.Name]; ok {
			vs := VPNStatus{Status: v.sup.Status()}
			if vc.Socks5.Active() {
				vs.Socks5 = vc.Socks5.Listen
			}
			st.VPNs = append(st.VPNs, vs)
		} else if vc.Disabled {
			st.VPNs = append(st.VPNs, VPNStatus{Status: fortivpn.Status{
				Name: vc.Name, Gateway: net.JoinHostPort(vc.Host, strconv.Itoa(vc.Port)), State: "disabled",
			}})
		}
	}
	if f, err := os.OpenFile(a.path, os.O_WRONLY, 0); err == nil {
		f.Close()
		st.Writable = true
	}
	return st
}

func (a *App) EditableConfig() (*config.Config, string, error) {
	data, err := os.ReadFile(a.path)
	if err != nil {
		return nil, "", err
	}
	raw, err := config.ParseRaw(data)
	if err != nil {
		return nil, string(data), err
	}
	return raw.MaskSecrets(), string(data), nil
}

func (a *App) SaveConfig(edited *config.Config) error {
	a.saveMu.Lock()
	defer a.saveMu.Unlock()
	original, err := os.ReadFile(a.path)
	if err != nil {
		return err
	}
	old, err := config.ParseRaw(original)
	if err != nil {
		return fmt.Errorf("current config: %w", err)
	}
	edited.RestoreSecrets(old)
	data, err := config.Marshal(edited, original)
	if err != nil {
		return err
	}
	return a.write(data)
}

func (a *App) SetVPNEnabled(name string, enabled bool) error {
	a.saveMu.Lock()
	defer a.saveMu.Unlock()
	original, err := os.ReadFile(a.path)
	if err != nil {
		return err
	}
	raw, err := config.ParseRaw(original)
	if err != nil {
		return fmt.Errorf("current config: %w", err)
	}
	found := false
	for i := range raw.FortiVPNs {
		if raw.FortiVPNs[i].Name == name {
			raw.FortiVPNs[i].Disabled = !enabled
			found = true
		}
	}
	if !found {
		return fmt.Errorf("no vpn named %q", name)
	}
	data, err := config.Marshal(raw, original)
	if err != nil {
		return err
	}
	return a.write(data)
}

func (a *App) SaveYAML(data []byte) error {
	a.saveMu.Lock()
	defer a.saveMu.Unlock()
	return a.write(data)
}

func (a *App) write(data []byte) error {
	cfg, err := config.WriteFile(a.path, data)
	if err != nil {
		return err
	}
	log.Printf("config saved from the dashboard, applying")

	a.pendingMu.Lock()
	a.pending = cfg
	a.pendingMu.Unlock()
	go func() {
		a.applyMu.Lock()
		defer a.applyMu.Unlock()
		a.pendingMu.Lock()
		next := a.pending
		a.pending = nil
		a.pendingMu.Unlock()
		if next != nil {
			a.apply(next)
		}
	}()
	return nil
}

type Flow struct {
	Kind    string `json:"kind"`
	Listen  string `json:"listen"`
	Through string `json:"through"`
	Target  string `json:"target"`
	Note    string `json:"note"`
	metrics.Snapshot
}

type Metrics struct {
	Time    time.Time                   `json:"time"`
	Total   metrics.Snapshot            `json:"total"`
	Flows   []Flow                      `json:"flows"`
	Tunnels map[string]metrics.Snapshot `json:"tunnels"`
	VPNs    map[string]metrics.Snapshot `json:"vpns"`
}

// Metrics reports cumulative counters since start; the dashboard turns them into rates.
func (a *App) Metrics() Metrics {
	a.mu.Lock()
	cfg := a.cfg
	a.mu.Unlock()

	m := Metrics{Time: time.Now(), Flows: []Flow{}, Tunnels: map[string]metrics.Snapshot{}, VPNs: map[string]metrics.Snapshot{}}
	add := func(f Flow, tunnel string) {
		m.Flows = append(m.Flows, f)
		m.Total = m.Total.Add(f.Snapshot)
		if tunnel != "" {
			m.Tunnels[tunnel] = m.Tunnels[tunnel].Add(f.Snapshot)
		}
	}
	for _, t := range cfg.Tunnels {
		m.Tunnels[t.Name] = metrics.Snapshot{}
	}
	for _, r := range cfg.Routes {
		f := Flow{Kind: "route", Listen: fmt.Sprintf(":%d/%s", r.LocalPort, r.Protocol), Target: r.Target, Note: r.Note,
			Snapshot: metrics.Lookup(metrics.RouteKey(r.Protocol, r.LocalPort))}
		tunnel := ""
		if r.FortiVPN != "" {
			f.Through = "vpn " + r.FortiVPN
		} else {
			f.Through, tunnel = "tunnel "+r.Tunnel, r.Tunnel
		}
		add(f, tunnel)
	}
	for _, r := range cfg.ReverseRoutes {
		f := Flow{Kind: "reverse", Listen: fmt.Sprintf("server:%d/%s", r.RemotePort, r.Protocol), Target: r.Target, Note: r.Note,
			Through: "tunnel " + r.Tunnel, Snapshot: metrics.Lookup(metrics.ReverseKey(r.Tunnel, r.Protocol, r.RemotePort))}
		if r.FortiVPN != "" {
			f.Through += " → vpn " + r.FortiVPN
		}
		add(f, r.Tunnel)
	}
	for _, t := range cfg.Tunnels {
		if t.Socks5.Listen != "" {
			add(Flow{Kind: "socks5", Listen: t.Socks5.Listen, Through: "tunnel " + t.Name, Target: "any",
				Snapshot: metrics.Lookup(metrics.SocksKey("tunnel", t.Name))}, t.Name)
		}
	}
	for _, v := range cfg.FortiVPNs {
		m.VPNs[v.Name] = metrics.Lookup(metrics.VPNKey(v.Name))
		if v.Socks5.Listen != "" {
			add(Flow{Kind: "socks5", Listen: v.Socks5.Listen, Through: "vpn " + v.Name, Target: "any",
				Snapshot: metrics.Lookup(metrics.SocksKey("vpn", v.Name))}, "")
		}
	}
	return m
}
