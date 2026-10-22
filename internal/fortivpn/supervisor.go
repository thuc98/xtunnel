package fortivpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"xtunnel/internal/config"
)

const (
	maxReconnectWait = 5 * time.Minute
	negotiateTimeout = 30 * time.Second
	echoInterval     = 30 * time.Second
	echoMaxSilence   = 100 * time.Second
)

type OTPFunc func(ctx context.Context, vpn, prompt string) (string, error)

type Supervisor struct {
	cfg     config.FortiVPNConfig
	session *session
	up      chan struct{}
	upOnce  sync.Once

	wasUp bool

	mu     sync.RWMutex
	net    *netStack
	status Status
}

type Status struct {
	Name    string       `json:"name"`
	Gateway string       `json:"gateway"`
	State   string       `json:"state"`
	Address string       `json:"address,omitempty"`
	DNS     []netip.Addr `json:"dns,omitempty"`
	Error   string       `json:"error,omitempty"`
	Since   time.Time    `json:"since"`
}

func (s *Supervisor) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *Supervisor) setStatus(state string, err error, addr netip.Addr, dns []netip.Addr) {
	st := Status{Name: s.cfg.Name, Gateway: s.session.addr(), State: state, DNS: dns, Since: time.Now()}
	if addr.IsValid() {
		st.Address = addr.String()
	}
	if err != nil {
		st.Error = err.Error()
	}
	s.mu.Lock()
	s.status = st
	s.mu.Unlock()
}

func NewSupervisor(cfg config.FortiVPNConfig, otp OTPFunc) *Supervisor {
	if cfg.InsecureSkipVerify {
		log.Printf("fortivpn %s: insecure_skip_verify is set, the gateway certificate is not verified", cfg.Name)
	}
	s := &Supervisor{cfg: cfg, session: newSession(cfg, otp), up: make(chan struct{})}
	s.setStatus("connecting", nil, netip.Addr{}, nil)
	return s
}

func (s *Supervisor) Run(ctx context.Context) error {
	defer func() {
		logoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.session.logout(logoutCtx)
	}()

	base := time.Duration(s.cfg.ReconnectIntervalSec) * time.Second
	interval := base
	for {
		s.wasUp = false
		err := s.runOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if s.wasUp {
			interval = base
		}
		s.setStatus("down", err, netip.Addr{}, nil)
		log.Printf("fortivpn %s down, reconnecting in %s: %v", s.cfg.Name, interval, err)

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if !s.wasUp {
			interval = min(interval*2, maxReconnectWait)
		}
	}
}

func (s *Supervisor) WaitUp(ctx context.Context) error {
	select {
	case <-s.up:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Supervisor) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	s.mu.RLock()
	n := s.net
	s.mu.RUnlock()
	if n == nil {
		return nil, fmt.Errorf("fortivpn %s tunnel is down", s.cfg.Name)
	}
	return n.dial(ctx, network, address)
}

func (s *Supervisor) runOnce(ctx context.Context) error {
	s.setStatus("connecting", nil, netip.Addr{}, nil)
	log.Printf("fortivpn %s connecting to %s", s.cfg.Name, s.session.addr())

	reused := s.session.cookie != ""
	if !reused {
		if err := s.session.login(ctx); err != nil {
			return fmt.Errorf("login: %w", err)
		}
		log.Printf("fortivpn %s authenticated", s.cfg.Name)
	}
	link, conn, tcfg, err := s.openTunnel(ctx)
	if err != nil {
		s.session.cookie = ""
		if reused {
			return fmt.Errorf("resume session: %w", err)
		}
		return err
	}
	defer conn.Close()

	res, err := link.negotiate(negotiateTimeout)
	if err != nil {
		s.session.cookie = ""
		return err
	}
	var dns []netip.Addr
	for _, addr := range append(tcfg.dns, res.dns...) {
		if !slices.Contains(dns, addr) {
			dns = append(dns, addr)
		}
	}
	n, err := newNetStack(res.addr, res.mtu, dns)
	if err != nil {
		return err
	}
	defer n.close()

	s.mu.Lock()
	s.net = n
	s.mu.Unlock()
	s.setStatus("up", nil, res.addr, dns)
	defer func() {
		s.mu.Lock()
		s.net = nil
		s.mu.Unlock()
	}()
	log.Printf("fortivpn %s up: address %s, dns %v, mtu %d", s.cfg.Name, res.addr, dns, res.mtu)
	s.upOnce.Do(func() { close(s.up) })
	s.wasUp = true

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(runCtx, func() { _ = conn.Close() })
	defer stop()

	errCh := make(chan error, 3)
	go func() { errCh <- n.pumpOutbound(runCtx, link.writeIPv4) }()
	go func() { errCh <- link.run(n.inject) }()
	go func() { errCh <- keepAlive(runCtx, link) }()

	err = <-errCh
	if errors.Is(err, errTerminated) {
		s.session.cookie = ""
	}
	return err
}

func (s *Supervisor) openTunnel(ctx context.Context) (*pppLink, net.Conn, tunnelConfig, error) {
	tcfg, err := s.session.allocate(ctx)
	if err != nil {
		return nil, nil, tunnelConfig{}, err
	}
	conn, err := s.session.dialTunnel(ctx)
	if err != nil {
		return nil, nil, tunnelConfig{}, err
	}
	return newPPPLink(newFrameConn(conn)), conn, tcfg, nil
}

func keepAlive(ctx context.Context, link *pppLink) error {
	ticker := time.NewTicker(echoInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			dead, err := link.sendEcho(echoMaxSilence)
			if err != nil {
				return err
			}
			if dead {
				return errors.New("gateway stopped answering keepalives")
			}
		}
	}
}
