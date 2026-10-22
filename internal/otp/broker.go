package otp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"xtunnel/internal/config"
)

type request struct {
	id      string
	vpn     string
	prompt  string
	created time.Time
	expires time.Time
	code    chan string
	link    string

	tgSent      bool
	tgMessageID int
}

type Broker struct {
	cfg config.OTPConfig

	linkBase string
	telegram *telegramBot

	mu      sync.Mutex
	pending map[string]*request
}

func NewBroker(cfg config.OTPConfig, linkBase string) *Broker {
	b := &Broker{cfg: cfg, linkBase: linkBase, pending: make(map[string]*request)}
	if cfg.Telegram.Enabled {
		b.telegram = newTelegramBot(cfg.Telegram)
	}
	return b
}

func (b *Broker) Enabled() bool {
	return b.linkBase != "" || b.telegram != nil
}

func (b *Broker) Run(ctx context.Context) error {
	if b.telegram == nil {
		<-ctx.Done()
		return nil
	}
	return b.pollTelegram(ctx)
}

type Pending struct {
	ID      string    `json:"id"`
	VPN     string    `json:"vpn"`
	Prompt  string    `json:"prompt"`
	Expires time.Time `json:"expires"`
}

func (b *Broker) Pending() []Pending {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Pending, 0, len(b.pending))
	for _, r := range b.pending {
		out = append(out, Pending{ID: r.id, VPN: r.vpn, Prompt: r.prompt, Expires: r.expires})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Expires.Before(out[j].Expires) })
	return out
}

func (b *Broker) Resolve(id, code string) error {
	_, err := b.resolve(id, code)
	return err
}

func (b *Broker) Request(ctx context.Context, vpn, prompt string) (string, error) {
	timeout := time.Duration(b.cfg.TimeoutSec) * time.Second
	id, err := randomID()
	if err != nil {
		return "", err
	}
	now := time.Now()
	req := &request{
		id:      id,
		vpn:     vpn,
		prompt:  strings.TrimSpace(prompt),
		created: now,
		expires: now.Add(timeout),
		code:    make(chan string, 1),
	}

	if b.linkBase != "" {
		req.link = b.linkBase + "/otp/" + id
	}

	b.mu.Lock()
	b.pending[id] = req
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pending, id)
		b.mu.Unlock()
	}()

	if req.link != "" {
		log.Printf("fortivpn %s needs an OTP (%s), enter it within %s at %s", vpn, req.prompt, timeout, req.link)
	}
	if b.telegram != nil {
		b.sendTelegramRequest(ctx, req)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case code := <-req.code:
		log.Printf("fortivpn %s: OTP received", vpn)
		return code, nil
	case <-timer.C:
		return "", fmt.Errorf("no OTP entered within %s", timeout)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (b *Broker) resolve(id, code string) (*request, error) {
	code = strings.TrimSpace(code)
	if code == "" || strings.ContainsAny(code, "\r\n") || len(code) > 64 {
		return nil, errors.New("invalid code")
	}
	b.mu.Lock()
	req, ok := b.pending[id]
	if ok {
		delete(b.pending, id)
	}
	b.mu.Unlock()
	if !ok {
		return nil, errors.New("request expired or already answered")
	}
	req.code <- code
	return req, nil
}

func (b *Broker) lookup(id string) (*request, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	req, ok := b.pending[id]
	return req, ok
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
