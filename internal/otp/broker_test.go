package otp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"xtunnel/internal/config"
)

func waitPending(t *testing.T, b *Broker, ready func(*request) bool) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		for id, req := range b.pending {
			if ready == nil || ready(req) {
				b.mu.Unlock()
				return id
			}
		}
		b.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no pending request")
	return ""
}

type result struct {
	code string
	err  error
}

func TestWebOTP(t *testing.T) {
	var b *Broker
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b.Handler().ServeHTTP(w, r) }))
	defer srv.Close()
	b = NewBroker(config.OTPConfig{TimeoutSec: 5}, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan result, 1)
	go func() {
		code, err := b.Request(ctx, "office", "Please enter code:")
		done <- result{code, err}
	}()
	id := waitPending(t, b, nil)
	link := srv.URL + "/otp/" + id

	resp, err := http.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Please enter code:") {
		t.Fatalf("form: status %d body %s", resp.StatusCode, body)
	}

	resp, err = http.PostForm(link, url.Values{"code": {" 987654 "}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("submit status %d", resp.StatusCode)
	}

	r := <-done
	if r.err != nil || r.code != "987654" {
		t.Fatalf("got %q, %v", r.code, r.err)
	}

	resp, err = http.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("answered link status %d, want 404", resp.StatusCode)
	}
}

func TestOTPTimeout(t *testing.T) {
	b := NewBroker(config.OTPConfig{TimeoutSec: 1}, "http://x")
	_, err := b.Request(context.Background(), "office", "code:")
	if err == nil || !strings.Contains(err.Error(), "no OTP entered") {
		t.Fatalf("got %v", err)
	}
}

type fakeTelegram struct {
	mu      sync.Mutex
	nextID  int
	sent    []map[string]any
	updates []telegramUpdate
}

func (f *fakeTelegram) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var params map[string]any
	_ = json.NewDecoder(r.Body).Decode(&params)
	f.mu.Lock()
	defer f.mu.Unlock()

	var result any
	switch {
	case strings.HasSuffix(r.URL.Path, "/sendMessage"):
		f.nextID++
		f.sent = append(f.sent, params)
		result = telegramMessage{MessageID: f.nextID}
	case strings.HasSuffix(r.URL.Path, "/getUpdates"):
		offset := int(params["offset"].(float64))
		var out []telegramUpdate
		for _, u := range f.updates {
			if u.UpdateID >= offset {
				out = append(out, u)
			}
		}
		result = out
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
}

func (f *fakeTelegram) reply(chatID int64, text string, replyTo int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	msg := &telegramMessage{Text: text, Date: time.Now().Unix()}
	msg.Chat.ID = chatID
	if replyTo != 0 {
		msg.ReplyToMessage = &telegramMessage{MessageID: replyTo}
	}
	f.updates = append(f.updates, telegramUpdate{UpdateID: len(f.updates) + 1, Message: msg})
}

func (f *fakeTelegram) sentTexts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, m := range f.sent {
		out = append(out, fmt.Sprint(m["text"]))
	}
	return out
}

func TestTelegramOTP(t *testing.T) {
	fake := &fakeTelegram{}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	b := NewBroker(config.OTPConfig{TimeoutSec: 10, Telegram: config.OTPTelegramConfig{
		Enabled: true, BotToken: "token", ChatID: 42, APIURL: srv.URL,
	}}, "")
	b.telegram.client.Timeout = 2 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = b.Run(ctx) }()

	office := make(chan result, 1)
	lab := make(chan result, 1)
	go func() {
		code, err := b.Request(ctx, "office", "Code for office:")
		office <- result{code, err}
	}()
	go func() {
		code, err := b.Request(ctx, "lab", "Code for lab:")
		lab <- result{code, err}
	}()
	officeID := waitPending(t, b, func(r *request) bool { return r.vpn == "office" && r.tgMessageID != 0 })
	labID := waitPending(t, b, func(r *request) bool { return r.vpn == "lab" && r.tgMessageID != 0 })
	officeReq, _ := b.lookup(officeID)
	labReq, _ := b.lookup(labID)

	fake.reply(7, "000000", officeReq.tgMessageID)
	fake.reply(42, "222222", labReq.tgMessageID)
	fake.reply(42, "111111", officeReq.tgMessageID)

	for name, ch := range map[string]chan result{"office": office, "lab": lab} {
		select {
		case r := <-ch:
			want := map[string]string{"office": "111111", "lab": "222222"}[name]
			if r.err != nil || r.code != want {
				t.Fatalf("%s: got %q, %v; want %s", name, r.code, r.err, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no code", name)
		}
	}

	wants := []string{"VPN office needs a one-time code", "Code received for VPN lab", "Code received for VPN office"}
	var texts string
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		texts = strings.Join(fake.sentTexts(), "\n---\n")
		missing := false
		for _, want := range wants {
			missing = missing || !strings.Contains(texts, want)
		}
		if !missing {
			return
		}
	}
	t.Fatalf("telegram messages missing confirmations:\n%s", texts)
}

func (f *fakeTelegram) sentTo(chatID int64) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, m := range f.sent {
		if int64(m["chat_id"].(float64)) == chatID {
			out = append(out, fmt.Sprint(m["text"]))
		}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestTelegramLinksChatOnStart(t *testing.T) {
	fake := &fakeTelegram{}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	chatFile := filepath.Join(t.TempDir(), "telegram_chat_id")
	b := NewBroker(config.OTPConfig{TimeoutSec: 10, Telegram: config.OTPTelegramConfig{
		Enabled: true, BotToken: "token", ChatIDFile: chatFile, APIURL: srv.URL,
	}}, "")
	b.telegram.client.Timeout = 2 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = b.Run(ctx) }()

	done := make(chan result, 1)
	go func() {
		code, err := b.Request(ctx, "office", "Code:")
		done <- result{code, err}
	}()
	waitPending(t, b, nil)
	fake.reply(99, "/start", 0)

	id := waitPending(t, b, func(r *request) bool { return r.tgMessageID != 0 })
	req, _ := b.lookup(id)
	waitFor(t, "request sent to linked chat", func() bool {
		return strings.Contains(strings.Join(fake.sentTo(99), "\n"), "VPN office needs a one-time code")
	})

	fake.reply(5, "/start", 0)
	fake.reply(5, "000000", req.tgMessageID)
	fake.reply(99, "123456", req.tgMessageID)

	select {
	case r := <-done:
		if r.err != nil || r.code != "123456" {
			t.Fatalf("got %q, %v", r.code, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no code")
	}
	waitFor(t, "other chat refused", func() bool {
		return strings.Contains(strings.Join(fake.sentTo(5), "\n"), "already linked to another chat")
	})

	data, err := os.ReadFile(chatFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "99" {
		t.Fatalf("chat id file = %q", data)
	}

	if got := NewBroker(b.cfg, "").telegram.linkedChat(); got != 99 {
		t.Fatalf("reloaded chat id = %d, want 99", got)
	}
}
