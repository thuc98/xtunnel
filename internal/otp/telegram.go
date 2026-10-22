package otp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"xtunnel/internal/config"
)

const telegramPollTimeout = 25 * time.Second

type telegramBot struct {
	cfg    config.OTPTelegramConfig
	client *http.Client

	mu     sync.Mutex
	chatID int64
}

type telegramMessage struct {
	MessageID int   `json:"message_id"`
	Date      int64 `json:"date"`
	Chat      struct {
		ID int64 `json:"id"`
	} `json:"chat"`
	Text           string           `json:"text"`
	ReplyToMessage *telegramMessage `json:"reply_to_message"`
}

type telegramUpdate struct {
	UpdateID int              `json:"update_id"`
	Message  *telegramMessage `json:"message"`
}

func newTelegramBot(cfg config.OTPTelegramConfig) *telegramBot {
	t := &telegramBot{cfg: cfg, client: &http.Client{Timeout: telegramPollTimeout + 10*time.Second}, chatID: cfg.ChatID}
	if t.chatID == 0 && cfg.ChatIDFile != "" {
		if data, err := os.ReadFile(cfg.ChatIDFile); err == nil {
			if id, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
				t.chatID = id
			}
		}
	}
	return t
}

func (t *telegramBot) linkedChat() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.chatID
}

func (t *telegramBot) link(chatID int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.chatID != 0 {
		return false
	}
	t.chatID = chatID
	if t.cfg.ChatIDFile != "" {
		if err := os.WriteFile(t.cfg.ChatIDFile, []byte(strconv.FormatInt(chatID, 10)+"\n"), 0o600); err != nil {
			log.Printf("otp telegram: save chat id to %s: %v", t.cfg.ChatIDFile, err)
		}
	}
	return true
}

func (t *telegramBot) call(ctx context.Context, method string, params, result any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/bot%s/%s", t.cfg.APIURL, t.cfg.BotToken, method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram %s: build request failed", method)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {

		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("telegram %s: %w", method, err)
	}
	defer resp.Body.Close()

	var envelope struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("telegram %s: decode response: %w", method, err)
	}
	if !envelope.OK {
		return fmt.Errorf("telegram %s: %s", method, envelope.Description)
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, result)
}

func (t *telegramBot) sendMessage(ctx context.Context, chatID int64, text string, replyTo int) (int, error) {
	params := map[string]any{"chat_id": chatID, "text": text}
	if replyTo != 0 {
		params["reply_parameters"] = map[string]any{"message_id": replyTo}
	}
	var msg telegramMessage
	if err := t.call(ctx, "sendMessage", params, &msg); err != nil {
		return 0, err
	}
	return msg.MessageID, nil
}

func (t *telegramBot) username(ctx context.Context) string {
	var me struct {
		Username string `json:"username"`
	}
	if err := t.call(ctx, "getMe", map[string]any{}, &me); err != nil {
		log.Printf("otp %v", err)
		return "your bot"
	}
	return "@" + me.Username
}

func (t *telegramBot) getUpdates(ctx context.Context, offset int, timeout time.Duration) ([]telegramUpdate, error) {
	params := map[string]any{
		"offset":          offset,
		"timeout":         int(timeout / time.Second),
		"allowed_updates": []string{"message"},
	}
	var updates []telegramUpdate
	err := t.call(ctx, "getUpdates", params, &updates)
	return updates, err
}

func telegramRequestText(req *request) string {
	remaining := time.Until(req.expires).Round(time.Second)
	text := fmt.Sprintf("🔐 VPN %s needs a one-time code.\n%s\n\nReply to this message with the code within %s.",
		req.vpn, req.prompt, remaining)
	if req.link != "" {
		text += "\nOr enter it at: " + req.link
	}
	return text
}

func (b *Broker) sendTelegramRequest(ctx context.Context, req *request) {
	t := b.telegram
	chatID := t.linkedChat()
	if chatID == 0 {
		log.Printf("fortivpn %s: no telegram chat linked yet, send /start to the bot to receive the OTP request", req.vpn)
		return
	}
	b.mu.Lock()
	if req.tgSent {
		b.mu.Unlock()
		return
	}
	req.tgSent = true
	b.mu.Unlock()

	msgID, err := t.sendMessage(ctx, chatID, telegramRequestText(req), 0)
	if err != nil {
		log.Printf("fortivpn %s: send OTP request to telegram: %v", req.vpn, err)
		return
	}
	b.mu.Lock()
	req.tgMessageID = msgID
	b.mu.Unlock()
	log.Printf("fortivpn %s needs an OTP (%s), sent request to telegram", req.vpn, req.prompt)
}

func (b *Broker) pollTelegram(ctx context.Context) error {
	t := b.telegram
	if t.linkedChat() == 0 {
		log.Printf("otp telegram: no chat linked, send /start to %s to receive OTP requests", t.username(ctx))
	}

	offset := 0
	for {
		updates, err := t.getUpdates(ctx, offset, telegramPollTimeout)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			log.Printf("otp %v, retrying", err)
			timer := time.NewTimer(5 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			continue
		}
		for _, u := range updates {
			offset = u.UpdateID + 1
			if u.Message != nil {
				b.handleTelegramMessage(ctx, u.Message)
			}
		}
	}
}

func (b *Broker) handleTelegramMessage(ctx context.Context, msg *telegramMessage) {
	t := b.telegram
	reply := func(text string) {
		if _, err := t.sendMessage(ctx, msg.Chat.ID, text, msg.MessageID); err != nil {
			log.Printf("otp %v", err)
		}
	}

	if isStartCommand(msg.Text) {
		b.handleStart(ctx, msg, reply)
		return
	}
	if msg.Chat.ID != t.linkedChat() {
		return
	}

	req, ambiguous := b.matchTelegramRequest(msg)
	if req == nil {
		if ambiguous {
			reply("Several VPNs are waiting for a code: reply directly to the request message.")
		}
		return
	}
	if _, err := b.resolve(req.id, msg.Text); err != nil {
		reply("❌ " + err.Error())
		return
	}
	reply("✅ Code received for VPN " + req.vpn)
}

func (b *Broker) handleStart(ctx context.Context, msg *telegramMessage, reply func(string)) {
	t := b.telegram
	switch linked := t.linkedChat(); {
	case linked == msg.Chat.ID:
		reply("This chat already receives xtunnel OTP requests.")
		return
	case linked != 0:
		log.Printf("otp telegram: ignored /start from chat %d, already linked to chat %d", msg.Chat.ID, linked)
		reply("This bot is already linked to another chat.")
		return
	}
	if !t.link(msg.Chat.ID) {
		return
	}
	log.Printf("otp telegram: linked chat %d", msg.Chat.ID)
	reply(fmt.Sprintf("✅ Linked. xtunnel OTP requests will be sent to this chat (id %d).", msg.Chat.ID))

	b.mu.Lock()
	var waiting []*request
	for _, req := range b.pending {
		if !req.tgSent {
			waiting = append(waiting, req)
		}
	}
	b.mu.Unlock()
	for _, req := range waiting {
		b.sendTelegramRequest(ctx, req)
	}
}

func isStartCommand(text string) bool {
	cmd, _, _ := strings.Cut(strings.TrimSpace(text), " ")
	return cmd == "/start" || strings.HasPrefix(cmd, "/start@")
}

func (b *Broker) matchTelegramRequest(msg *telegramMessage) (req *request, ambiguous bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var candidates []*request
	for _, r := range b.pending {
		if r.tgMessageID == 0 || msg.Date < r.created.Unix() {
			continue
		}
		if msg.ReplyToMessage != nil && msg.ReplyToMessage.MessageID == r.tgMessageID {
			return r, false
		}
		candidates = append(candidates, r)
	}
	if len(candidates) == 1 {
		return candidates[0], false
	}
	return nil, len(candidates) > 1
}
