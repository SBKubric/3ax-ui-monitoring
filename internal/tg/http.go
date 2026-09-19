package tg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// defaultAPIBase is the real Telegram Bot API host, used whenever NewHTTP is
// given an empty apiBase (production callers). Tests point apiBase at an
// httptest.Server instead, so no test ever reaches the real network (spec
// §4's "no real Telegram" testing policy, docs/agents/testing.md).
const defaultAPIBase = "https://api.telegram.org"

// defaultTimeout bounds one sendMessage call the same way the panel client
// bounds one panel request (spec §4: "таймаут 10 с") — a stuck Telegram
// request must not stall whatever caller is trying to notify.
const defaultTimeout = 10 * time.Second

// HTTP is the real Telegram Bot API client (spec §8: "тот же бот, что у
// панели" — plain net/http, no SDK per the architecture brief's "new deps:
// none" rule). It carries no token or chat id itself: those are per-call,
// because settingsNotifier (settings.go) rereads them from Settings on every
// Send.
type HTTP struct {
	hc      *http.Client
	apiBase string
}

// NewHTTP builds an HTTP client. hc nil gets a defaultTimeout client (a
// caller that already has a shared *http.Client, e.g. for connection
// pooling, may pass its own); apiBase empty gets the real Bot API host — the
// parameter only exists so tests can point at an httptest.Server.
func NewHTTP(hc *http.Client, apiBase string) *HTTP {
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	if apiBase == "" {
		apiBase = defaultAPIBase
	}
	return &HTTP{hc: hc, apiBase: apiBase}
}

// sendMessageRequest is the Bot API's sendMessage body — only the two fields
// mon-server ever needs (no parse_mode, no reply markup).
type sendMessageRequest struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

// sendMessageResponse is the Bot API's envelope: ok is false on every
// documented failure, with description explaining why (e.g. "Bad Request:
// chat not found"). Result is intentionally not modelled: mon-server never
// reads the sent message back.
type sendMessageResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
}

// SendTo posts one message to chatID via the bot identified by token,
// returning an error that carries Telegram's own description when the API
// rejects the call. The returned error never includes token: the bot token
// sits in the request URL, so any error that could echo the URL (a network
// or transport failure) has token scrubbed out of it first — a caller that
// logs this error (as internal/panel's notify does) must not leak the
// secret into logs.
func (h *HTTP) SendTo(ctx context.Context, token, chatID, text string) error {
	body, err := json.Marshal(sendMessageRequest{ChatID: chatID, Text: text})
	if err != nil {
		return fmt.Errorf("tg: encode sendMessage body: %w", err)
	}

	url := h.apiBase + "/bot" + token + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("tg: build request: %s", redactToken(err.Error(), token))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.hc.Do(req)
	if err != nil {
		return fmt.Errorf("tg: send message: %s", redactToken(err.Error(), token))
	}
	defer resp.Body.Close()

	var parsed sendMessageResponse
	_ = json.NewDecoder(resp.Body).Decode(&parsed) // best effort: status code alone still catches a non-JSON body below

	if resp.StatusCode != http.StatusOK || !parsed.OK {
		if parsed.Description != "" {
			return fmt.Errorf("tg: send message: %s", parsed.Description)
		}
		return fmt.Errorf("tg: send message: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// redactToken strips the bot token out of s (an error's text, which may
// embed the request URL courtesy of net/http or net/url), so a transport
// error can never leak it into a log line.
func redactToken(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "<redacted>")
}
