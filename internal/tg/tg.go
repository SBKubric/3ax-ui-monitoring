// Package tg delivers the Telegram messages mon-server sends itself
// (spec mon-server.md §8).
//
// mon-server notifies the owner directly only in the few cases the catalog in
// internal/alert spells out: the panel becoming unreachable and coming back,
// the panel rejecting the monitoring token, a mon-client config error, and
// target or mon-client transitions raised while the panel is down. Everything
// else reaches Telegram through the panel.
//
// This package is the transport: a Bot API client built on net/http with no
// third-party Telegram library, plus Alert, which adapts it to alert.Func so a
// Telegram outage logs instead of breaking a panel poll cycle or a heartbeat.
// The bot token lives in the request path, so nothing here ever puts a URL in
// an error or a log line.
package tg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/alert"
)

// DefaultBaseURL is the public Bot API root. Tests point a Sender at an
// httptest server with WithBaseURL instead of reaching the network.
const DefaultBaseURL = "https://api.telegram.org"

// defaultTimeout caps one sendMessage round trip. It matches the panel client
// budget of §4: a notification never holds a poll cycle open longer than that.
const defaultTimeout = 10 * time.Second

// maxResponseBody is how much of a Bot API response is read. The API answers
// with a short JSON envelope; anything larger is a proxy or gateway page.
const maxResponseBody = 4 << 10

// testMessage is what the "Send test" button on the Settings tab delivers
// (§9.4). It is short and self-identifying so the owner can tell which server
// the message came from.
const testMessage = "mon-server: Telegram is configured correctly — this is a test message."

// ErrNotConfigured is returned by Send when the bot token or the chat id is
// missing, so a caller can tell "Telegram is switched off" from "Telegram
// failed". The wiring layer uses alert.Logged instead of Alert in that case.
var ErrNotConfigured = errors.New("tg: telegram is not configured")

// Sender posts plain-text messages to one chat through the Telegram Bot API.
// It is safe for concurrent use.
type Sender struct {
	token   string
	chatID  string
	baseURL string
	http    *http.Client
	log     *slog.Logger
}

// Option overrides a Sender default.
type Option func(*Sender)

// WithBaseURL points the Sender at another Bot API root, such as an httptest
// server in tests or a local Bot API server. An empty value keeps
// DefaultBaseURL; a trailing slash is ignored.
func WithBaseURL(baseURL string) Option {
	return func(s *Sender) {
		if trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/"); trimmed != "" {
			s.baseURL = trimmed
		}
	}
}

// New returns a Sender for the bot token and chat id held in settings (§9.4,
// keys tgToken and tgChatId). Both are trimmed, because they arrive from a
// pasted form field. httpClient may be nil, meaning a client with a sane
// timeout; log may be nil, meaning discard — Alert must not panic on the
// notification path. Without options the Sender talks to DefaultBaseURL.
func New(token, chatID string, httpClient *http.Client, log *slog.Logger, opts ...Option) *Sender {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Sender{
		token:   strings.TrimSpace(token),
		chatID:  strings.TrimSpace(chatID),
		baseURL: DefaultBaseURL,
		http:    httpClient,
		log:     log,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Configured reports whether a bot token and a chat id are both set.
func (s *Sender) Configured() bool { return s.token != "" && s.chatID != "" }

// sendMessageRequest is the Bot API sendMessage body. parse_mode is left out
// on purpose: messages carry target keys, reasons and config-error text, and
// none of it may be read as markup or break the message.
type sendMessageRequest struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

// apiResponse is the part of the Bot API envelope worth reporting. OK is a
// pointer so that a body without the field is not read as a failure.
type apiResponse struct {
	OK          *bool  `json:"ok"`
	Description string `json:"description"`
}

// Send posts one plain-text message to the configured chat. It returns an
// error describing a non-2xx response or a transport failure; the caller's
// context is honoured and the send is capped at defaultTimeout regardless.
func (s *Sender) Send(ctx context.Context, text string) error {
	if !s.Configured() {
		return ErrNotConfigured
	}
	body, err := json.Marshal(sendMessageRequest{ChatID: s.chatID, Text: text})
	if err != nil {
		return fmt.Errorf("tg: encode sendMessage: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint("sendMessage"), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("tg: build sendMessage request: %w", withoutURL(err))
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("tg: sendMessage to chat %s: %w", s.chatID, withoutURL(err))
	}
	defer resp.Body.Close()
	return s.checkResponse(resp)
}

// SendTest delivers the fixed message behind the "Send test" button of the
// Settings tab (§9.4), so the owner can prove the bot token and chat id work
// before saving them.
func (s *Sender) SendTest(ctx context.Context) error {
	return s.Send(ctx, testMessage)
}

// Alert adapts the Sender to alert.Func. It sends, and on failure logs and
// returns without propagating: §8 alerts are best effort, and a Telegram
// outage must never break a panel poll cycle or a heartbeat.
func (s *Sender) Alert() alert.Func {
	return func(ctx context.Context, text string) {
		if !s.Configured() {
			s.log.Warn("telegram alert dropped, telegram is not configured", "text", text)
			return
		}
		if err := s.Send(ctx, text); err != nil {
			s.log.Error("telegram alert failed", "chat_id", s.chatID, "text", text, "error", err)
			return
		}
		s.log.Debug("telegram alert sent", "chat_id", s.chatID)
	}
}

// endpoint builds the URL of one Bot API method. The token is part of the
// path, which is why the result never appears in an error or a log line.
func (s *Sender) endpoint(method string) string {
	return s.baseURL + "/bot" + url.PathEscape(s.token) + "/" + method
}

// checkResponse turns a Bot API answer into an error naming the HTTP status
// and, when the API explains itself, its description.
func (s *Sender) checkResponse(resp *http.Response) error {
	api := readAPIResponse(resp.Body)
	switch {
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return fmt.Errorf("tg: sendMessage to chat %s rejected with status %d%s",
			s.chatID, resp.StatusCode, describe(api.Description))
	case api.OK != nil && !*api.OK:
		return fmt.Errorf("tg: sendMessage to chat %s answered status %d with ok=false%s",
			s.chatID, resp.StatusCode, describe(api.Description))
	default:
		return nil
	}
}

// readAPIResponse decodes the Bot API envelope, falling back to the first line
// of whatever came back when it is not JSON, such as a gateway error page. A
// body that cannot be read at all simply leaves the envelope empty.
func readAPIResponse(r io.Reader) apiResponse {
	var out apiResponse
	body, err := io.ReadAll(io.LimitReader(r, maxResponseBody))
	if err != nil || len(body) == 0 {
		return out
	}
	if json.Unmarshal(body, &out) != nil {
		out.Description = string(body)
	}
	return out
}

// describe renders a Bot API description as an error suffix, trimmed to one
// short line.
func describe(description string) string {
	if line := alert.FirstLine(description); line != "" {
		return ": " + line
	}
	return ""
}

// withoutURL strips the request URL from a transport error. net/http reports
// those as *url.Error, whose message repeats the whole URL — and the URL
// carries the bot token, which must never reach a log. Unwrapping keeps
// errors.Is working for context.Canceled and context.DeadlineExceeded.
func withoutURL(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}
