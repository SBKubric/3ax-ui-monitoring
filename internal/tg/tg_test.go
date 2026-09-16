package tg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/alert"
)

const (
	testToken  = "123456789:AAExample-Bot_TokenValue"
	testChatID = "-1001234567890"
)

// capturedRequest is what the Bot API stub saw.
type capturedRequest struct {
	method      string
	path        string
	contentType string
	rawBody     string
	body        sendMessageRequest
}

// stubAPI stands in for api.telegram.org: it records every request and answers
// with the status and body the test asks for.
type stubAPI struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []capturedRequest
	status   int
	body     string
}

func newStubAPI(t *testing.T) *stubAPI {
	t.Helper()
	api := &stubAPI{status: http.StatusOK, body: `{"ok":true,"result":{"message_id":7}}`}
	api.server = httptest.NewServer(http.HandlerFunc(api.handle))
	t.Cleanup(api.server.Close)
	return api
}

func (a *stubAPI) handle(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	got := capturedRequest{
		method:      r.Method,
		path:        r.URL.Path,
		contentType: r.Header.Get("Content-Type"),
		rawBody:     string(raw),
	}
	_ = json.Unmarshal(raw, &got.body)

	a.mu.Lock()
	a.requests = append(a.requests, got)
	status, body := a.status, a.body
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// reply sets the answer the stub gives to the requests that follow.
func (a *stubAPI) reply(status int, body string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status, a.body = status, body
}

func (a *stubAPI) captured() []capturedRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]capturedRequest(nil), a.requests...)
}

func (a *stubAPI) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.requests)
}

// only returns the single request the stub must have seen.
func (a *stubAPI) only(t *testing.T) capturedRequest {
	t.Helper()
	got := a.captured()
	if len(got) != 1 {
		t.Fatalf("stub saw %d requests, want exactly 1", len(got))
	}
	return got[0]
}

// logBuffer collects log output for assertions; it is written from whichever
// goroutine logs, so it locks.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newTestSender wires a Sender to the stub with a logger the test can read.
func newTestSender(t *testing.T, api *stubAPI, token, chatID string) (*Sender, *logBuffer) {
	t.Helper()
	logs := &logBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return New(token, chatID, api.server.Client(), log, WithBaseURL(api.server.URL)), logs
}

// callAlert runs the alert.Func and fails the test if it panics or blows up
// the caller instead of swallowing the failure.
func callAlert(t *testing.T, s *Sender, ctx context.Context, text string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Alert panicked: %v", r)
		}
	}()
	s.Alert()(ctx, text)
}

func TestSendPostsPlainTextToBotAPI(t *testing.T) {
	api := newStubAPI(t)
	sender, _ := newTestSender(t, api, testToken, testChatID)

	const text = "mon-server: panel back, 3 events resent"
	if err := sender.Send(context.Background(), text); err != nil {
		t.Fatalf("Send: %v", err)
	}

	got := api.only(t)
	if got.method != http.MethodPost {
		t.Errorf("method = %q, want POST", got.method)
	}
	if want := "/bot" + testToken + "/sendMessage"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	if !strings.HasPrefix(got.contentType, "application/json") {
		t.Errorf("content type = %q, want application/json", got.contentType)
	}
	if got.body.ChatID != testChatID {
		t.Errorf("chat_id = %q, want %q", got.body.ChatID, testChatID)
	}
	if got.body.Text != text {
		t.Errorf("text = %q, want %q", got.body.Text, text)
	}
	// Plain text only: markup would let a target name or a config error break
	// the message.
	if strings.Contains(got.rawBody, "parse_mode") {
		t.Errorf("body carries parse_mode: %s", got.rawBody)
	}
}

func TestSendReportsTelegramFailuresAndAlertSwallowsThem(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "bad request", status: http.StatusBadRequest, body: `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`, want: "Bad Request: chat not found"},
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{"ok":false,"error_code":401,"description":"Unauthorized"}`, want: "Unauthorized"},
		{name: "too many requests", status: http.StatusTooManyRequests, body: `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 12"}`, want: "Too Many Requests: retry after 12"},
		{name: "server error", status: http.StatusInternalServerError, body: `{"ok":false,"error_code":500,"description":"Internal Server Error"}`, want: "Internal Server Error"},
		{name: "bad gateway without json", status: http.StatusBadGateway, body: "<html>bad gateway</html>", want: "<html>bad gateway</html>"},
		{name: "ok false on 200", status: http.StatusOK, body: `{"ok":false,"description":"Forbidden: bot was blocked by the user"}`, want: "Forbidden: bot was blocked by the user"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := newStubAPI(t)
			api.reply(tt.status, tt.body)
			sender, logs := newTestSender(t, api, testToken, testChatID)

			err := sender.Send(context.Background(), "mon-server: panel unreachable (http_timeout)")
			if err == nil {
				t.Fatal("Send returned no error for a failing Telegram answer")
			}
			if status := strconv.Itoa(tt.status); !strings.Contains(err.Error(), status) {
				t.Errorf("error %q does not name status %s", err, status)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not carry the description %q", err, tt.want)
			}
			if strings.Contains(err.Error(), testToken) {
				t.Errorf("error leaks the bot token: %q", err)
			}

			// A Telegram outage must not break the poll cycle: Alert sends,
			// fails, logs and returns.
			callAlert(t, sender, context.Background(), "mon-server: panel unreachable (http_timeout)")

			if api.count() != 2 {
				t.Errorf("stub saw %d requests, want 2 (Send and Alert)", api.count())
			}
			out := logs.String()
			if !strings.Contains(out, "telegram alert failed") {
				t.Errorf("Alert did not log the failure, log was: %s", out)
			}
			if !strings.Contains(out, testChatID) {
				t.Errorf("Alert log does not name the chat id, log was: %s", out)
			}
			if strings.Contains(out, testToken) {
				t.Errorf("Alert log leaks the bot token: %s", out)
			}
		})
	}
}

func TestUnconfiguredSenderNeverReachesTelegram(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		chatID string
	}{
		{name: "no token", token: "", chatID: testChatID},
		{name: "no chat id", token: testToken, chatID: ""},
		{name: "nothing configured", token: "", chatID: ""},
		{name: "blank token", token: "   ", chatID: testChatID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := newStubAPI(t)
			sender, logs := newTestSender(t, api, tt.token, tt.chatID)

			if sender.Configured() {
				t.Error("Configured() = true, want false")
			}
			if err := sender.Send(context.Background(), "mon-server: panel back, 0 events resent"); !errors.Is(err, ErrNotConfigured) {
				t.Errorf("Send error = %v, want ErrNotConfigured", err)
			}
			if err := sender.SendTest(context.Background()); !errors.Is(err, ErrNotConfigured) {
				t.Errorf("SendTest error = %v, want ErrNotConfigured", err)
			}
			callAlert(t, sender, context.Background(), "mon-server: panel unreachable (conn_refused)")

			if api.count() != 0 {
				t.Errorf("an unconfigured sender performed %d requests, want 0", api.count())
			}
			if out := logs.String(); !strings.Contains(out, "telegram is not configured") {
				t.Errorf("Alert did not log the missing configuration, log was: %s", out)
			}
		})
	}
}

func TestAlertWithNilLoggerDoesNotPanic(t *testing.T) {
	// New(..., nil) must survive the notification path: a panic here would
	// take down a poll cycle.
	callAlert(t, New("", "", nil, nil), context.Background(), "mon-server: panel unreachable (http_timeout)")
}

func TestSendHonoursContextCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Drain the body first: until the request body hits EOF net/http does
		// not watch the connection, so it would never notice the client going
		// away and never cancel this context.
		_, _ = io.Copy(io.Discard, r.Body)
		once.Do(func() { close(started) })
		// Block until the client goes away, so the test drives the timing
		// instead of the clock. release is the safety net that keeps a
		// regression here from hanging the suite.
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)

	sender := New(testToken, testChatID, server.Client(), nil, WithBaseURL(server.URL))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-started
		cancel()
	}()

	err := sender.Send(ctx, "mon-server: panel unreachable (http_timeout)")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Send error = %v, want context.Canceled", err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("error leaks the bot token: %q", err)
	}
}

func TestTransportFailureDoesNotLeakToken(t *testing.T) {
	// A server that is already gone: the transport error net/http builds
	// carries the whole request URL, token included, unless it is stripped.
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	client := server.Client()
	server.Close()

	sender := New(testToken, testChatID, client, nil, WithBaseURL(url))
	err := sender.Send(context.Background(), "mon-server: panel back, 1 events resent")
	if err == nil {
		t.Fatal("Send returned no error against a closed server")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("transport error leaks the bot token: %q", err)
	}
	if !strings.Contains(err.Error(), testChatID) {
		t.Errorf("transport error %q does not name the chat id", err)
	}
}

func TestCatalogMessagesArriveVerbatim(t *testing.T) {
	tests := []struct {
		name          string
		text          string
		want          string
		viaMonServer  bool
		wantFirstLine bool
	}{
		{
			name: "panel unreachable",
			text: alert.MsgPanelUnreachable("http_timeout"),
			want: "mon-server: panel unreachable (http_timeout)",
		},
		{
			name: "panel back",
			text: alert.MsgPanelBack(12),
			want: "mon-server: panel back, 12 events resent",
		},
		{
			name: "panel rejects token",
			text: alert.MsgPanelRejectsToken(),
			want: "mon-server: panel rejects monitoring token or monitoring is disabled",
		},
		{
			name:          "config error keeps only the first line",
			text:          alert.MsgConfigError("msk-1", "\n  applying config failed: probe url is not https\nat target vless:3:direct\n"),
			want:          "mon-client msk-1: config error applying config failed: probe url is not https",
			wantFirstLine: true,
		},
		{
			name:         "target transition with a reason",
			text:         alert.MsgTargetTransition("msk-1", "vless:3:direct", "UP", "DOWN", "tls_timeout"),
			want:         "target vless:3:direct on msk-1: UP → DOWN (tls_timeout) — via mon-server",
			viaMonServer: true,
		},
		{
			name:         "target transition without a reason",
			text:         alert.MsgTargetTransition("msk-1", "vless:3:proxy", "DOWN", "UP", ""),
			want:         "target vless:3:proxy on msk-1: DOWN → UP — via mon-server",
			viaMonServer: true,
		},
		{
			name:         "mon-client transition",
			text:         alert.MsgMonClientTransition("msk-1", "ru-msk", "OFFLINE"),
			want:         "mon-client msk-1 (ru-msk) OFFLINE — via mon-server",
			viaMonServer: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := newStubAPI(t)
			sender, _ := newTestSender(t, api, testToken, testChatID)

			// Through Alert, the way every §8 caller reaches this package.
			callAlert(t, sender, context.Background(), tt.text)

			got := api.only(t)
			if got.body.Text != tt.want {
				t.Errorf("text that reached Telegram =\n%q\nwant\n%q", got.body.Text, tt.want)
			}
			if got.body.ChatID != testChatID {
				t.Errorf("chat_id = %q, want %q", got.body.ChatID, testChatID)
			}
			if strings.Contains(got.rawBody, "parse_mode") {
				t.Errorf("body carries parse_mode: %s", got.rawBody)
			}
			if tt.viaMonServer && !strings.Contains(got.body.Text, "— via mon-server") {
				t.Errorf("transition %q lacks the via mon-server marker", got.body.Text)
			}
			if tt.wantFirstLine && strings.Contains(got.body.Text, "at target") {
				t.Errorf("config error was not trimmed to its first line: %q", got.body.Text)
			}
		})
	}
}

func TestSendTestReachesTelegram(t *testing.T) {
	api := newStubAPI(t)
	sender, _ := newTestSender(t, api, testToken, testChatID)

	if err := sender.SendTest(context.Background()); err != nil {
		t.Fatalf("SendTest: %v", err)
	}

	got := api.only(t)
	if want := "/bot" + testToken + "/sendMessage"; got.path != want {
		t.Errorf("path = %q, want %q", got.path, want)
	}
	if strings.TrimSpace(got.body.Text) == "" {
		t.Error("SendTest sent an empty text")
	}
	if !strings.Contains(got.body.Text, "mon-server") {
		t.Errorf("test message %q does not identify mon-server", got.body.Text)
	}
}

func TestEndpointURL(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
		want string
	}{
		{
			name: "default base url",
			want: "https://api.telegram.org/bot" + testToken + "/sendMessage",
		},
		{
			name: "override",
			opts: []Option{WithBaseURL("http://127.0.0.1:8081")},
			want: "http://127.0.0.1:8081/bot" + testToken + "/sendMessage",
		},
		{
			name: "override with a trailing slash",
			opts: []Option{WithBaseURL("http://127.0.0.1:8081/")},
			want: "http://127.0.0.1:8081/bot" + testToken + "/sendMessage",
		},
		{
			name: "empty override keeps the default",
			opts: []Option{WithBaseURL("")},
			want: "https://api.telegram.org/bot" + testToken + "/sendMessage",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := New(" "+testToken+" ", testChatID, nil, nil, tt.opts...)
			if got := sender.endpoint("sendMessage"); got != tt.want {
				t.Errorf("endpoint = %q, want %q", got, tt.want)
			}
			if !sender.Configured() {
				t.Error("Configured() = false for a token and chat id that are set")
			}
		})
	}
}
