package tg

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// countingHandler is a slog.Handler that counts every record it receives,
// so TestNewFromSettings_WarnsOncePerSpell can assert on how many times
// "telegram not configured" was logged without depending on slog's text
// output format.
type countingHandler struct {
	mu sync.Mutex
	n  int
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(context.Context, slog.Record) error {
	h.mu.Lock()
	h.n++
	h.mu.Unlock()
	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

// swapSlogHandler installs h as slog's default handler for the duration of a
// test and returns a func that restores the previous default.
func swapSlogHandler(h slog.Handler) func() {
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	return func() { slog.SetDefault(prev) }
}

// fakeCredentials is a CredentialsSource whose Settings a test can mutate
// between Sends, standing in for an admin using the Settings page while
// mon-server keeps running.
type fakeCredentials struct {
	mu  sync.Mutex
	set store.Settings
}

func (f *fakeCredentials) LoadSettings() (*store.Settings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := f.set
	return &cp, nil
}

func (f *fakeCredentials) setCreds(token, chatID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.set.TgToken = token
	f.set.TgChatID = chatID
}

// newTestHTTP builds an *HTTP against an httptest.Server that records every
// message it is sent and always answers ok:true, so settings_test.go never
// depends on http_test.go's assertions about the wire format.
func newTestHTTP(t *testing.T) (*HTTP, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var got []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body sendMessageRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		got = append(got, body.Text)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	return NewHTTP(nil, srv.URL), &got
}

// TestNewFromSettings_NotConfiguredIsSilentSuccess checks that with no
// tgToken/tgChatId set yet, Send neither reaches the network nor errors:
// mon-server must run fine with the Telegram tab left blank (spec §9.4).
func TestNewFromSettings_NotConfiguredIsSilentSuccess(t *testing.T) {
	h, sent := newTestHTTP(t)
	src := &fakeCredentials{}
	n := NewFromSettings(src, h)

	if err := n.Send(context.Background(), "hello"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(*sent) != 0 {
		t.Fatalf("sent = %v, want no network call while unconfigured", *sent)
	}
}

// TestNewFromSettings_SendsOnceConfigured checks that filling in
// tgToken/tgChatId (an admin's Save) takes effect on the very next Send,
// with no restart and no caching of the old empty credentials.
func TestNewFromSettings_SendsOnceConfigured(t *testing.T) {
	h, sent := newTestHTTP(t)
	src := &fakeCredentials{}
	n := NewFromSettings(src, h)

	if err := n.Send(context.Background(), "before"); err != nil {
		t.Fatalf("Send (unconfigured): %v", err)
	}

	src.setCreds("123:ABC", "42")
	if err := n.Send(context.Background(), "after"); err != nil {
		t.Fatalf("Send (configured): %v", err)
	}

	if got := *sent; len(got) != 1 || got[0] != "after" {
		t.Fatalf("sent = %v, want exactly [\"after\"]", got)
	}
}

// TestNewFromSettings_WarnsOncePerSpell checks the "log once per spell"
// rule: repeated Sends while unconfigured only warn once, but a spell of
// being configured in between makes the next unconfigured spell warn again.
// It drives Send through a custom slog handler rather than asserting network
// behaviour, since the warning is the only observable difference between
// the two unconfigured spells.
func TestNewFromSettings_WarnsOncePerSpell(t *testing.T) {
	h, _ := newTestHTTP(t)
	src := &fakeCredentials{}
	n := NewFromSettings(src, h)
	ctx := context.Background()

	warnCount := &countingHandler{}
	restore := swapSlogHandler(warnCount)
	defer restore()

	if err := n.Send(ctx, "a"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := n.Send(ctx, "b"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if warnCount.n != 1 {
		t.Fatalf("warnings = %d, want exactly 1 across two unconfigured Sends", warnCount.n)
	}

	src.setCreds("123:ABC", "42")
	if err := n.Send(ctx, "configured"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	src.setCreds("", "")
	if err := n.Send(ctx, "c"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if warnCount.n != 2 {
		t.Fatalf("warnings = %d, want a new warning after a configured spell in between", warnCount.n)
	}
}
